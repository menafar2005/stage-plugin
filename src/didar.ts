// Didar clients: marketplace (install, Runtime Token, Runtime refresh) and Didar OpenAPI (data).
// Every outgoing call is logged to external_api_calls with secrets removed: client secret, install code, launchCode,
// access/refresh tokens and api keys never reach the table (see redact* in util.ts). error.code and traceId stay
// visible in their own columns for troubleshooting.
import { decryptSecret } from "./crypto";
import { collectSecrets, envSecrets, Env, nowIso, redactBody, redactHeaders, redactMessage, redactUrl } from "./util";

/** Marks rows written with the current redaction rules; the legacy scrub (migrations/0004) only touches older rows. */
export const REDACTION_VERSION = 2;
const MARKETPLACE_TIMEOUT_MS = 10_000;

export interface RuntimeContext {
  target: "extension" | "settings_page";
  runtimeId: string;
  location: number | null;
  entityType: "deal" | "case" | "person" | "company" | "activity" | null; // "activity": ActivitiesList (9)
  entityIds: string[];
  payload: Record<string, unknown>;
  [extra: string]: unknown; // any other field the marketplace sends is kept as-is
}

export interface RuntimeRun {
  accessToken: string;
  tokenType: string;
  expiresInSeconds: number;
  context: RuntimeContext;
  /** One-time refresh token (new contract). Missing on older marketplace responses. */
  refreshToken?: string | null;
  /** Absolute UTC ISO-8601 end of the session; refreshes never extend it. */
  refreshTokenExpiresAt?: string | null;
}

export class DidarError extends Error {
  constructor(public status: number, public code: string | null, public traceId: string | null) {
    super(`Didar API ${status} ${code ?? ""}`.trim());
  }
}

/** error.code from the marketplace envelope, an OAuth-style `error` string, or the Didar `Response.Error`. */
export function errorCodeOf(body: any): string | null {
  const c = body?.error?.code ?? (typeof body?.error === "string" ? body.error : null) ?? body?.Response?.Error?.Code ?? body?.code;
  return typeof c === "string" && c ? c : null;
}
export function traceIdOf(body: any): string | null {
  const t = body?.meta?.traceId ?? body?.traceId ?? body?.Response?.Meta?.TraceId ?? body?.error?.traceId;
  return typeof t === "string" && t ? t : null;
}

interface FetchOpts {
  bizDomainId?: string;
  /** Extra request-body keys to redact for this call only (e.g. "code" for the install exchange). */
  requestSecretKeys?: string[];
  /** Exact secret values sent in this call (they are scrubbed wherever they appear). */
  secrets?: (string | null | undefined)[];
  timeoutMs?: number;
}

/** Thrown when the request may have reached the server but no usable answer came back (network error, timeout). */
export class FetchFailed extends Error {
  constructor(name: string, message: string) {
    super(message);
    this.name = name;
  }
}

async function loggedFetch(env: Env, ctx: ExecutionContext, service: string, url: string, init: RequestInit, opts: FetchOpts = {}): Promise<{ status: number; body: any }> {
  const started = Date.now();
  const startedIso = nowIso();
  let res: Response | null = null;
  let raw = "";
  let error: Error | null = null;
  try {
    res = await fetch(url, { ...init, signal: init.signal ?? (opts.timeoutMs ? AbortSignal.timeout(opts.timeoutMs) : undefined) });
    raw = await res.text();
  } catch (e) {
    error = e as Error;
  }

  let body: any = null;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    /* non-JSON */
  }

  // Everything secret in this exchange: env secrets, values we sent, and every secret-keyed value in the reply.
  const known = [...envSecrets(env), ...(opts.secrets ?? []).filter((s): s is string => !!s), ...collectSecrets(body)];
  const reqHeaders = new Headers(init.headers);
  const errMessage = error ? redactMessage(error.message, known) : null;
  ctx.waitUntil(
    env.DB.prepare(
      `INSERT INTO external_api_calls (biz_domain_id, service, call_source, request_started_at, response_received_at, duration_ms,
         request_method, request_url, request_headers, request_body, response_status, response_status_text, response_headers,
         response_body, success, error_name, error_message, error_code, trace_id, redaction_version)
       VALUES (?, ?, 'backend', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        opts.bizDomainId ?? "", service, startedIso, nowIso(), Date.now() - started,
        init.method ?? "GET", redactUrl(url, known), redactHeaders(reqHeaders, known),
        redactBody(init.body as string | undefined, { extra: opts.requestSecretKeys, known, contentType: reqHeaders.get("Content-Type") }),
        res?.status ?? null, res?.statusText ?? null, res ? redactHeaders(res.headers, known) : null,
        res ? redactBody(raw, { known, contentType: res.headers.get("Content-Type") }) : null,
        res?.ok ? 1 : 0, error?.name ?? null, errMessage, errorCodeOf(body), traceIdOf(body), REDACTION_VERSION,
      )
      .run()
      .catch((e) => console.error("external_api_calls insert failed", redactMessage((e as Error)?.message, known))),
  );

  if (error) throw new FetchFailed(error.name, errMessage ?? "fetch failed");
  return { status: res!.status, body };
}

/** Validates the `data` of a runtime token / refresh response. null when it is not usable. */
function parseRuntimeRun(data: any, fallbackContext?: RuntimeContext): RuntimeRun | null {
  if (!data || typeof data.accessToken !== "string" || !data.accessToken) return null;
  const expiresIn = Number(data.expiresInSeconds);
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) return null;
  const context = (data.context && typeof data.context === "object" ? data.context : fallbackContext) as RuntimeContext | undefined;
  if (!context) return null;
  context.entityIds ??= [];
  context.payload ??= {};
  return {
    ...data,
    tokenType: typeof data.tokenType === "string" ? data.tokenType : "Bearer",
    expiresInSeconds: expiresIn,
    context,
    refreshToken: typeof data.refreshToken === "string" && data.refreshToken ? data.refreshToken : null,
    refreshTokenExpiresAt: typeof data.refreshTokenExpiresAt === "string" ? data.refreshTokenExpiresAt : null,
  };
}

/** launchCode -> Runtime Token + Runtime Context (+ refresh token). Only for starting a NEW run. null when rejected. */
export async function exchangeLaunchCode(env: Env, ctx: ExecutionContext, launchCode: string | null): Promise<RuntimeRun | null> {
  if (!launchCode) return null;
  let status: number, body: any;
  try {
    ({ status, body } = await loggedFetch(env, ctx, "didar.runtime_token", `${env.MARKETPLACE_URL}/api/v1/runtime/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ launchCode, clientId: env.DIDAR_CLIENT_ID, clientSecret: env.DIDAR_CLIENT_SECRET }),
    }, { secrets: [launchCode], timeoutMs: MARKETPLACE_TIMEOUT_MS }));
  } catch (e) {
    console.error("launch exchange failed", (e as Error).name);
    return null; // the launchCode is one-time: never retried
  }
  const run = status >= 200 && status < 300 && body?.succeeded ? parseRuntimeRun(body.data) : null;
  if (!run) console.error("launch exchange failed", status, errorCodeOf(body), traceIdOf(body));
  return run;
}

export type RefreshResult =
  | { kind: "ok"; run: RuntimeRun }
  /** The marketplace answered with an error: the code says what to do. */
  | { kind: "rejected"; status: number; code: string | null; traceId: string | null }
  /** The request may have been processed (network error, timeout, 5xx, unreadable success): outcome unknown. */
  | { kind: "unknown"; reason: string };

/** POST /api/v1/runtime/refresh. Called once per attempt; never retried (the refresh token is one-time). */
export async function refreshRuntimeToken(env: Env, ctx: ExecutionContext, refreshToken: string, previous: RuntimeContext, bizDomainId = ""): Promise<RefreshResult> {
  let status: number, body: any;
  try {
    ({ status, body } = await loggedFetch(env, ctx, "didar.runtime_refresh", `${env.MARKETPLACE_URL}/api/v1/runtime/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken, clientId: env.DIDAR_CLIENT_ID, clientSecret: env.DIDAR_CLIENT_SECRET }),
    }, { secrets: [refreshToken], timeoutMs: MARKETPLACE_TIMEOUT_MS, bizDomainId }));
  } catch (e) {
    return { kind: "unknown", reason: (e as Error).name || "FetchFailed" };
  }
  if (status >= 200 && status < 300) {
    const run = body?.succeeded ? parseRuntimeRun(body.data, previous) : null;
    // A 2xx without a usable replacement: the old token may already be spent.
    return run?.refreshToken ? { kind: "ok", run } : { kind: "unknown", reason: "INVALID_SUCCESS_RESPONSE" };
  }
  const code = errorCodeOf(body);
  if (status >= 500 && !code) return { kind: "unknown", reason: `HTTP_${status}` };
  return { kind: "rejected", status, code, traceId: traceIdOf(body) };
}

/**
 * The decrypted api_key of the BizDomain's installation (installations.api_key_encrypted, written by the install
 * callback from /install/auth/token). Only an 'active' installation counts.
 */
export async function installationApiKey(env: Env, bizDomainId: string): Promise<string> {
  const row = await env.DB.prepare(`SELECT api_key_encrypted, status FROM installations WHERE biz_domain_id = ?`)
    .bind(bizDomainId).first<{ api_key_encrypted: string | null; status: string }>();
  if (!row?.api_key_encrypted) throw new DidarError(0, "INSTALLATION_NOT_FOUND", null);
  if (row.status !== "active") throw new DidarError(0, "INSTALLATION_INACTIVE", null);
  try {
    return await decryptSecret(env.ENCRYPTION_KEY, row.api_key_encrypted);
  } catch {
    throw new DidarError(0, "INSTALLATION_API_KEY_UNREADABLE", null); // e.g. ENCRYPTION_KEY changed
  }
}

/**
 * Didar OpenAPI (https://developers.didar.me): POST https://app.didar.me<path>?apikey=<installation api_key>, result
 * under `Response`. The key is the stored api_key of `bizDomainId`'s installation. There is no global key.
 * Independent of the Runtime JWT: the JWT is never sent here, and marketplace permissions are not enforced on these
 * calls. For anything done on behalf of a user, call it through sessionOpenApi (session.ts), which checks the session first.
 */
export async function didarOpenApi<T = any>(env: Env, ctx: ExecutionContext, path: string, payload: unknown, bizDomainId: string): Promise<T> {
  if (!bizDomainId) throw new DidarError(0, "BIZ_DOMAIN_UNKNOWN", null);
  const apiKey = await installationApiKey(env, bizDomainId);
  const url = `${env.DIDAR_APP_URL}${path}?apikey=${encodeURIComponent(apiKey)}`;
  let status: number, body: any;
  try {
    ({ status, body } = await loggedFetch(env, ctx, `didar.openapi POST ${path}`, url, {
      method: "POST",
      headers: payload === undefined ? { Accept: "application/json" } : { "Content-Type": "application/json", Accept: "application/json" },
      body: payload === undefined ? undefined : JSON.stringify(payload),
    }, { bizDomainId, secrets: [apiKey] }));
  } catch {
    throw new DidarError(0, "DIDAR_OPENAPI_UNREACHABLE", null);
  }
  if (status < 200 || status >= 300 || !body || !("Response" in body)) throw new DidarError(status, errorCodeOf(body), traceIdOf(body));
  return body.Response as T;
}

// ---------- Installation (marketplace OAuth-style token endpoint) ----------
export type InstallErrorKind = "invalid_client" | "invalid_code" | "expired_code" | "used_code" | "didar_service" | "unknown";

export type InstallResult =
  | { ok: true; apiKey: string; scope: string }
  | { ok: false; kind: InstallErrorKind; status: number; code: string | null; traceId: string | null };

/** Maps a marketplace install error (envelope error.code or OAuth-style `error`) to what the callback should say. */
export function classifyInstallError(status: number, code: string | null): InstallErrorKind {
  const c = (code ?? "").toUpperCase();
  if (c === "INVALID_CLIENT" || c.includes("CLIENT_CREDENTIALS") || c === "UNAUTHORIZED_CLIENT") return "invalid_client";
  if (c.includes("DIDAR_SERVICE") || c.includes("DIDARSERVICE") || c.startsWith("DIDAR_")) return "didar_service";
  if (c.includes("EXPIRED")) return "expired_code";
  if (c.includes("ALREADY_USED") || c.includes("CONSUMED") || c.endsWith("_USED")) return "used_code";
  if (c === "INVALID_GRANT" || c.includes("CODE_INVALID") || c.includes("INVALID_CODE") || c === "INVALID_REQUEST") return "invalid_code";
  if (status === 401) return "invalid_client";
  if (status === 410) return "expired_code";
  if (status === 409) return "used_code";
  if (status === 400 || status === 404) return "invalid_code";
  if (status >= 500) return "didar_service";
  return "unknown";
}

/**
 * Callback `code` -> installation api_key. POST {MARKETPLACE_URL}/install/auth/token, form-urlencoded.
 * Success has no envelope: {"api_key":"...","scope":"..."}. The code is one-time, so it is never retried.
 */
export async function completeInstallation(env: Env, ctx: ExecutionContext, code: string, redirectUri: string): Promise<InstallResult> {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: env.DIDAR_CLIENT_ID,
    client_secret: env.DIDAR_CLIENT_SECRET,
  });
  let status: number, body: any;
  try {
    ({ status, body } = await loggedFetch(env, ctx, "didar.install_token", `${env.MARKETPLACE_URL}/install/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: form.toString(),
    }, { requestSecretKeys: ["code"], secrets: [code], timeoutMs: MARKETPLACE_TIMEOUT_MS }));
  } catch (e) {
    console.error("install token request failed", (e as Error).name);
    return { ok: false, kind: "didar_service", status: 0, code: null, traceId: null };
  }

  const apiKey = body?.api_key;
  const scope = body?.scope;
  if (status >= 200 && status < 300 && typeof apiKey === "string" && apiKey.trim() && typeof scope === "string") {
    return { ok: true, apiKey, scope };
  }
  const errCode = errorCodeOf(body);
  const kind = status >= 200 && status < 300 ? "unknown" : classifyInstallError(status, errCode);
  console.error("install failed", status, errCode, traceIdOf(body));
  return { ok: false, kind, status, code: errCode, traceId: traceIdOf(body) };
}
