// Shared launch flow for every extension: exchange launchCode, resolve BizDomain, record session + event in D1.
// exchangeLaunchCode runs only to START a run. A reload of the same launch (same launchCode, already spent) or a
// later request of an iframe run resumes the stored session from the didar_run cookie instead (see session.ts).
import { exchangeLaunchCode, RuntimeRun } from "./didar";
import { getValidRuntimeSessionById, insertRefreshToken, sessionColumns, sessionCookie, sessionStartedBy } from "./session";
import { b64urlDecodeJson, Env, nowSec, randomToken, redactDeep, sha256Hex } from "./util";

// Didar extension locations, as returned in the Runtime Context (context.location).
export const LOCATION = {
  DealsList: 1,
  DealDetail: 2,
  PersonList: 3,
  PersonDetail: 4,
  CompanyList: 5,
  CompanyDetail: 6,
  CaseList: 7,
  CaseDetail: 8,
  ActivitiesList: 9,
} as const;
const VALID_LOCATIONS = new Set<number>(Object.values(LOCATION));

export type ExtensionKind ="link" | "json_modal" | "custom_modal" | "json_panel" | "custom_panel" | "settings";

const INVALID_RUN = "این اجرا معتبر نیست یا منقضی شده؛ اکستنشن را دوباره از دیدار باز کن.";

export interface StartedRun extends RuntimeRun {
  bizDomainId: string | null; // null when neither the token nor the Didar OpenAPI gave the tenant
  bizDomainTitle: string | null; // the Didar OpenAPI has no BizDomain-info endpoint, so this stays null
  sessionId: string; // raw value for the cookie; only its hash is stored
  sessionExpiresInSeconds: number; // cookie lifetime: absolute session end when refreshable, else the JWT lifetime
  resumed: boolean; // true when the run came from the stored session (no launchCode was exchanged)
}

export type StartResult = { ok: true; run: StartedRun } | { ok: false; status: number; message: string };

export async function startRun(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  kind: ExtensionKind,
  expect: { target: "extension" | "settings_page" },
  loggedPayload?: unknown, // validated JSON-extension values; defaults to context.payload
  opts: { resume?: boolean } = {}, // iframe pages: resume the cookie's session on reload instead of re-exchanging
): Promise<StartResult> {
  const url = new URL(req.url);
  const launchCode = url.searchParams.get("launchCode");

  if (opts.resume) {
    const sid = sessionCookie(req);
    // No launchCode, or the very launchCode that started this session (already spent): resume, never re-exchange.
    if (sid && (!launchCode || (await sessionStartedBy(env, sid, launchCode)))) return resumeRun(sid, env, ctx, kind, expect);
  }

  const run = await exchangeLaunchCode(env, ctx, launchCode);
  if (!run) return { ok: false, status: 401, message: INVALID_RUN };

  const c = run.context;
  if (c.target !== expect.target) return { ok: false, status: 400, message: "این آدرس برای این نوع اجرا نیست." };
  // Extensions: location must be one of Didar's Location codes (1-9); any valid page is accepted.
  // Settings page: Didar sends location = null by design.
  const locationOk = c.target === "settings_page" ? c.location == null : c.location != null && VALID_LOCATIONS.has(c.location);
  if (!locationOk) return { ok: false, status: 400, message: "محل اجرای این اکستنشن معتبر نیست." };

  // Decode the token if it is a JWT. It came straight from the marketplace in exchange for our client
  // secret, so its claims are as trustworthy as the context (the signature is not verified here).
  const parts = run.accessToken.split(".");
  const header = parts.length === 3 ? b64urlDecodeJson(parts[0]) : null;
  const claims = parts.length === 3 ? b64urlDecodeJson(parts[1]) : null;
  const num = (v: unknown) => (typeof v === "number" ? v : null);
  const str = (v: unknown) => (v == null ? null : String(v));
  const userId = str(claims?.["user_id"] ?? claims?.["userId"] ?? claims?.["UserId"] ?? claims?.["sub"] ?? claims?.["uid"]);

  // Tenant, never from query/form: the token's biz_domain_id claim (the marketplace issues it). It selects the
  // installation whose api_key is used for the Didar OpenAPI. Without it the run continues with bizDomainId = null,
  // and handlers that need tenant data must check it.
  const bizDomainId = bizDomainClaim(claims);
  const bizDomainTitle: string | null = null;

  const sessionId = randomToken(24);
  const sessionIdHash = await sha256Hex(sessionId);
  const now = nowSec();
  // Tokens are encrypted (AES-GCM) and stay server-side; expires_at = absolute session end (cleanup).
  const cols = await sessionColumns(env, run, now);
  const ip = req.headers.get("CF-Connecting-IP");
  const ua = req.headers.get("User-Agent");

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO runtime_sessions (session_id_hash, token_hash, header, payload, algorithm, token_type, user_id, biz_domain_id,
         runtime_id, target, location, entity_type, entity_ids, issued_at, expires_at, not_before, jwt_id, token_source,
         last_request_method, last_request_path, last_request_ip, last_request_user_agent,
         access_token_encrypted, access_token_expires_at, refresh_token_expires_at, context_json, launch_code_hash, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
       ON CONFLICT(token_hash) DO UPDATE SET use_count = use_count + 1, last_seen_at = CURRENT_TIMESTAMP`,
    ).bind(
      sessionIdHash, await sha256Hex(run.accessToken),
      header ? JSON.stringify(header) : null, claims ? JSON.stringify(claims) : null,
      str(header?.["alg"]), run.tokenType ?? str(header?.["typ"]), userId, bizDomainId,
      c.runtimeId, c.target, c.location, c.entityType, JSON.stringify(c.entityIds),
      num(claims?.["iat"]), cols.sessionExpiresAt, num(claims?.["nbf"]), str(claims?.["jti"]), kind,
      req.method, url.pathname, ip, ua,
      cols.accessTokenEncrypted, cols.accessTokenExpiresAt, cols.refreshTokenExpiresAt,
      JSON.stringify(c), await sha256Hex(launchCode!),
    ),
    // The refresh token goes into its own table, in the same atomic batch.
    ...(cols.refreshTokenEncrypted ? [insertRefreshToken(env, sessionIdHash, cols.refreshTokenEncrypted, cols.refreshTokenExpiresAt!)] : []),
    env.DB.prepare(
      `INSERT INTO extension_events (biz_domain_id, runtime_id, event_action, event_object, location, entity_ids, payload)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(bizDomainId, c.runtimeId, kind, c.entityType, c.location, JSON.stringify(c.entityIds), JSON.stringify(redactDeep(loggedPayload ?? c.payload)).slice(0, 16000)),
  ]);

  return {
    ok: true,
    run: { ...run, bizDomainId, bizDomainTitle, sessionId, sessionExpiresInSeconds: cols.sessionExpiresAt - now, resumed: false },
  };
}

/** Reload / follow-up of an iframe run: the stored session (refreshed if needed), never a second exchange. */
async function resumeRun(sessionId: string, env: Env, ctx: ExecutionContext, kind: ExtensionKind, expect: { target: "extension" | "settings_page" }): Promise<StartResult> {
  const s = await getValidRuntimeSessionById(sessionId, env, ctx);
  if (!s.ok) return { ok: false, status: s.status, message: s.message };
  const ses = s.session;
  // The cookie is shared by every iframe extension: only resume a session of this same extension kind.
  if (ses.kind !== kind || ses.context.target !== expect.target) return { ok: false, status: 401, message: INVALID_RUN };
  const now = nowSec();
  return {
    ok: true,
    run: {
      accessToken: ses.accessToken, tokenType: ses.tokenType, expiresInSeconds: Math.max(0, ses.accessTokenExpiresAt - now),
      context: ses.context, bizDomainId: ses.bizDomainId, bizDomainTitle: null, sessionId,
      sessionExpiresInSeconds: Math.max(0, ses.sessionExpiresAt - now), resumed: true,
    },
  };
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isGuid = (v: unknown): v is string => typeof v === "string" && GUID.test(v);

/**
 * The token's BizDomain: the `biz_domain_id` claim (any claim whose name contains "bizdomain", any case/separator,
 * whose value is a GUID). Real Runtime Tokens carry biz_domain_id, user_id, installation_id, runtime_id, scope, ...
 */
function bizDomainClaim(claims: Record<string, unknown> | null): string | null {
  if (!claims) return null;
  for (const [k, v] of Object.entries(claims)) {
    if (k.toLowerCase().replace(/[^a-z]/g, "").includes("bizdomain") && isGuid(v)) return v;
  }
  return null;
}
