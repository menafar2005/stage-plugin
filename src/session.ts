// Server-side Runtime sessions that survive the 5-minute JWT: the didar_run cookie carries only a random id,
// D1 holds the AES-GCM encrypted access + refresh tokens, and a refresh happens shortly before the JWT expires.
//
// Concurrency: the refresh token is one-time and requests of one session may run on different isolates, so an
// in-memory lock is not enough. Exactly one refresh per session is in flight thanks to a D1 lease taken with
// compare-and-swap (UPDATE ... WHERE version = ? AND lease free). Others wait briefly and read the stored result.
// The replacement tokens, expiries and version are written in ONE conditional UPDATE (atomic in D1).
import { decryptSecret, encryptSecret } from "./crypto";
import { DidarError, didarOpenApi, refreshRuntimeToken, RuntimeContext, RuntimeRun } from "./didar";
import { b64urlDecodeJson, Env, getCookie, nowSec, randomToken, sha256Hex } from "./util";

export const SESSION_COOKIE = "didar_run";
/** Refresh when the JWT has less than this many seconds left. */
export const REFRESH_MARGIN_SEC = 30;
/** Lease length; longer than the marketplace fetch timeout (10s) so a live holder never loses it. */
export const REFRESH_LEASE_SEC = 30;
/** After a configuration error (bad client secret, installation key missing) refresh is not tried again for this long. */
export const CONFIG_COOLDOWN_SEC = 60;

export type SessionStatus = "active" | "reauth_required" | "expired" | "revoked" | "unavailable";

export const MSG = {
  relaunch: "نشست این اجرا معتبر نیست یا تمام شده؛ اکستنشن را دوباره از دیدار باز کن.",
  revoked: "دسترسی شما به این اپ لغو شده است؛ اکستنشن را دوباره از دیدار باز کن یا با مدیر کسب‌وکار تماس بگیر.",
  unavailable: "این اپ یا این اجرا دیگر در دسترس نیست.",
  clientConfig: "تنظیمات اتصال اپ به مارکت‌پلیس نادرست است؛ با پشتیبانی اپ تماس بگیر.",
  installConfig: "نصب این اپ کامل پیکربندی نشده است؛ مدیر کسب‌وکار باید نصب را بررسی کند.",
  busy: "در حال تمدید نشست؛ چند لحظه بعد دوباره امتحان کن.",
  didarFailed: "درخواست به دیدار انجام نشد؛ کمی بعد دوباره امتحان کن.",
} as const;

interface SessionRow {
  id: number;
  session_id_hash: string;
  user_id: string | null;
  biz_domain_id: string | null;
  runtime_id: string | null;
  target: string | null;
  token_type: string | null;
  token_source: string | null;
  context_json: string | null;
  launch_code_hash: string | null;
  access_token_encrypted: string | null;
  access_token_expires_at: number | null;
  /** From runtime_refresh_tokens: the session's single active token (NULL when there is none). */
  refresh_token_id: number | null;
  refresh_token_encrypted: string | null;
  refresh_token_expires_at: number | null;
  status: SessionStatus;
  status_reason: string | null;
  version: number;
  refresh_lease_id: string | null;
  refresh_lease_until: number | null;
}

/** What callers get. accessToken is for server-side use only: never put it in HTML, JS, storage or a URL. */
export interface RuntimeSession {
  id: number;
  sessionId: string;
  userId: string | null;
  bizDomainId: string | null;
  kind: string | null;
  context: RuntimeContext;
  accessToken: string;
  tokenType: string;
  accessTokenExpiresAt: number;
  sessionExpiresAt: number;
  version: number;
  refreshed: boolean;
}

export type SessionResult =
  | { ok: true; session: RuntimeSession }
  | { ok: false; status: number; reason: string; message: string; relaunch: boolean };

export interface SessionOptions {
  /** How long to wait for another request's in-flight refresh before answering "busy" (bounded, no endless loop). */
  maxWaitMs?: number;
  pollMs?: number;
}

const fail = (status: number, reason: string, message: string, relaunch: boolean): SessionResult => ({ ok: false, status, reason, message, relaunch });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** UTC ISO-8601 -> unix seconds; null when missing or unparseable. */
export function isoToSec(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

/** Encrypted columns + expiries for a fresh run. The row's expires_at becomes the absolute session end. */
export async function sessionColumns(env: Env, run: RuntimeRun, now = nowSec()) {
  const accessExp = now + run.expiresInSeconds;
  const refreshExp = run.refreshToken ? isoToSec(run.refreshTokenExpiresAt) : null;
  const refreshable = !!run.refreshToken && refreshExp != null && refreshExp > now;
  return {
    accessTokenEncrypted: await encryptSecret(env.ENCRYPTION_KEY, run.accessToken),
    accessTokenExpiresAt: accessExp,
    refreshTokenEncrypted: refreshable ? await encryptSecret(env.ENCRYPTION_KEY, run.refreshToken!) : null,
    refreshTokenExpiresAt: refreshable ? refreshExp : null,
    /** Cookie + cleanup lifetime: the absolute session end when refreshable, else the JWT lifetime. */
    sessionExpiresAt: refreshable ? Math.max(refreshExp!, accessExp) : accessExp,
  };
}

// The session row plus its single active refresh token (runtime_refresh_tokens). The session's own
// refresh_token_expires_at stays the absolute end used for every decision.
const SELECT = `SELECT s.id, s.session_id_hash, s.user_id, s.biz_domain_id, s.runtime_id, s.target, s.token_type, s.token_source,
  s.context_json, s.launch_code_hash, s.access_token_encrypted, s.access_token_expires_at, s.refresh_token_expires_at,
  t.id AS refresh_token_id, t.refresh_token_encrypted, s.status, s.status_reason, s.version, s.refresh_lease_id, s.refresh_lease_until
  FROM runtime_sessions s LEFT JOIN runtime_refresh_tokens t ON t.session_id = s.id AND t.status = 'active'
  WHERE s.session_id_hash = ?`;

async function load(env: Env, hash: string): Promise<SessionRow | null> {
  return env.DB.prepare(SELECT).bind(hash).first<SessionRow>();
}

/** Runs only if the batch's first statement moved the session to `version` (same transaction, so no interleaving). */
const IF_SESSION_AT = `EXISTS (SELECT 1 FROM runtime_sessions WHERE id = ? AND version = ?)`;

/** Ends a session for good (access token and active refresh token wiped), only if nobody changed it since `version`. */
async function terminate(env: Env, row: SessionRow, status: SessionStatus, reason: string): Promise<boolean> {
  const [r] = await env.DB.batch([
    env.DB.prepare(
      `UPDATE runtime_sessions SET status = ?, status_reason = ?, access_token_encrypted = NULL,
         refresh_lease_id = NULL, refresh_lease_until = NULL, version = version + 1, last_seen_at = CURRENT_TIMESTAMP
       WHERE id = ? AND version = ?`,
    ).bind(status, reason, row.id, row.version),
    env.DB.prepare(
      `UPDATE runtime_refresh_tokens SET status = 'ended', status_reason = ?, refresh_token_encrypted = NULL
       WHERE session_id = ? AND status = 'active' AND ${IF_SESSION_AT}`,
    ).bind(reason, row.id, row.id, row.version + 1),
  ]);
  return (r.meta?.changes ?? 0) === 1;
}

/** Statement that stores a session's first refresh token (used by startRun in the same batch as the session insert). */
export function insertRefreshToken(env: Env, sessionIdHash: string, encrypted: string, expiresAt: number) {
  return env.DB.prepare(
    `INSERT INTO runtime_refresh_tokens (session_id, user_id, biz_domain_id, runtime_id, refresh_token_encrypted, expires_at, status)
     SELECT id, user_id, biz_domain_id, runtime_id, ?, ?, 'active' FROM runtime_sessions s
     WHERE session_id_hash = ? AND NOT EXISTS (SELECT 1 FROM runtime_refresh_tokens t WHERE t.session_id = s.id AND t.status = 'active')`,
  ).bind(encrypted, expiresAt, sessionIdHash);
}

function statusFailure(row: SessionRow): SessionResult | null {
  switch (row.status) {
    case "active":
      return null;
    case "revoked":
      return fail(403, row.status_reason ?? "INSTALLATION_ACCESS_DENIED", MSG.revoked, true);
    case "unavailable":
      return fail(403, row.status_reason ?? "RUNTIME_UNAVAILABLE", MSG.unavailable, false);
    default:
      return fail(401, row.status_reason ?? "REAUTH_REQUIRED", MSG.relaunch, true);
  }
}

/** Cool-down after a configuration error: lease_until in the future without a holder. */
function cooldownFailure(row: SessionRow, now: number): SessionResult | null {
  if (row.refresh_lease_id != null || (row.refresh_lease_until ?? 0) <= now) return null;
  return row.status_reason === "DIDAR_API_KEY_NOT_CONFIGURED"
    ? fail(409, "DIDAR_API_KEY_NOT_CONFIGURED", MSG.installConfig, false)
    : fail(503, row.status_reason ?? "INVALID_CLIENT_CREDENTIALS", MSG.clientConfig, false);
}

async function toSession(env: Env, row: SessionRow, sessionId: string, refreshed: boolean): Promise<SessionResult> {
  let context: RuntimeContext;
  try {
    context = JSON.parse(row.context_json ?? "null");
    if (!context) throw new Error("no context");
  } catch {
    return fail(401, "SESSION_CONTEXT_MISSING", MSG.relaunch, true);
  }
  return {
    ok: true,
    session: {
      id: row.id,
      sessionId,
      userId: row.user_id,
      bizDomainId: row.biz_domain_id,
      kind: row.token_source,
      context,
      accessToken: await decryptSecret(env.ENCRYPTION_KEY, row.access_token_encrypted!),
      tokenType: row.token_type ?? "Bearer",
      accessTokenExpiresAt: row.access_token_expires_at!,
      sessionExpiresAt: row.refresh_token_expires_at!,
      version: row.version,
      refreshed,
    },
  };
}

/** The session id from the didar_run cookie, or null. */
export const sessionCookie = (req: Request) => getCookie(req, SESSION_COOKIE);

/** True when the cookie's session was started by exactly this launchCode (an iframe reload): no new exchange needed. */
export async function sessionStartedBy(env: Env, sessionId: string, launchCode: string): Promise<boolean> {
  const row = await env.DB.prepare(`SELECT launch_code_hash FROM runtime_sessions WHERE session_id_hash = ?`)
    .bind(await sha256Hex(sessionId)).first<{ launch_code_hash: string | null }>();
  return !!row?.launch_code_hash && row.launch_code_hash === (await sha256Hex(launchCode));
}

/**
 * The one entry point for everything that needs the Runtime session: validates the cookie's session, refreshes
 * the JWT when it is close to expiry (single-flight across isolates), and returns a usable token or a reason.
 * It never consumes a launchCode and never retries a refresh.
 */
export async function getValidRuntimeSession(req: Request, env: Env, ctx: ExecutionContext, opts: SessionOptions = {}): Promise<SessionResult> {
  const sessionId = sessionCookie(req);
  if (!sessionId) return fail(401, "NO_SESSION", MSG.relaunch, true);
  return getValidRuntimeSessionById(sessionId, env, ctx, opts);
}

export async function getValidRuntimeSessionById(sessionId: string, env: Env, ctx: ExecutionContext, opts: SessionOptions = {}): Promise<SessionResult> {
  const hash = await sha256Hex(sessionId);
  const pollMs = opts.pollMs ?? 250;
  // Bounded by attempts, not wall-clock time: at most maxWaitMs of sleeping, then "busy". Never an endless loop.
  const maxPolls = Math.max(0, Math.floor((opts.maxWaitMs ?? 4000) / pollMs));

  for (let polls = 0; ; polls++) {
    const row = await load(env, hash);
    if (!row) return fail(401, "NO_SESSION", MSG.relaunch, true);
    const blocked = statusFailure(row);
    if (blocked) return blocked;
    if (!row.refresh_token_encrypted || !row.access_token_encrypted || row.refresh_token_expires_at == null || row.access_token_expires_at == null) {
      // Session from before refresh support (or one that never got a refresh token): only a new launch helps.
      return fail(401, "REFRESH_NOT_AVAILABLE", MSG.relaunch, true);
    }

    const now = nowSec();
    if (row.refresh_token_expires_at <= now) {
      await terminate(env, row, "expired", "SESSION_EXPIRED");
      return fail(401, "SESSION_EXPIRED", MSG.relaunch, true);
    }
    if (row.access_token_expires_at - now > REFRESH_MARGIN_SEC) return toSession(env, row, sessionId, false);

    const stillValid = row.access_token_expires_at > now + 1;
    const cooldown = cooldownFailure(row, now);
    if (cooldown) return stillValid ? toSession(env, row, sessionId, false) : cooldown;

    // Try to become the single refresher: CAS on version + a free (or expired) lease.
    const leaseId = randomToken(16);
    const took = await env.DB.prepare(
      `UPDATE runtime_sessions SET refresh_lease_id = ?, refresh_lease_until = ?
       WHERE id = ? AND version = ? AND status = 'active' AND (refresh_lease_until IS NULL OR refresh_lease_until <= ?)`,
    ).bind(leaseId, now + REFRESH_LEASE_SEC, row.id, row.version, now).run();
    if ((took.meta?.changes ?? 0) === 1) return refreshHeld(env, ctx, row, sessionId);

    // Someone else is refreshing (or just did). Use the current JWT while it lasts, else wait for their result.
    if (stillValid) return toSession(env, row, sessionId, false);
    if (polls >= maxPolls) return fail(503, "REFRESH_IN_PROGRESS", MSG.busy, false);
    await sleep(pollMs);
  }
}

/** We hold the lease for `row` (at row.version): call the marketplace once and store the outcome atomically. */
async function refreshHeld(env: Env, ctx: ExecutionContext, row: SessionRow, sessionId: string): Promise<SessionResult> {
  let previous: RuntimeContext;
  let refreshToken: string;
  try {
    previous = JSON.parse(row.context_json ?? "null");
    refreshToken = await decryptSecret(env.ENCRYPTION_KEY, row.refresh_token_encrypted!);
    if (!previous) throw new Error("no context");
  } catch {
    await terminate(env, row, "reauth_required", "SESSION_UNREADABLE");
    return fail(401, "SESSION_UNREADABLE", MSG.relaunch, true);
  }

  const r = await refreshRuntimeToken(env, ctx, refreshToken, previous, row.biz_domain_id ?? "");
  const now = nowSec();

  if (r.kind === "ok") {
    const run = r.run;
    // A refresh must stay on the same runtime/target; anything else is not this session any more.
    if (run.context.runtimeId !== previous.runtimeId || run.context.target !== previous.target) {
      await terminate(env, row, "reauth_required", "CONTEXT_MISMATCH");
      return fail(401, "CONTEXT_MISMATCH", MSG.relaunch, true);
    }
    // The absolute end never moves later, whatever the response says.
    const serverEnd = isoToSec(run.refreshTokenExpiresAt);
    const sessionEnd = serverEnd != null ? Math.min(serverEnd, row.refresh_token_expires_at!) : row.refresh_token_expires_at!;
    const accessExp = Math.min(now + run.expiresInSeconds, sessionEnd);
    const parts = run.accessToken.split(".");
    const claims = parts.length === 3 ? b64urlDecodeJson(parts[1]) : null;
    const next = row.version + 1;
    // One atomic batch: session CAS (version -> version + 1), then, only if that applied, the old refresh token is
    // marked rotated (ciphertext wiped), the replacement inserted, and the old row linked to it.
    const [saved] = await env.DB.batch([
      env.DB.prepare(
        `UPDATE runtime_sessions SET access_token_encrypted = ?, access_token_expires_at = ?,
           refresh_token_expires_at = ?, expires_at = ?, token_hash = ?, token_type = ?, context_json = ?, payload = COALESCE(?, payload),
           version = version + 1, refresh_count = refresh_count + 1, last_refreshed_at = ?, refresh_lease_id = NULL,
           refresh_lease_until = NULL, status_reason = NULL, last_seen_at = CURRENT_TIMESTAMP
         WHERE id = ? AND version = ? AND status = 'active'`,
      ).bind(
        await encryptSecret(env.ENCRYPTION_KEY, run.accessToken), accessExp, sessionEnd, sessionEnd, await sha256Hex(run.accessToken),
        run.tokenType, JSON.stringify(run.context), claims ? JSON.stringify(claims) : null, now, row.id, row.version,
      ),
      env.DB.prepare(
        `UPDATE runtime_refresh_tokens SET status = 'rotated', refresh_token_encrypted = NULL, rotated_at = ?
         WHERE id = ? AND status = 'active' AND ${IF_SESSION_AT}`,
      ).bind(now, row.refresh_token_id, row.id, next),
      env.DB.prepare(
        `INSERT INTO runtime_refresh_tokens (session_id, user_id, biz_domain_id, runtime_id, refresh_token_encrypted, expires_at, status)
         SELECT id, user_id, biz_domain_id, runtime_id, ?, ?, 'active' FROM runtime_sessions WHERE id = ? AND version = ?`,
      ).bind(await encryptSecret(env.ENCRYPTION_KEY, run.refreshToken!), sessionEnd, row.id, next),
      env.DB.prepare(
        `UPDATE runtime_refresh_tokens SET replaced_by_id =
           (SELECT id FROM runtime_refresh_tokens WHERE session_id = ? AND status = 'active')
         WHERE id = ? AND ${IF_SESSION_AT}`,
      ).bind(row.id, row.refresh_token_id, row.id, next),
    ]);
    if ((saved.meta?.changes ?? 0) !== 1) {
      // The row changed under us (e.g. ended meanwhile). The new tokens cannot be stored safely: drop them.
      return reread(env, sessionId, fail(401, "REFRESH_RESULT_LOST", MSG.relaunch, true));
    }
    const fresh = await load(env, row.session_id_hash);
    return fresh ? toSession(env, fresh, sessionId, true) : fail(401, "NO_SESSION", MSG.relaunch, true);
  }

  if (r.kind === "unknown") {
    // The marketplace may have rotated the token without us getting the replacement: never retry the old one.
    console.error("runtime refresh outcome unknown", r.reason);
    if (!(await terminate(env, row, "reauth_required", "REFRESH_OUTCOME_UNKNOWN"))) return reread(env, sessionId, fail(401, "REFRESH_OUTCOME_UNKNOWN", MSG.relaunch, true));
    return fail(401, "REFRESH_OUTCOME_UNKNOWN", MSG.relaunch, true);
  }

  console.error("runtime refresh rejected", r.status, r.code, r.traceId);
  switch (r.code) {
    case "INVALID_CLIENT_CREDENTIALS":
    case "DIDAR_API_KEY_NOT_CONFIGURED": {
      // Configuration, not an expired JWT: keep the session, release the lease into a cool-down, no retry loop.
      await env.DB.prepare(
        `UPDATE runtime_sessions SET refresh_lease_id = NULL, refresh_lease_until = ?, status_reason = ?
         WHERE id = ? AND version = ? AND status = 'active'`,
      ).bind(now + CONFIG_COOLDOWN_SEC, r.code, row.id, row.version).run();
      return r.code === "DIDAR_API_KEY_NOT_CONFIGURED"
        ? fail(409, r.code, MSG.installConfig, false)
        : fail(503, r.code, MSG.clientConfig, false);
    }
    case "REFRESH_TOKEN_INVALID": {
      // Maybe another request already replaced it: prefer a stored replacement over ending the session.
      const after = await load(env, row.session_id_hash);
      if (after && after.version !== row.version && after.status === "active" && after.access_token_encrypted && (after.access_token_expires_at ?? 0) > now) {
        return toSession(env, after, sessionId, false);
      }
      await terminate(env, row, "reauth_required", r.code);
      return fail(401, r.code, MSG.relaunch, true);
    }
    case "REFRESH_TOKEN_EXPIRED":
      await terminate(env, row, "expired", r.code);
      return fail(401, r.code, MSG.relaunch, true);
    case "INSTALLATION_ACCESS_DENIED":
      await terminate(env, row, "revoked", r.code);
      return fail(403, r.code, MSG.revoked, true);
    case "RUNTIME_UNAVAILABLE":
    case "EXTENSION_RUNTIME_UNAVAILABLE":
    case "SETTINGS_PAGE_RUNTIME_UNAVAILABLE":
      await terminate(env, row, "unavailable", r.code);
      return fail(403, r.code, MSG.unavailable, false);
    default:
      // Unknown rejection: the token may or may not be spent, so the safe path is a new launch.
      await terminate(env, row, "reauth_required", r.code ?? `HTTP_${r.status}`);
      return fail(r.status === 403 ? 403 : 401, r.code ?? `HTTP_${r.status}`, MSG.relaunch, true);
  }
}

/**
 * Didar OpenAPI on behalf of the cookie's user: validates (and if needed refreshes) the Runtime session FIRST, then
 * calls with the api_key of THAT session's BizDomain. If the session is invalid, revoked or its refresh failed,
 * nothing is sent: there is no fallback key.
 */
export async function sessionOpenApi<T = any>(
  req: Request, env: Env, ctx: ExecutionContext, path: string, payload?: unknown,
): Promise<{ ok: true; data: T } | { ok: false; status: number; reason: string; message: string }> {
  const s = await getValidRuntimeSession(req, env, ctx);
  if (!s.ok) return { ok: false, status: s.status, reason: s.reason, message: s.message };
  if (!s.session.bizDomainId) return { ok: false, status: 400, reason: "BIZ_DOMAIN_UNKNOWN", message: MSG.relaunch };
  try {
    return { ok: true, data: await didarOpenApi<T>(env, ctx, path, payload, s.session.bizDomainId) };
  } catch (e) {
    if (!(e instanceof DidarError)) throw e;
    const missing = e.code === "INSTALLATION_NOT_FOUND" || e.code === "INSTALLATION_INACTIVE";
    return { ok: false, status: missing ? 409 : 502, reason: e.code ?? `HTTP_${e.status}`, message: missing ? MSG.installConfig : MSG.didarFailed };
  }
}

/** After losing a CAS: a concurrent request may have stored a valid replacement; use it, else `otherwise`. */
async function reread(env: Env, sessionId: string, otherwise: SessionResult): Promise<SessionResult> {
  const row = await load(env, await sha256Hex(sessionId));
  if (row && row.status === "active" && row.access_token_encrypted && (row.access_token_expires_at ?? 0) > nowSec()) return toSession(env, row, sessionId, false);
  return otherwise;
}
