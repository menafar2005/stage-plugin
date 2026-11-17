import { completeInstallation, InstallErrorKind } from "./didar";
import { encryptSecret } from "./crypto";
import { framePage, linkPage } from "./pages";
import { isGuid, startRun } from "./run";
import { getValidRuntimeSession, SESSION_COOKIE } from "./session";
import { Env, getCookie, iframeCookie, json, nowSec, randomToken, text } from "./util";

// Every extension accepts any valid Didar Location (1-9); the check lives in startRun (see LOCATION in run.ts).

// ---------- Install ----------
export async function installStart(env: Env): Promise<Response> {
  if (!env.DIDAR_INSTALLATION_URL) return text(500, "DIDAR_INSTALLATION_URL تنظیم نشده.");
  const state = randomToken(24);
  const target = new URL(env.DIDAR_INSTALLATION_URL);
  target.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: {
      Location: target.toString(),
      "Set-Cookie": `didar_install_state=${state}; Path=/didar/callback; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
    },
  });
}

const INSTALL_ERRORS: Record<InstallErrorKind, { status: number; message: string }> = {
  invalid_client: { status: 502, message: "تنظیمات اپ (Client ID / Client secret) نادرست است و نصب انجام نشد؛ با پشتیبانی اپ تماس بگیر." },
  invalid_code: { status: 400, message: "کد نصب معتبر نیست؛ نصب را دوباره از دیدار شروع کن." },
  expired_code: { status: 400, message: "کد نصب منقضی شده؛ نصب را دوباره از دیدار شروع کن." },
  used_code: { status: 409, message: "این کد نصب قبلاً استفاده شده؛ برای نصب دوباره، از دیدار شروع کن." },
  didar_service: { status: 502, message: "سرویس دیدار پاسخ نداد و نصب کامل نشد؛ کمی بعد نصب را دوباره از دیدار شروع کن." },
  unknown: { status: 502, message: "نصب کامل نشد. دوباره از لینک نصب امتحان کن." },
};

/** `{UserId-GUID}.{BizDomainId-GUID}.{UniqueKey}`; null when the code does not have that shape. */
export function parseInstallCode(code: string): { userId: string; bizDomainId: string } | null {
  const [userId, bizDomainId, ...rest] = code.split(".");
  return isGuid(userId) && isGuid(bizDomainId) && rest.join(".").length > 0 ? { userId, bizDomainId } : null;
}

export async function installCallback(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const clear = { "Set-Cookie": "didar_install_state=; Path=/didar/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax" };
  if (!code) return text(400, "کد نصب در درخواست نیست.", clear);

  // If the flow started at /didar/install, the one-time state must match.
  const expected = getCookie(req, "didar_install_state");
  if (expected && url.searchParams.get("state") !== expected) return text(400, "درخواست نصب معتبر نیست.", clear);

  // redirect_uri must be exactly the Callback URL registered in Developer Hub. Checked before the code is spent.
  const redirectUri = env.DIDAR_REDIRECT_URI;
  let redirectPath: string | null = null;
  try {
    redirectPath = redirectUri ? new URL(redirectUri).pathname : null;
  } catch {
    /* invalid */
  }
  if (!redirectUri || redirectPath !== url.pathname) {
    console.error("install misconfigured: DIDAR_REDIRECT_URI missing or not this callback");
    return text(500, "تنظیم DIDAR_REDIRECT_URI با آدرس Callback یکی نیست؛ نصب انجام نشد.", clear);
  }

  // Shape check only (nothing is trusted or stored yet): a malformed code is rejected without spending it.
  const parsed = parseInstallCode(code);
  if (!parsed) return text(400, INSTALL_ERRORS.invalid_code.message, clear);

  const r = await completeInstallation(env, ctx, code, redirectUri); // the full code, unchanged; never retried
  if (!r.ok) {
    const e = INSTALL_ERRORS[r.kind];
    return text(e.status, e.message, clear);
  }

  // Only now, after the marketplace accepted the code, are its BizDomain / user parts used.
  // installation_id, app_public_id, installed_at and scopes are not in the new response: existing values are kept.
  try {
    await env.DB.prepare(
      `INSERT INTO installations (biz_domain_id, scope, api_key_encrypted, installed_by_user_id, status)
       VALUES (?, ?, ?, ?, 'active')
       ON CONFLICT(biz_domain_id) DO UPDATE SET scope = excluded.scope, api_key_encrypted = excluded.api_key_encrypted,
         installed_by_user_id = excluded.installed_by_user_id, status = 'active', updated_at = CURRENT_TIMESTAMP`,
    )
      .bind(parsed.bizDomainId, r.scope, await encryptSecret(env.ENCRYPTION_KEY, r.apiKey), parsed.userId)
      .run();
  } catch (e) {
    console.error("installation save failed", (e as Error).name);
    return text(500, "نصب در مارکت‌پلیس تأیید شد اما ذخیره‌ی آن ناموفق بود؛ نصب را دوباره از دیدار شروع کن.", clear);
  }

  return text(200, "نصب کامل شد. می‌توانی به دیدار برگردی.", clear);
}

// ---------- Links (Deals list + Deal details) ----------
export async function linkExtension(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const r = await startRun(req, env, ctx, "link", { target: "extension" });
  return r.ok ? linkPage("Hello DIDAR!") : linkPage(r.message, r.status);
}

// ---------- Custom modal / Custom panel / Settings (any valid location; settings has none) ----------
async function iframeExtension(
  req: Request, env: Env, ctx: ExecutionContext,
  kind: "custom_modal" | "custom_panel" | "settings", target: "extension" | "settings_page", message = "Hello DIDAR!",
): Promise<Response> {
  // resume: an iframe reload (same, already spent launchCode) or a request without launchCode uses the stored session.
  const r = await startRun(req, env, ctx, kind, { target }, undefined, { resume: true });
  if (!r.ok) return framePage(env.DIDAR_ORIGIN, r.message, r.status);
  // The cookie carries only the random session id; it lives as long as the session can be refreshed.
  return framePage(env.DIDAR_ORIGIN, message, 200, {
    "Set-Cookie": iframeCookie(SESSION_COOKIE, r.run.sessionId, r.run.sessionExpiresInSeconds),
  });
}
export const customModal = (req: Request, env: Env, ctx: ExecutionContext) =>
  iframeExtension(req, env, ctx, "custom_modal", "extension");
export const customPanel = (req: Request, env: Env, ctx: ExecutionContext) =>
  iframeExtension(req, env, ctx, "custom_panel", "extension", "hello custom Panel!");
export const settingsPage = (req: Request, env: Env, ctx: ExecutionContext) =>
  iframeExtension(req, env, ctx, "settings", "settings_page");

// ---------- Session status for follow-up requests from the iframe (same origin, cookie only) ----------
// Returns the trusted context and expiries, never a token. Refreshes the JWT when close to expiry.
export async function sessionInfo(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const s = await getValidRuntimeSession(req, env, ctx);
  const headers = { "Cache-Control": "no-store" };
  if (!s.ok) return json({ ok: false, code: s.reason, message: s.message, relaunch: s.relaunch }, { status: s.status, headers });
  const { context: c, accessTokenExpiresAt, sessionExpiresAt } = s.session;
  return json({
    ok: true,
    session: {
      target: c.target, runtimeId: c.runtimeId, location: c.location, entityType: c.entityType, entityIds: c.entityIds,
      accessTokenExpiresInSeconds: Math.max(0, accessTokenExpiresAt - nowSec()),
      sessionExpiresAt: new Date(sessionExpiresAt * 1000).toISOString(),
    },
  }, { headers });
}
