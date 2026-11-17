import { AppConfig, CONFIG, Secrets } from "./config";
import { SECRETS } from "./secrets"; // git-ignored; copy src/secrets.example.ts

/** What Cloudflare provides: only the D1 binding. Settings are in src/config.ts, secrets in src/secrets.ts. */
export interface Bindings {
  DB: D1Database;
}

/** Bindings + project config + project secrets. Handlers always receive this, built per request by withConfig. */
export type Env = Bindings & AppConfig & Secrets;

/** The project files always win: same-named Cloudflare variables or secrets are ignored. */
export const withConfig = (bindings: Bindings): Env => ({ ...bindings, ...SECRETS, ...CONFIG });

const enc = new TextEncoder();

export const nowIso = () => new Date().toISOString();
export const nowSec = () => Math.floor(Date.now() / 1000);

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 24): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecodeJson(part: string): Record<string, unknown> | null {
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

export function getCookie(req: Request, name: string): string | null {
  const header = req.headers.get("Cookie") ?? "";
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}

/** Cookie readable inside Didar's iframe (third-party context). */
export function iframeCookie(name: string, value: string, maxAgeSec: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; Secure; SameSite=None; Partitioned`;
}

export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function text(status: number, message: string, headers: HeadersInit = {}): Response {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...headers } });
}

export function escapeHtml(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

// ---- Redaction: secrets never reach logs, event tables, debug output or the browser ----
// Keys are compared after normalisation (lower case, separators removed), so accessToken, access_token,
// ACCESS-TOKEN and AccessToken are the same key. error.code / traceId / refreshTokenExpiresAt stay visible.
export const REDACTED = "[REDACTED]";

const SECRET_KEYS = new Set([
  "clientsecret", "launchcode", "state", "accesstoken", "refreshtoken", "idtoken", "token", "apikey", "xapikey",
  "authorization", "proxyauthorization", "cookie", "setcookie", "password", "secret", "sessionid", "didarrun",
]);

export const normalizeKey = (k: string) => k.toLowerCase().replace(/[^a-z0-9]/g, "");

/** True for any key that names a credential: the fixed set plus *token, *secret, *apikey, *password. */
export function isSecretKey(key: string, extra: readonly string[] = []): boolean {
  const k = normalizeKey(key);
  if (SECRET_KEYS.has(k) || extra.some((e) => normalizeKey(e) === k)) return true;
  return k.endsWith("token") || k.endsWith("secret") || k.endsWith("apikey") || k.endsWith("password");
}

/** `extra` adds keys for this call only (e.g. "code" in request bodies; error.code in responses stays visible). */
export function redactDeep(value: unknown, extra: readonly string[] = [], known: readonly string[] = []): unknown {
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, extra, known));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = isSecretKey(k, extra) && v != null && v !== "" ? REDACTED : redactDeep(v, extra, known);
    return out;
  }
  return typeof value === "string" ? scrubText(value, known) : value;
}

/** Collects the values of every secret key in a parsed body, so they can be scrubbed from any other text too. */
export function collectSecrets(value: unknown, extra: readonly string[] = [], out: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((v) => collectSecrets(v, extra, out));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (isSecretKey(k, extra) && typeof v === "string" && v) out.push(v);
      else collectSecrets(v, extra, out);
    }
  }
  return out;
}

/**
 * Removes every known secret value (exact match, also URL-encoded) and anything that looks like a JWT or a long
 * opaque token. Known values matter: a refresh token may contain dots or be short enough to escape the regexes.
 */
export function scrubText(s: string, known: readonly string[] = []): string {
  let out = s;
  for (const secret of [...new Set(known)].filter((k) => k && k.length >= 6).sort((a, b) => b.length - a.length)) {
    for (const form of new Set([secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)])) out = out.split(form).join(REDACTED);
  }
  return maskTokens(out);
}

export function maskTokens(s: string): string {
  return s
    .replace(/eyJ[\w-]+\.[\w-]+\.[\w-]*/g, "[REDACTED_JWT]")
    .replace(/[A-Za-z0-9+_-]{40,}={0,2}/g, REDACTED); // long opaque values; dotted or short ones are caught via `known`
}

/** `key=value` / `"key":"value"` pairs for secret keys inside free text (non-JSON bodies, error messages). */
function scrubPairs(s: string, extra: readonly string[]): string {
  return s
    .replace(/("([^"\\]{1,64})"\s*:\s*)"(?:[^"\\]|\\.)*"/g, (m, pre: string, key: string) => (isSecretKey(key, extra) ? `${pre}"${REDACTED}"` : m))
    .replace(/(^|[?&\s;,])([A-Za-z0-9_.-]{1,64})=([^&\s;,]*)/g, (m, sep: string, key: string) => (isSecretKey(key, extra) ? `${sep}${key}=${REDACTED}` : m));
}

/** Any request/response body (JSON, form-urlencoded or text) with secrets removed. */
export function redactBody(
  raw: string | null | undefined, opts: { extra?: readonly string[]; known?: readonly string[]; contentType?: string | null; max?: number } = {},
): string | null {
  if (raw == null || raw === "") return null;
  const { extra = [], known = [], contentType, max = 500_000 } = opts;
  const clip = (s: string) => (s.length > max ? `${s.slice(0, max)}…[truncated ${s.length - max} chars]` : s);
  try {
    return clip(JSON.stringify(redactDeep(JSON.parse(raw), extra, known)));
  } catch {
    /* not JSON */
  }
  if ((contentType ?? "").includes("application/x-www-form-urlencoded")) {
    const p = new URLSearchParams(raw);
    for (const k of [...new Set(p.keys())]) if (isSecretKey(k, extra)) p.set(k, REDACTED);
    return clip(scrubText(p.toString().replace(/%5BREDACTED%5D/g, REDACTED), known));
  }
  // e.g. a Cloudflare "error code: 502" page: keep it so the real error is visible.
  return clip("[text] " + scrubText(scrubPairs(raw, extra), known));
}

/** Error messages / anything printed with console.*: secret pairs, known values and token-looking strings removed. */
export function redactMessage(s: unknown, known: readonly string[] = []): string {
  return scrubText(scrubPairs(String(s ?? ""), []), known).slice(0, 2000);
}

export function redactHeaders(h: Headers, known: readonly string[] = []): string {
  const out: Record<string, string> = {};
  h.forEach((v, k) => (out[k] = isSecretKey(k) ? REDACTED : k in out ? `${out[k]}, ${scrubText(v, known)}` : scrubText(v, known)));
  return JSON.stringify(out);
}

/** Query string with secret params (apikey, launchCode, code, state, refresh_token, ...) masked. */
export function redactedQuery(url: URL, known: readonly string[] = []): string {
  const p = new URLSearchParams(url.search);
  for (const k of [...new Set(p.keys())]) if (isSecretKey(k, ["code"])) p.set(k, REDACTED);
  return scrubText(p.toString().replace(/%5BREDACTED%5D/g, REDACTED), known);
}

/** Full URL with secret query params masked and known secrets removed from the path; the fragment is dropped. */
export function redactUrl(raw: string, known: readonly string[] = []): string {
  try {
    const u = new URL(raw);
    const q = redactedQuery(u, known);
    return `${u.origin}${scrubText(u.pathname, known)}${q ? "?" + q : ""}`;
  } catch {
    return "[unparseable url]";
  }
}

/** Secret values from the environment that must never appear in any log, whatever key they sit under. */
export const envSecrets = (env: Partial<Env>): string[] =>
  [env.DIDAR_CLIENT_SECRET, env.ENCRYPTION_KEY].filter((v): v is string => !!v);
