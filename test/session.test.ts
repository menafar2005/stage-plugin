import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decryptSecret } from "../src/crypto";
import {
  BIZ, Call, envelope, errorEnvelope, fakeFetch, jsonRes, makeCtx, makeEnv, migratedDb, req, runCookie, tokenSet, USER_A, USER_B, FakeD1,
} from "./helpers";

type Worker = typeof import("../src/index").default;
type SessionMod = typeof import("../src/session");

/** A separate module graph = a separate Worker isolate (no shared memory), same D1. */
async function instance(): Promise<{ worker: Worker; session: SessionMod }> {
  vi.resetModules();
  const worker = (await import("../src/index")).default;
  const session = await import("../src/session");
  return { worker, session };
}

/** Session row + its single active refresh token (as session.ts reads it). */
const SESSION_WITH_TOKEN = `SELECT s.*, t.refresh_token_encrypted FROM runtime_sessions s
  LEFT JOIN runtime_refresh_tokens t ON t.session_id = s.id AND t.status = 'active'`;

let db: FakeD1;
let T0: number;
const advance = (sec: number) => vi.setSystemTime(Date.now() + sec * 1000);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  T0 = Date.UTC(2026, 10, 16, 10, 0, 0);
  vi.setSystemTime(T0);
  db = migratedDb();
});
afterEach(() => vi.useRealTimers());

/** Marketplace stand-in: launch codes -> token sets; refresh tokens rotate (old one dies at once). */
function marketplace(opts: { refreshDelayMs?: number; refresh?: (c: Call) => Response | Promise<Response> } = {}) {
  const issued = new Map<string, ReturnType<typeof tokenSet>>(); // refreshToken -> set
  const launches = new Map<string, string>(); // launchCode -> userId
  const used = new Set<string>();
  const calls = fakeFetch(async (c) => {
    if (c.url.endsWith("/api/v1/runtime/token")) {
      const code = c.body.launchCode;
      if (used.has(code) || !launches.has(code)) return jsonRes(409, errorEnvelope("LAUNCH_CODE_ALREADY_USED"));
      used.add(code);
      const set = tokenSet(launches.get(code));
      issued.set(set.refreshToken, set);
      return jsonRes(200, envelope(set));
    }
    if (c.url.endsWith("/api/v1/runtime/refresh")) {
      if (opts.refreshDelayMs) await new Promise((r) => setTimeout(r, opts.refreshDelayMs));
      if (opts.refresh) return opts.refresh(c);
      const old = issued.get(c.body.refreshToken);
      if (!old) return jsonRes(401, errorEnvelope("REFRESH_TOKEN_INVALID"));
      issued.delete(c.body.refreshToken);
      const set = tokenSet(JSON.parse(Buffer.from(old.accessToken.split(".")[1], "base64url").toString()).sub, {
        refreshTokenExpiresAt: new Date(Date.now() + 30 * 86400 * 1000).toISOString(), // server tries to extend: must be ignored
      });
      issued.set(set.refreshToken, set);
      return jsonRes(200, envelope(set));
    }
    return jsonRes(404, {});
  });
  return { calls, issued, launch: (code: string, user = USER_A) => launches.set(code, user) };
}

const refreshCalls = (calls: Call[]) => calls.filter((c) => c.url.endsWith("/runtime/refresh"));
const tokenCalls = (calls: Call[]) => calls.filter((c) => c.url.endsWith("/runtime/token"));

async function launch(worker: Worker, code: string) {
  const env = makeEnv(db);
  const { ctx, flush } = makeCtx();
  const res = await worker.fetch(req(`/didar/custom-panel?launchCode=${code}`), env, ctx);
  await flush();
  return { res, cookie: runCookie(res)!, html: await res.text() };
}

describe("refreshable runtime session", () => {
  it("stores tokens encrypted, never in the browser response or logs, cookie lives as long as the session", async () => {
    const mk = marketplace();
    mk.launch("LC1");
    const { worker } = await instance();
    const { res, cookie, html } = await launch(worker, "LC1");
    expect(res.status).toBe(200);
    const set = [...mk.issued.values()][0];

    const row = db.rows(SESSION_WITH_TOKEN)[0];
    expect(db.rows("SELECT refresh_token_encrypted r FROM runtime_sessions")[0].r).toBeNull(); // the token lives in its own table
    expect(db.rows("SELECT session_id, user_id, biz_domain_id, status, expires_at FROM runtime_refresh_tokens")).toEqual([
      { session_id: row.id, user_id: USER_A, biz_domain_id: BIZ, status: "active", expires_at: row.refresh_token_expires_at },
    ]);
    expect(row.access_token_encrypted).toBeTruthy();
    expect(await decryptSecret(makeEnv(db).ENCRYPTION_KEY, row.access_token_encrypted)).toBe(set.accessToken);
    expect(await decryptSecret(makeEnv(db).ENCRYPTION_KEY, row.refresh_token_encrypted)).toBe(set.refreshToken);
    expect(row.access_token_expires_at).toBe(T0 / 1000 + 300);
    expect(row.refresh_token_expires_at).toBe(Math.floor(Date.parse(set.refreshTokenExpiresAt) / 1000));
    expect(row.expires_at).toBe(row.refresh_token_expires_at); // cleanup keeps it for the whole session
    expect(JSON.parse(row.context_json).extraField).toBe("kept");

    // Browser: only the random id, with the iframe cookie attributes; no token anywhere.
    const sc = res.headers.get("Set-Cookie")!;
    expect(sc).toMatch(/HttpOnly; Secure; SameSite=None; Partitioned/);
    expect(Number(/Max-Age=(\d+)/.exec(sc)![1])).toBe(7 * 86400);
    const everythingSent = html + JSON.stringify([...res.headers]);
    for (const secret of [set.accessToken, set.refreshToken]) {
      expect(everythingSent).not.toContain(secret);
      expect(db.dump(["external_api_calls", "extension_events", "rate_limits"])).not.toContain(secret);
    }
    // LOG_RAW_REQUESTS: the launch request (with its launchCode) is logged as sent; responses stay redacted.
    expect(db.requestLog()).toContain("LC1");
    expect(db.nonRequestLog()).not.toContain("LC1");
    expect(cookie).not.toContain(set.refreshToken);
  });

  it("refreshes near expiry, uses the replacement next time, absolute expiry never moves", async () => {
    const mk = marketplace();
    mk.launch("LC1");
    const { worker, session } = await instance();
    const { cookie } = await launch(worker, "LC1");
    const first = [...mk.issued.values()][0];
    const absEnd = db.rows("SELECT refresh_token_expires_at AS e FROM runtime_sessions")[0].e;
    const env = makeEnv(db);
    const { ctx, flush } = makeCtx();

    // Plenty of time left: no refresh.
    let s = await session.getValidRuntimeSession(req("/didar/session", { cookie }), env, ctx);
    expect(s.ok && s.session.accessToken).toBe(first.accessToken);
    expect(refreshCalls(mk.calls)).toHaveLength(0);

    advance(280); // 20s left < 30s margin
    s = await session.getValidRuntimeSession(req("/didar/session", { cookie }), env, ctx);
    expect(s.ok).toBe(true);
    if (!s.ok) return;
    expect(s.session.refreshed).toBe(true);
    expect(s.session.accessToken).not.toBe(first.accessToken);
    expect(refreshCalls(mk.calls)[0].body).toEqual({ refreshToken: first.refreshToken, clientId: "test-client-id", clientSecret: env.DIDAR_CLIENT_SECRET });
    const second = s.session.accessToken;

    // Next call: the stored replacement, no new refresh.
    const again = await session.getValidRuntimeSession(req("/didar/session", { cookie }), env, ctx);
    expect(again.ok && again.session.accessToken).toBe(second);
    expect(refreshCalls(mk.calls)).toHaveLength(1);

    // Next refresh sends the ROTATED refresh token, and the absolute end stays the original one.
    advance(290);
    const third = await session.getValidRuntimeSession(req("/didar/session", { cookie }), env, ctx);
    expect(third.ok).toBe(true);
    const rc = refreshCalls(mk.calls);
    expect(rc).toHaveLength(2);
    expect(rc[1].body.refreshToken).not.toBe(first.refreshToken);
    const row = db.rows("SELECT * FROM runtime_sessions")[0];
    expect(row.refresh_token_expires_at).toBe(absEnd);
    expect(row.expires_at).toBe(absEnd);
    expect(row.version).toBe(2);
    expect(tokenCalls(mk.calls)).toHaveLength(1); // the launchCode was exchanged exactly once

    // Token history: two rotated (ciphertext wiped, linked to their replacement), one active, same absolute end.
    const hist = db.rows("SELECT id, status, refresh_token_encrypted IS NOT NULL AS has_ct, replaced_by_id, expires_at FROM runtime_refresh_tokens ORDER BY id");
    expect(hist.map((h) => [h.status, h.has_ct])).toEqual([["rotated", 0], ["rotated", 0], ["active", 1]]);
    expect([hist[0].replaced_by_id, hist[1].replaced_by_id, hist[2].replaced_by_id]).toEqual([hist[1].id, hist[2].id, null]);
    expect(hist.every((h) => h.expires_at === absEnd)).toBe(true);
    const active = db.rows("SELECT refresh_token_encrypted c FROM runtime_refresh_tokens WHERE status = 'active'")[0].c;
    expect(mk.issued.has(await decryptSecret(env.ENCRYPTION_KEY, active))).toBe(true); // the latest issued token

    await flush();
    // Requests are logged raw (the refresh token sent + client secret); responses never show any token.
    const responses = db.nonRequestLog();
    for (const set of [first, ...mk.issued.values()]) {
      expect(responses).not.toContain(set.accessToken);
      expect(responses).not.toContain(set.refreshToken);
      expect(db.requestLog()).not.toContain(set.accessToken); // access tokens are never sent to the marketplace
    }
    expect(responses).not.toContain(env.DIDAR_CLIENT_SECRET);
    expect(db.requestLog()).toContain(first.refreshToken);
    expect(db.requestLog()).toContain(env.DIDAR_CLIENT_SECRET);
    expect(db.rows("SELECT DISTINCT redaction_version v FROM external_api_calls")).toEqual([{ v: 3 }]);
  });

  it("an access token never outlives the absolute session end; after it, a new launch is required", async () => {
    const mk = marketplace();
    mk.launch("LC1");
    const { worker, session } = await instance();
    const { cookie } = await launch(worker, "LC1");
    advance(7 * 86400 + 1);
    const s = await session.getValidRuntimeSession(req("/", { cookie }), makeEnv(db), makeCtx().ctx);
    expect(s.ok).toBe(false);
    if (!s.ok) expect([s.reason, s.relaunch]).toEqual(["SESSION_EXPIRED", true]);
    expect(refreshCalls(mk.calls)).toHaveLength(0);
    const ended = db.rows(SESSION_WITH_TOKEN)[0];
    expect([ended.access_token_encrypted, ended.refresh_token_encrypted, ended.status]).toEqual([null, null, "expired"]);
    expect(db.rows("SELECT status, status_reason, refresh_token_encrypted r FROM runtime_refresh_tokens")).toEqual([{ status: "ended", status_reason: "SESSION_EXPIRED", r: null }]);
  });

  it("two independent Worker instances racing: exactly one refresh, both get the stored result", async () => {
    const mk = marketplace({ refreshDelayMs: 150 });
    mk.launch("LC1");
    const a = await instance();
    const b = await instance();
    expect(a.session).not.toBe(b.session);
    const { cookie } = await launch(a.worker, "LC1");
    advance(301); // JWT expired, session alive

    const env = makeEnv(db);
    const opts = { pollMs: 20, maxWaitMs: 3000 };
    const [ra, rb] = await Promise.all([
      a.session.getValidRuntimeSession(req("/", { cookie }), env, makeCtx().ctx, opts),
      b.session.getValidRuntimeSession(req("/", { cookie }), env, makeCtx().ctx, opts),
    ]);
    expect(refreshCalls(mk.calls)).toHaveLength(1);
    expect(ra.ok && rb.ok).toBe(true);
    if (ra.ok && rb.ok) {
      expect(ra.session.accessToken).toBe(rb.session.accessToken);
      expect([ra.session.refreshed, rb.session.refreshed].filter(Boolean)).toHaveLength(1);
    }
    expect(db.rows("SELECT version, refresh_lease_id FROM runtime_sessions")[0]).toEqual({ version: 1, refresh_lease_id: null });
  });

  it("a waiter gives up after a bounded time instead of refreshing itself", async () => {
    const mk = marketplace({ refreshDelayMs: 400 });
    mk.launch("LC1");
    const a = await instance();
    const b = await instance();
    const { cookie } = await launch(a.worker, "LC1");
    advance(301);
    const env = makeEnv(db);
    const slow = a.session.getValidRuntimeSession(req("/", { cookie }), env, makeCtx().ctx);
    // Wait until the first request holds the lease (it is then inside the 400ms marketplace call).
    for (let i = 0; i < 100 && !db.rows("SELECT refresh_lease_id l FROM runtime_sessions")[0].l; i++) await new Promise((r) => setTimeout(r, 5));
    const quick = await b.session.getValidRuntimeSession(req("/", { cookie }), env, makeCtx().ctx, { pollMs: 20, maxWaitMs: 100 });
    expect(quick.ok).toBe(false);
    if (!quick.ok) expect([quick.status, quick.reason]).toEqual([503, "REFRESH_IN_PROGRESS"]);
    expect((await slow).ok).toBe(true);
    expect(refreshCalls(mk.calls)).toHaveLength(1);
  });

  it("an iframe reload with the spent launchCode, or later requests, resume via cookie without re-exchanging", async () => {
    const mk = marketplace();
    mk.launch("LC1");
    const { worker } = await instance();
    const { cookie } = await launch(worker, "LC1");
    const env = makeEnv(db);

    const reload = await worker.fetch(req("/didar/custom-panel?launchCode=LC1", { cookie }), env, makeCtx().ctx);
    expect(reload.status).toBe(200);
    expect(await reload.text()).toContain("hello custom Panel!");
    const noCode = await worker.fetch(req("/didar/custom-panel", { cookie }), env, makeCtx().ctx);
    expect(noCode.status).toBe(200);

    advance(290);
    const info = await worker.fetch(req("/didar/session", { cookie }), env, makeCtx().ctx);
    const body = await info.json<any>();
    expect(info.status).toBe(200);
    expect(body.session).toMatchObject({ runtimeId: expect.any(String), target: "extension", entityIds: ["d1"] });
    expect(JSON.stringify(body)).not.toMatch(/eyJ|rt\./);
    expect(tokenCalls(mk.calls)).toHaveLength(1);
    expect(refreshCalls(mk.calls)).toHaveLength(1);

    // Another extension kind cannot borrow this session.
    const modal = await worker.fetch(req("/didar/custom-modal", { cookie }), env, makeCtx().ctx);
    expect(modal.status).toBe(401);
  });

  it("keeps users' sessions apart", async () => {
    const mk = marketplace();
    mk.launch("LCA", USER_A);
    mk.launch("LCB", USER_B);
    const { worker, session } = await instance();
    const a = await launch(worker, "LCA");
    const b = await launch(worker, "LCB");
    expect(a.cookie).not.toBe(b.cookie);
    const env = makeEnv(db);
    const sa = await session.getValidRuntimeSession(req("/", { cookie: a.cookie }), env, makeCtx().ctx);
    const sb = await session.getValidRuntimeSession(req("/", { cookie: b.cookie }), env, makeCtx().ctx);
    expect(sa.ok && sa.session.userId).toBe(USER_A);
    expect(sb.ok && sb.session.userId).toBe(USER_B);
    expect(sa.ok && sb.ok && sa.session.accessToken !== sb.session.accessToken).toBe(true);
    const forged = await session.getValidRuntimeSession(req("/", { cookie: "didar_run=guess" }), env, makeCtx().ctx);
    expect(forged.ok).toBe(false);
    expect(db.rows("SELECT DISTINCT biz_domain_id b FROM runtime_sessions")).toEqual([{ b: BIZ }]);
  });
});

describe("refresh errors", () => {
  async function expiredSession(refresh: (c: Call) => Response | Promise<Response>) {
    const mk = marketplace({ refresh });
    mk.launch("LC1");
    const { worker, session } = await instance();
    const { cookie } = await launch(worker, "LC1");
    advance(301);
    const call = () => session.getValidRuntimeSession(req("/", { cookie }), makeEnv(db), makeCtx().ctx);
    return { mk, call, row: () => db.rows(SESSION_WITH_TOKEN)[0] };
  }

  it("INSTALLATION_ACCESS_DENIED: session revoked, tokens wiped, no retry", async () => {
    const { mk, call, row } = await expiredSession(() => jsonRes(403, errorEnvelope("INSTALLATION_ACCESS_DENIED")));
    const r = await call();
    expect(r.ok).toBe(false);
    if (!r.ok) expect([r.status, r.reason]).toEqual([403, "INSTALLATION_ACCESS_DENIED"]);
    expect(row()).toMatchObject({ status: "revoked", access_token_encrypted: null, refresh_token_encrypted: null });
    await call();
    expect(refreshCalls(mk.calls)).toHaveLength(1);
  });

  it("REFRESH_TOKEN_EXPIRED: re-launch required", async () => {
    const { call, row } = await expiredSession(() => jsonRes(401, errorEnvelope("REFRESH_TOKEN_EXPIRED")));
    const r = await call();
    expect(!r.ok && r.relaunch).toBe(true);
    expect(row().status).toBe("expired");
  });

  it.each(["RUNTIME_UNAVAILABLE", "EXTENSION_RUNTIME_UNAVAILABLE", "SETTINGS_PAGE_RUNTIME_UNAVAILABLE"])("%s: unavailable", async (code) => {
    const { call, row } = await expiredSession(() => jsonRes(403, errorEnvelope(code)));
    const r = await call();
    expect(!r.ok && r.reason).toBe(code);
    expect(row().status).toBe("unavailable");
  });

  it("INVALID_CLIENT_CREDENTIALS: configuration error, session kept, no repeated refresh during cool-down", async () => {
    const { mk, call, row } = await expiredSession(() => jsonRes(401, errorEnvelope("INVALID_CLIENT_CREDENTIALS")));
    const r1 = await call();
    const r2 = await call();
    expect(!r1.ok && r1.status).toBe(503);
    expect(!r2.ok && r2.reason).toBe("INVALID_CLIENT_CREDENTIALS");
    expect(refreshCalls(mk.calls)).toHaveLength(1);
    expect(row().status).toBe("active");
    expect(row().refresh_token_encrypted).toBeTruthy();
  });

  it("DIDAR_API_KEY_NOT_CONFIGURED: not treated as JWT expiry", async () => {
    const { call, row } = await expiredSession(() => jsonRes(409, errorEnvelope("DIDAR_API_KEY_NOT_CONFIGURED")));
    const r = await call();
    expect(!r.ok && [r.status, r.relaunch]).toEqual([409, false]);
    expect(row().status).toBe("active");
  });

  it("timeout / connection lost: outcome unknown, old token never retried, re-launch required", async () => {
    const { mk, call, row } = await expiredSession(() => {
      throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
    });
    const r = await call();
    expect(!r.ok && [r.reason, r.relaunch]).toEqual(["REFRESH_OUTCOME_UNKNOWN", true]);
    await call();
    expect(refreshCalls(mk.calls)).toHaveLength(1);
    expect(row()).toMatchObject({ status: "reauth_required", refresh_token_encrypted: null });
  });

  it("5xx without error code is ambiguous too", async () => {
    const { call, row } = await expiredSession(() => new Response("error code: 502", { status: 502 }));
    const r = await call();
    expect(!r.ok && r.reason).toBe("REFRESH_OUTCOME_UNKNOWN");
    expect(row().status).toBe("reauth_required");
  });

  it("REFRESH_TOKEN_INVALID with no stored replacement: re-launch required", async () => {
    const { call, row } = await expiredSession(() => jsonRes(401, errorEnvelope("REFRESH_TOKEN_INVALID")));
    const r = await call();
    expect(!r.ok && r.reason).toBe("REFRESH_TOKEN_INVALID");
    expect(row().status).toBe("reauth_required");
  });

  it("REFRESH_TOKEN_INVALID after a concurrent refresh already stored a replacement: uses it", async () => {
    // Simulates a lease takeover: while our call is in flight another refresher stores new tokens (version + 1).
    const { encryptSecret } = await import("../src/crypto");
    const env = makeEnv(db);
    const replacement = tokenSet();
    const { call } = await expiredSession(async () => {
      db.sqlite.prepare(
        `UPDATE runtime_sessions SET access_token_encrypted = ?, refresh_token_encrypted = ?, access_token_expires_at = ?, version = version + 1`,
      ).run(await encryptSecret(env.ENCRYPTION_KEY, replacement.accessToken), await encryptSecret(env.ENCRYPTION_KEY, replacement.refreshToken), Math.floor(Date.now() / 1000) + 300);
      return jsonRes(401, errorEnvelope("REFRESH_TOKEN_INVALID"));
    });
    const r = await call();
    expect(r.ok && r.session.accessToken).toBe(replacement.accessToken);
  });

  it("a session from before the migration (no refresh token) asks for a new launch", async () => {
    const { worker } = await instance();
    marketplace();
    db.sqlite.prepare(
      `INSERT INTO runtime_sessions (session_id_hash, token_hash, expires_at, token_source) VALUES (?, 'legacy-token-hash', ?, 'custom_panel')`,
    ).run(await (await import("../src/util")).sha256Hex("legacy-cookie"), Math.floor(Date.now() / 1000) + 200);
    const res = await worker.fetch(req("/didar/session", { cookie: "didar_run=legacy-cookie" }), makeEnv(db), makeCtx().ctx);
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ ok: false, code: "REFRESH_NOT_AVAILABLE", relaunch: true });
  });
});
