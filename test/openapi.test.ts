import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CONFIG } from "../src/config";
import { encryptSecret } from "../src/crypto";
import { DidarError, didarOpenApi } from "../src/didar";
import worker from "../src/index";
import { sessionOpenApi } from "../src/session";
import { BIZ, envelope, FakeD1, fakeFetch, jsonRes, makeCtx, makeEnv, migratedDb, req, runCookie, tokenSet } from "./helpers";

const OTHER_BIZ = "55555555-5555-4555-8555-555555555555";
const KEY_A = "installation-key-of-biz-aaaa";
const KEY_B = "installation-key-of-biz-bbbb";
let db: FakeD1;

async function install(biz: string, key: string, status = "active") {
  db.sqlite.prepare(`INSERT INTO installations (biz_domain_id, api_key_encrypted, scope, status) VALUES (?, ?, 'full api access', ?)`)
    .run(biz, await encryptSecret(makeEnv(db).ENCRYPTION_KEY, key), status);
}

beforeEach(async () => {
  db = migratedDb();
  await install(BIZ, KEY_A);
  await install(OTHER_BIZ, KEY_B);
});
afterEach(() => vi.useRealTimers());

describe("Didar OpenAPI with the installation's api_key (no DIDAR_API_KEY)", () => {
  it("with LOG_RAW_REQUESTS = \"false\" the apikey is masked in the logged URL again", async () => {
    fakeFetch(() => jsonRes(200, { Response: [] }));
    const { ctx, flush } = makeCtx();
    await didarOpenApi(makeEnv(db, { LOG_RAW_REQUESTS: "false" }), ctx, "/api/Tag/GetTagList", undefined, BIZ);
    await flush();
    expect(db.dump(["external_api_calls"])).not.toContain(KEY_A);
    expect(db.rows("SELECT redaction_version v FROM external_api_calls")).toEqual([{ v: 2 }]);
  });

  it("uses exactly the api_key of the given BizDomain, logs the request as sent, never sends the Runtime JWT", async () => {
    const calls = fakeFetch(() => jsonRes(200, { Response: [{ Id: 1 }] }));
    const { ctx, flush } = makeCtx();
    expect(await didarOpenApi(makeEnv(db), ctx, "/api/Tag/GetTagList", undefined, BIZ)).toEqual([{ Id: 1 }]);
    await didarOpenApi(makeEnv(db), ctx, "/api/Tag/GetTagList", undefined, OTHER_BIZ);
    await flush();
    expect(calls[0].url).toBe(`${CONFIG.DIDAR_APP_URL}/api/Tag/GetTagList?apikey=${KEY_A}`);
    expect(calls[1].url).toContain(`apikey=${KEY_B}`);
    expect(new Headers(calls[0].init.headers).get("Authorization")).toBeNull();
    // LOG_RAW_REQUESTS = "true": the URL is logged exactly as sent, ?apikey= included.
    expect(db.rows("SELECT request_url u FROM external_api_calls ORDER BY id").map((r) => r.u)).toEqual([calls[0].url, calls[1].url]);
    expect(db.nonRequestLog()).not.toContain(KEY_A);
    expect(db.rows("SELECT DISTINCT biz_domain_id b FROM external_api_calls ORDER BY b").map((r) => r.b)).toEqual([BIZ, OTHER_BIZ].sort()); // logged under its BizDomain
  });

  it.each([
    ["no installation", "66666666-6666-4666-8666-666666666666", "INSTALLATION_NOT_FOUND"],
    ["revoked installation", "77777777-7777-4777-8777-777777777777", "INSTALLATION_INACTIVE"],
    ["unknown BizDomain", "", "BIZ_DOMAIN_UNKNOWN"],
  ])("%s: nothing is sent", async (_n, biz, code) => {
    await install("77777777-7777-4777-8777-777777777777", "revoked-key", "revoked");
    const calls = fakeFetch(() => jsonRes(200, { Response: [] }));
    await expect(didarOpenApi(makeEnv(db), makeCtx().ctx, "/api/Tag/GetTagList", undefined, biz)).rejects.toMatchObject({ code });
    await expect(didarOpenApi(makeEnv(db), makeCtx().ctx, "/x", undefined, biz)).rejects.toBeInstanceOf(DidarError);
    expect(calls).toHaveLength(0);
  });
});

describe("sessionOpenApi: session first, then that session's BizDomain key", () => {
  async function launch() {
    fakeFetch(() => jsonRes(200, envelope(tokenSet())));
    const res = await worker.fetch(req("/didar/custom-panel?launchCode=LC1"), makeEnv(db), makeCtx().ctx);
    return runCookie(res)!;
  }

  it("valid session: calls with its own BizDomain's key (from the token's biz_domain_id claim)", async () => {
    const cookie = await launch();
    const calls = fakeFetch(() => jsonRes(200, { Response: { ok: 1 } }));
    const r = await sessionOpenApi(req("/", { cookie }), makeEnv(db), makeCtx().ctx, "/api/Deal/GetDeal", { Id: "d1" });
    expect(r).toEqual({ ok: true, data: { ok: 1 } });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain(`apikey=${KEY_A}`);
    expect(calls[0].url).not.toContain(KEY_B);
  });

  it("no session / revoked session: no OpenAPI call at all", async () => {
    const calls = fakeFetch(() => jsonRes(200, { Response: {} }));
    const none = await sessionOpenApi(req("/"), makeEnv(db), makeCtx().ctx, "/api/Deal/GetDeal");
    expect(none).toMatchObject({ ok: false, reason: "NO_SESSION" });

    const cookie = await launch();
    db.exec(`UPDATE runtime_sessions SET status = 'revoked', status_reason = 'INSTALLATION_ACCESS_DENIED'`);
    const calls2 = fakeFetch(() => jsonRes(200, { Response: {} }));
    const revoked = await sessionOpenApi(req("/", { cookie }), makeEnv(db), makeCtx().ctx, "/api/Deal/GetDeal");
    expect(revoked).toMatchObject({ ok: false, status: 403, reason: "INSTALLATION_ACCESS_DENIED" });
    expect(calls).toHaveLength(0);
    expect(calls2).toHaveLength(0);
  });

  it("session valid but its installation was removed: 409, nothing sent", async () => {
    const cookie = await launch();
    db.exec(`DELETE FROM installations WHERE biz_domain_id = '${BIZ}'`);
    const calls = fakeFetch(() => jsonRes(200, { Response: {} }));
    const r = await sessionOpenApi(req("/", { cookie }), makeEnv(db), makeCtx().ctx, "/api/Deal/GetDeal");
    expect(r).toMatchObject({ ok: false, status: 409, reason: "INSTALLATION_NOT_FOUND" });
    expect(calls).toHaveLength(0);
  });
});
