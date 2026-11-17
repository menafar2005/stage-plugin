import { beforeEach, describe, expect, it } from "vitest";
import { decryptSecret } from "../src/crypto";
import worker from "../src/index";
import { BIZ, CLIENT_SECRET, FakeD1, fakeFetch, jsonRes, makeCtx, makeEnv, migratedDb, req, USER_A } from "./helpers";

const CODE = `${USER_A}.${BIZ}.unique-key-0123456789`;
const API_KEY = "installation-api-key-abcdef";
let db: FakeD1;
beforeEach(() => {
  db = migratedDb();
});

async function callback(query: string, cookie?: string, env = makeEnv(db)) {
  const { ctx, flush } = makeCtx();
  const res = await worker.fetch(req(`/didar/callback?${query}`, { cookie }), env, ctx);
  await flush();
  return { res, body: await res.text() };
}

describe("install callback (POST /install/auth/token)", () => {
  it("sends the exact form body and stores the encrypted api_key + scope", async () => {
    const calls = fakeFetch(() => jsonRes(200, { api_key: API_KEY, scope: "full api access" }));
    const { res, body } = await callback(`code=${encodeURIComponent(CODE)}&state=s1`, "didar_install_state=s1");
    expect(res.status).toBe(200);
    expect(body).toContain("نصب کامل شد");

    expect(calls).toHaveLength(1);
    const c = calls[0];
    expect(c.url).toBe("https://marketplace.didar.test/install/auth/token");
    expect(c.url).not.toContain("/api/v1/auth/token");
    expect(c.init.method).toBe("POST");
    expect(new Headers(c.init.headers).get("Content-Type")).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(c.init.body as string))).toEqual({
      grant_type: "authorization_code",
      code: CODE, // unchanged
      redirect_uri: "https://plugin.test/didar/callback",
      client_id: "test-client-id",
      client_secret: CLIENT_SECRET,
    });

    const row = db.rows("SELECT * FROM installations")[0];
    expect(row.biz_domain_id).toBe(BIZ);
    expect(row.installed_by_user_id).toBe(USER_A);
    expect(row.scope).toBe("full api access");
    expect(row.api_key_encrypted).not.toContain(API_KEY);
    expect(await decryptSecret(makeEnv(db).ENCRYPTION_KEY, row.api_key_encrypted)).toBe(API_KEY);
    // Not in the new response: nothing invented.
    expect([row.installation_id, row.app_public_id, row.installed_at]).toEqual([null, null, null]);

    // Logs: no install code, client secret or api_key.
    const logs = db.dump(["external_api_calls", "rate_limits"]);
    for (const s of [CODE, "unique-key-0123456789", CLIENT_SECRET, API_KEY]) expect(logs).not.toContain(s);
    expect(logs).toContain("full api access");
  });

  it("reinstall keeps existing data the new response does not carry", async () => {
    db.sqlite.prepare(
      `INSERT INTO installations (biz_domain_id, biz_domain_title, installation_id, app_public_id, scopes, api_key_encrypted, installed_at, status)
       VALUES (?, 'Acme', 14, 'app-1', '["basicinfo"]', 'old', '2026-09-29T09:55:22Z', 'revoked')`,
    ).run(BIZ);
    fakeFetch(() => jsonRes(200, { api_key: API_KEY, scope: "full api access" }));
    const { res } = await callback(`code=${encodeURIComponent(CODE)}`);
    expect(res.status).toBe(200);
    const rows = db.rows("SELECT * FROM installations");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ biz_domain_title: "Acme", installation_id: 14, app_public_id: "app-1", scopes: '["basicinfo"]', installed_at: "2026-09-29T09:55:22Z", status: "active", scope: "full api access" });
    expect(rows[0].api_key_encrypted).not.toBe("old");
  });

  it.each([
    ["invalid client", 401, { error: "invalid_client" }, 502, "Client"],
    ["invalid client (envelope)", 401, { succeeded: false, error: { code: "INVALID_CLIENT_CREDENTIALS" } }, 502, "Client"],
    ["invalid code", 400, { error: "invalid_grant" }, 400, "معتبر نیست"],
    ["expired code", 400, { succeeded: false, error: { code: "INSTALL_CODE_EXPIRED" } }, 400, "منقضی"],
    ["expired code (410)", 410, {}, 400, "منقضی"],
    ["used code", 409, { succeeded: false, error: { code: "INSTALL_CODE_ALREADY_USED" } }, 409, "قبلاً استفاده"],
    ["DidarService error", 502, { succeeded: false, error: { code: "DIDAR_SERVICE_ERROR" } }, 502, "سرویس دیدار"],
    ["old envelope instead of api_key", 200, { succeeded: true, data: { ApiKey: "x" } }, 502, "نصب کامل نشد"],
    ["empty api_key", 200, { api_key: "", scope: "s" }, 502, "نصب کامل نشد"],
  ])("%s: no install record, no success message, one call only", async (_n, status, payload, expStatus, msg) => {
    const calls = fakeFetch(() => jsonRes(status as number, payload));
    const { res, body } = await callback(`code=${encodeURIComponent(CODE)}`);
    expect(res.status).toBe(expStatus);
    expect(body).toContain(msg as string);
    expect(body).not.toContain("نصب کامل شد");
    expect(calls).toHaveLength(1);
    expect(db.rows("SELECT * FROM installations")).toHaveLength(0);
    const logs = db.dump(["external_api_calls"]);
    expect(logs).not.toContain(CODE);
    expect(logs).not.toContain(CLIENT_SECRET);
  });

  it("network error: no retry, no record", async () => {
    const calls = fakeFetch(() => {
      throw new TypeError("fetch failed");
    });
    const { res } = await callback(`code=${encodeURIComponent(CODE)}`);
    expect(res.status).toBe(502);
    expect(calls).toHaveLength(1);
    expect(db.rows("SELECT * FROM installations")).toHaveLength(0);
  });

  it("keeps the state check, and rejects before spending the code on bad config or a malformed code", async () => {
    const calls = fakeFetch(() => jsonRes(200, { api_key: API_KEY, scope: "x" }));
    expect((await callback(`code=${encodeURIComponent(CODE)}&state=wrong`, "didar_install_state=s1")).res.status).toBe(400);
    expect((await callback(`code=${encodeURIComponent(CODE)}`, undefined, makeEnv(db, { DIDAR_REDIRECT_URI: undefined }))).res.status).toBe(500);
    expect((await callback(`code=${encodeURIComponent(CODE)}`, undefined, makeEnv(db, { DIDAR_REDIRECT_URI: "https://plugin.test/other" }))).res.status).toBe(500);
    expect((await callback(`code=not-a-valid-code`)).res.status).toBe(400);
    expect(calls).toHaveLength(0);
    expect(db.rows("SELECT * FROM installations")).toHaveLength(0);
  });
});
