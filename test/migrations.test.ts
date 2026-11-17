import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { exchangeLaunchCode } from "../src/didar";
import { envelope, errorEnvelope, fakeFetch, jsonRes, makeCtx, makeEnv, migratedDb, readSql, tokenSet } from "./helpers";

afterEach(() => vi.useRealTimers());

const LEGACY_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWdhY3kifQ.legacysig";
const LEGACY_SECRET = "legacy-client-secret-xyz";

describe("migrations on an existing (0001) database", () => {
  it("applies 0002-0004 additively, keeps data and scrubs legacy logs (re-runnable)", () => {
    const db = migratedDb("0001_init.sql");
    db.exec(`
      INSERT INTO installations (biz_domain_id, installation_id, app_public_id, scopes, api_key_encrypted, installed_at)
        VALUES ('biz-1', 14, 'app-1', '["basicinfo"]', 'enc', '2026-09-29T09:55:22Z');
      INSERT INTO runtime_sessions (session_id_hash, token_hash, user_id, expires_at, token_source) VALUES ('sh', 'th', 'u1', 1800000000, 'custom_panel');
      INSERT INTO external_api_calls (service, request_started_at, request_method, request_url, request_headers, request_body, response_status, response_headers, response_body, error_message)
        VALUES ('didar.runtime_token', '2026-11-14', 'POST', 'https://marketplace/x?apikey=LEGACYKEY&a=1', '{"authorization":"Bearer ${LEGACY_TOKEN}"}',
          '{"launchCode":"LC","clientSecret":"${LEGACY_SECRET}"}', 401, '{"set-cookie":"a=b"}',
          '{"succeeded":false,"data":{"accessToken":"${LEGACY_TOKEN}"},"error":{"code":"INVALID_CLIENT_CREDENTIALS"},"meta":{"traceId":"tr-1"}}', 'msg ${LEGACY_TOKEN}');
      INSERT INTO external_api_calls (service, request_started_at, request_method, request_url, response_body)
        VALUES ('didar.complete_installation', '2026-11-14', 'POST', 'https://app/x', '{"Response":{"Succeeded":false,"Error":{"Code":"CODE_USED"},"Meta":{"TraceId":"tr-2"}}}');
    `);

    for (const f of ["0002_runtime_refresh_sessions.sql", "0003_installation_scope.sql", "0004_redact_api_logs.sql"]) db.exec(readSql(`migrations/${f}`));

    expect(db.rows("SELECT biz_domain_id, installation_id, app_public_id, scopes, api_key_encrypted, installed_at, scope FROM installations")[0])
      .toEqual({ biz_domain_id: "biz-1", installation_id: 14, app_public_id: "app-1", scopes: '["basicinfo"]', api_key_encrypted: "enc", installed_at: "2026-09-29T09:55:22Z", scope: null });
    expect(db.rows("SELECT user_id, expires_at, access_token_expires_at, status, version, refresh_token_encrypted FROM runtime_sessions")[0])
      .toEqual({ user_id: "u1", expires_at: 1800000000, access_token_expires_at: 1800000000, status: "active", version: 0, refresh_token_encrypted: null });

    const logs = db.rows("SELECT * FROM external_api_calls ORDER BY id");
    const all = JSON.stringify(logs);
    for (const s of [LEGACY_TOKEN, LEGACY_SECRET, "LEGACYKEY", '"LC"']) expect(all).not.toContain(s);
    expect(logs[0]).toMatchObject({ error_code: "INVALID_CLIENT_CREDENTIALS", trace_id: "tr-1", response_status: 401, request_url: "https://marketplace/x?[REDACTED_LEGACY]" });
    expect(JSON.parse(logs[0].response_body)).toMatchObject({ legacyRedacted: true, error: { code: "INVALID_CLIENT_CREDENTIALS" }, meta: { traceId: "tr-1" } });
    expect(logs[1]).toMatchObject({ error_code: "CODE_USED", trace_id: "tr-2" });

    // Re-running the scrub changes nothing (and new, already-redacted rows are never touched).
    db.exec(`INSERT INTO external_api_calls (service, request_started_at, request_method, request_url, response_body, redaction_version)
      VALUES ('new', '2026-11-16', 'POST', 'https://m/x?page=1', '{"data":{"accessToken":"[REDACTED]"}}', 2)`);
    const before = JSON.stringify(db.rows("SELECT * FROM external_api_calls"));
    db.exec(readSql("scripts/scrub-legacy-api-logs.sql"));
    db.exec(readSql("scripts/scrub-legacy-api-logs.sql"));
    expect(JSON.stringify(db.rows("SELECT * FROM external_api_calls"))).toBe(before);

    const checks = readSql("scripts/check-legacy-secrets.sql").split("\n").filter((l) => !l.startsWith("--")).join("\n")
      .split(";").map((s) => s.trim()).filter(Boolean).map((s) => db.rows(s)[0]);
    expect(checks).toHaveLength(6);
    expect(checks.find((c) => c.check_name.startsWith("external_api_calls: unscrubbed")).row_count).toBe(0);
    expect(checks.find((c) => c.check_name.includes("JWT-looking text")).row_count).toBe(0);
  });
});

describe("0005: refresh tokens move to their own table", () => {
  it("moves each stored refresh token (one active per session), clears the old column, and is safe to re-run", () => {
    const db = migratedDb("0004_redact_api_logs.sql");
    db.exec(`INSERT INTO runtime_sessions (session_id_hash, token_hash, user_id, biz_domain_id, runtime_id, expires_at, refresh_token_encrypted, refresh_token_expires_at)
      VALUES ('s1', 't1', 'u1', 'b1', 'r1', 1900000000, 'CIPHERTEXT-1', 1900000000), ('s2', 't2', 'u2', 'b2', 'r2', 1800000000, NULL, NULL);`);
    db.exec(readSql("migrations/0005_runtime_refresh_tokens.sql"));
    db.exec(readSql("migrations/0005_runtime_refresh_tokens.sql"));
    expect(db.rows("SELECT session_id, user_id, biz_domain_id, runtime_id, refresh_token_encrypted, expires_at, status FROM runtime_refresh_tokens"))
      .toEqual([{ session_id: 1, user_id: "u1", biz_domain_id: "b1", runtime_id: "r1", refresh_token_encrypted: "CIPHERTEXT-1", expires_at: 1900000000, status: "active" }]);
    expect(db.rows("SELECT COUNT(*) n FROM runtime_sessions WHERE refresh_token_encrypted IS NOT NULL")[0].n).toBe(0);
    expect(() => db.exec(`INSERT INTO runtime_refresh_tokens (session_id, expires_at) VALUES (1, 1)`)).toThrow(/UNIQUE/); // one active per session
  });
});

describe("remote stage-plugin-db state", () => {
  it("0001 applied by hand, then `migrations apply` re-runs 0001 and applies 0002-0004 without losing rows", () => {
    const db = migratedDb("0001_init.sql");
    db.exec(`INSERT INTO rate_limits (rate_key, route_key, window_start, request_count) VALUES ('ip:x', '/didar/link', 1, 1);
      INSERT INTO external_api_calls (service, request_started_at, request_method, request_url, response_body)
        VALUES ('didar.runtime_token', '2026-11-16', 'POST', 'https://marketplace/api/v1/runtime/token', '{"launchCode":"x"}');`);
    for (const f of ["0001_init.sql", "0002_runtime_refresh_sessions.sql", "0003_installation_scope.sql", "0004_redact_api_logs.sql"]) db.exec(readSql(`migrations/${f}`));
    expect(db.rows("SELECT COUNT(*) n FROM rate_limits")[0].n).toBe(1);
    expect(db.rows("SELECT request_body, legacy_scrubbed_at IS NOT NULL s FROM external_api_calls")[0]).toEqual({ request_body: null, s: 1 });
    expect(db.rows("SELECT name FROM pragma_table_info('runtime_sessions') WHERE name = 'refresh_token_encrypted'")).toHaveLength(1);
  });
});

describe("new log rows", () => {
  it("initial token response: tokens redacted, redaction_version set; error.code and traceId kept on failure", async () => {
    const db = migratedDb();
    const env = makeEnv(db);
    const set = tokenSet();
    fakeFetch(() => jsonRes(200, envelope(set)));
    const { ctx, flush } = makeCtx();
    expect(await exchangeLaunchCode(env, ctx, "LAUNCH-CODE-1")).not.toBeNull();
    fakeFetch(() => jsonRes(401, errorEnvelope("LAUNCH_CODE_INVALID", "trace-9")));
    expect(await exchangeLaunchCode(env, ctx, "LAUNCH-CODE-2")).toBeNull();
    await flush();
    const rows = db.rows("SELECT * FROM external_api_calls ORDER BY id");
    const all = JSON.stringify(rows);
    for (const s of [set.accessToken, set.refreshToken, "LAUNCH-CODE-1", "LAUNCH-CODE-2", env.DIDAR_CLIENT_SECRET, "server-cookie-secret"]) expect(all).not.toContain(s);
    expect(rows.every((r) => r.redaction_version === 2)).toBe(true);
    expect(JSON.parse(rows[0].response_body).data.refreshTokenExpiresAt).toBe(set.refreshTokenExpiresAt);
    expect(rows[1]).toMatchObject({ error_code: "LAUNCH_CODE_INVALID", trace_id: "trace-9" });
    expect(JSON.parse(rows[1].response_body).error.code).toBe("LAUNCH_CODE_INVALID");
  });

  it("daily cleanup keeps a live refreshable session past five minutes", async () => {
    const db = migratedDb();
    const now = Math.floor(Date.now() / 1000);
    db.exec(`INSERT INTO runtime_sessions (session_id_hash, token_hash, expires_at, access_token_expires_at, refresh_token_expires_at)
      VALUES ('live', 't1', ${now + 6 * 86400}, ${now - 3 * 86400}, ${now + 6 * 86400}),
             ('old', 't2', ${now - 2 * 86400}, ${now - 2 * 86400}, NULL)`);
    await worker.scheduled({} as ScheduledController, makeEnv(db), makeCtx().ctx);
    expect(db.rows("SELECT session_id_hash s FROM runtime_sessions")).toEqual([{ s: "live" }]);
  });
});
