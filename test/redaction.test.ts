import { describe, expect, it } from "vitest";
import { isSecretKey, redactBody, redactDeep, redactedQuery, redactHeaders, redactMessage, redactUrl, REDACTED } from "../src/util";

const RT = "rt.with.dots.short"; // dotted + short: no regex would catch it
const AT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig";

describe("redaction", () => {
  it("treats every common spelling of credential keys as secret", () => {
    for (const k of ["refreshToken", "refresh_token", "REFRESH-TOKEN", "RefreshToken", "accessToken", "access_token", "ACCESS_TOKEN",
      "clientSecret", "client_secret", "CLIENT-SECRET", "apiKey", "api_key", "apikey", "launchCode", "Authorization", "set-cookie", "id_token", "token"]) {
      expect(isSecretKey(k), k).toBe(true);
    }
    for (const k of ["code", "traceId", "refreshTokenExpiresAt", "tokenType", "expiresInSeconds", "scope", "redirect_uri"]) expect(isSecretKey(k), k).toBe(false);
  });

  it("redacts nested objects and arrays, any case, and keeps error.code + traceId", () => {
    const body = {
      succeeded: false,
      data: { accessToken: AT, REFRESH_TOKEN: RT, refreshTokenExpiresAt: "2026-11-23T00:00:00Z", list: [{ refresh_token: RT }, { Client_Secret: "s3cr3t-value" }] },
      error: { code: "REFRESH_TOKEN_INVALID", message: "bad" },
      meta: { traceId: "trace-123" },
    };
    const out = redactDeep(body) as any;
    expect(out.data.accessToken).toBe(REDACTED);
    expect(out.data.REFRESH_TOKEN).toBe(REDACTED);
    expect(out.data.list[0].refresh_token).toBe(REDACTED);
    expect(out.data.list[1].Client_Secret).toBe(REDACTED);
    expect(out.data.refreshTokenExpiresAt).toBe("2026-11-23T00:00:00Z");
    expect(out.error.code).toBe("REFRESH_TOKEN_INVALID");
    expect(out.meta.traceId).toBe("trace-123");
  });

  it("scrubs known secret values wherever they appear, even dotted and short", () => {
    const raw = JSON.stringify({ note: `token was ${RT}`, arr: [`x ${RT} y`] });
    const out = redactBody(raw, { known: [RT] })!;
    expect(out).not.toContain(RT);
    expect(redactBody(`plain text ${RT} end`, { known: [RT] })).not.toContain(RT);
    expect(redactMessage(`failed for ${encodeURIComponent("a/b+c=" + RT)}`, ["a/b+c=" + RT])).not.toContain(RT);
  });

  it("redacts form bodies (install exchange): code and client_secret", () => {
    const form = new URLSearchParams({ grant_type: "authorization_code", code: "u.b.k", redirect_uri: "https://x/didar/callback", client_id: "cid", client_secret: "csecret" });
    const out = redactBody(form.toString(), { extra: ["code"], contentType: "application/x-www-form-urlencoded" })!;
    expect(out).not.toContain("u.b.k");
    expect(out).not.toContain("csecret");
    expect(out).toContain("grant_type=authorization_code");
    expect(out).toContain("client_id=cid");
  });

  it("redacts secrets in URL query strings and text pairs", () => {
    const url = "https://app.didar.me/api/x?apikey=KEY123456&Refresh_Token=" + encodeURIComponent(RT) + "&page=2&code=c0de&launchCode=lc";
    const out = redactUrl(url, [RT]);
    for (const s of ["KEY123456", RT, encodeURIComponent(RT), "c0de", "=lc"]) expect(out).not.toContain(s);
    expect(out).toContain("page=2");
    expect(redactedQuery(new URL("https://x/?access_token=abcdef&ok=1"))).toBe(`access_token=${REDACTED}&ok=1`);
    expect(redactBody('refresh_token=abc.def&x=1 "accessToken":"zzz"')).not.toMatch(/abc\.def|zzz/);
  });

  it("redacts secret headers", () => {
    const h = new Headers({ Authorization: "Bearer " + AT, "X-Api-Key": "k", Cookie: "didar_run=abc", "Content-Type": "application/json" });
    const out = JSON.parse(redactHeaders(h));
    expect(out.authorization).toBe(REDACTED);
    expect(out["x-api-key"]).toBe(REDACTED);
    expect(out.cookie).toBe(REDACTED);
    expect(out["content-type"]).toBe("application/json");
  });
});
