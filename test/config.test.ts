import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CONFIG } from "../src/config";
import worker from "../src/index";
import { fakeFetch, jsonRes, makeCtx, makeEnv, migratedDb, req } from "./helpers";

describe("project config (no Cloudflare variables)", () => {
  it("holds the values that used to be Worker vars", () => {
    expect(CONFIG).toEqual({
      DIDAR_ORIGIN: "https://app.didar.me",
      DIDAR_APP_URL: "https://app.didar.me",
      MARKETPLACE_URL: "https://marketplace.didar.me",
      RATE_LIMIT_PER_MINUTE: "120",
      DIDAR_REDIRECT_URI: "https://stage-plugin.ehsan2005-ir.workers.dev/didar/callback",
    });
  });

  it("secrets come from src/secrets.ts; a Cloudflare secret with the same name is ignored", async () => {
    const db = migratedDb();
    const calls = fakeFetch(() => jsonRes(401, { succeeded: false, error: { code: "INVALID_CLIENT_CREDENTIALS" } }));
    const bindings = { DB: makeEnv(db).DB, DIDAR_CLIENT_SECRET: "cloudflare-secret", DIDAR_CLIENT_ID: "cloudflare-id" };
    await worker.fetch(req("/didar/link?launchCode=abcdef"), bindings, makeCtx().ctx);
    expect(calls[0].body).toMatchObject({ clientId: "test-client-id", clientSecret: "test-client-secret-value-123" });
  });

  it("src/secrets.ts is git-ignored and the committed example holds no values", () => {
    const root = join(__dirname, "..");
    expect(readFileSync(join(root, ".gitignore"), "utf8")).toMatch(/^src\/secrets\.ts$/m);
    const example = readFileSync(join(root, "src", "secrets.example.ts"), "utf8");
    for (const m of example.matchAll(/^\s+([A-Z_]+):\s*"([^"]*)"/gm)) expect(m[2], m[1]).toBe("");
  });

  it("wrangler.jsonc declares no vars, so a deploy leaves none on the Worker", () => {
    const cfg = readFileSync(join(__dirname, "..", "wrangler.jsonc"), "utf8").replace(/^\s*\/\/.*$/gm, "");
    expect(cfg).not.toMatch(/"vars"\s*:/);
  });

  it("a same-named variable set in Cloudflare is ignored: the Worker uses src/config.ts", async () => {
    const db = migratedDb();
    const calls = fakeFetch(() => jsonRes(401, { succeeded: false, error: { code: "LAUNCH_CODE_INVALID" } }));
    const bindings = { ...makeEnv(db), MARKETPLACE_URL: "https://evil.example", DIDAR_ORIGIN: "https://evil.example" };
    const { ctx } = makeCtx();
    await worker.fetch(req("/didar/link?launchCode=abc"), bindings, ctx);
    expect(calls[0].url).toBe(`${CONFIG.MARKETPLACE_URL}/api/v1/runtime/token`);
    const opt = await worker.fetch(req("/didar/json-panel", { method: "OPTIONS" }), bindings, ctx);
    expect(opt.headers.get("Access-Control-Allow-Origin")).toBe(CONFIG.DIDAR_ORIGIN);
  });
});
