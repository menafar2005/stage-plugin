// Test harness: a D1 stand-in on node:sqlite (D1 is SQLite), the real migrations, a fake marketplace and env/ctx.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { type Env, withConfig } from "../src/util";

const MIGRATIONS_DIR = join(__dirname, "..", "migrations");
export const migrationFiles = () => readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
export const readSql = (rel: string) => readFileSync(join(__dirname, "..", rel), "utf8");

const norm = (v: unknown) => (v === undefined ? null : typeof v === "boolean" ? (v ? 1 : 0) : v);

class Stmt {
  constructor(private db: DatabaseSync, private sql: string, private params: unknown[] = []) {}
  bind(...params: unknown[]) {
    return new Stmt(this.db, this.sql, params.map(norm));
  }
  private exec() {
    const st = this.db.prepare(this.sql);
    if (/\breturning\b/i.test(this.sql)) {
      const rows = st.all(...(this.params as never[]));
      return { results: rows as any[], meta: { changes: rows.length } };
    }
    if (/^\s*(select|with)\b/i.test(this.sql)) return { results: st.all(...(this.params as never[])) as any[], meta: { changes: 0 } };
    const r = st.run(...(this.params as never[]));
    return { results: [] as any[], meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }
  async run() {
    return { success: true, ...this.exec() };
  }
  async all() {
    return { success: true, ...this.exec() };
  }
  async first<T>(col?: string): Promise<T | null> {
    const row = this.exec().results[0] ?? null;
    return (row && col ? row[col] : row) as T | null;
  }
  _execSync() {
    return { success: true, ...this.exec() };
  }
}

/** D1Database-compatible fake. One shared instance = one database, whatever number of "Worker instances" use it. */
export class FakeD1 {
  readonly sqlite = new DatabaseSync(":memory:");
  prepare(sql: string) {
    return new Stmt(this.sqlite, sql);
  }
  async batch(stmts: Stmt[]) {
    this.sqlite.exec("BEGIN");
    try {
      const out = stmts.map((s) => s._execSync());
      this.sqlite.exec("COMMIT");
      return out;
    } catch (e) {
      this.sqlite.exec("ROLLBACK");
      throw e;
    }
  }
  exec(sql: string) {
    this.sqlite.exec(sql);
  }
  rows(sql: string, ...p: unknown[]): any[] {
    return this.sqlite.prepare(sql).all(...(p as never[])) as any[];
  }
  /** external_api_calls request columns (logged raw when CONFIG.LOG_RAW_REQUESTS is "true"). */
  requestLog(): string {
    return JSON.stringify(this.rows(`SELECT request_url, request_headers, request_body FROM external_api_calls`));
  }
  /** Everything that must stay free of secrets: response columns + the other log/event tables. */
  nonRequestLog(): string {
    return [
      JSON.stringify(this.rows(`SELECT response_headers, response_body, error_message FROM external_api_calls`)),
      this.dump(["extension_events", "rate_limits"]),
    ].join("\n");
  }
  /** Every text value of every row of every table, for "secret never stored" checks. */
  dump(tables = ["external_api_calls", "extension_events", "rate_limits", "runtime_sessions", "installations"]): string {
    return tables.map((t) => JSON.stringify(this.rows(`SELECT * FROM ${t}`))).join("\n");
  }
}

export function migratedDb(upTo?: string): FakeD1 {
  const db = new FakeD1();
  for (const f of migrationFiles()) {
    if (upTo && f > upTo) break;
    db.exec(readSql(`migrations/${f}`));
  }
  return db;
}

export const ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64"); // test-only key
export const CLIENT_SECRET = "test-client-secret-value-123";

/**
 * The env the Worker builds: D1 + src/config.ts + secrets (mocked in test/setup.ts). `over` only reaches code that
 * receives this env directly; worker.fetch re-applies the project files, as in production.
 */
export function makeEnv(db: FakeD1, over: Partial<Record<keyof Env, unknown>> = {}): Env {
  return { ...withConfig({ DB: db as unknown as D1Database }), ...over } as Env;
}

export function makeCtx() {
  const pending: Promise<unknown>[] = [];
  return {
    ctx: { waitUntil: (p: Promise<unknown>) => pending.push(p), passThroughOnException() {}, props: {} } as unknown as ExecutionContext,
    flush: () => Promise.all(pending),
  };
}

/** Unsigned JWT-shaped token (the plugin does not verify signatures). */
export function jwt(claims: Record<string, unknown>): string {
  const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b({ alg: "HS256", typ: "JWT" })}.${b(claims)}.c2lnbmF0dXJl`;
}

export const USER_A = "11111111-1111-4111-8111-111111111111";
export const USER_B = "22222222-2222-4222-8222-222222222222";
export const BIZ = "33333333-3333-4333-8333-333333333333";
export const RUNTIME = "44444444-4444-4444-8444-444444444444";

export interface Call { url: string; init: RequestInit; body: any }
type Responder = (call: Call) => Response | Promise<Response>;

/** Replaces global fetch; records each call with its parsed JSON/form body. */
export function fakeFetch(responder: Responder) {
  const calls: Call[] = [];
  const fn = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const raw = typeof init.body === "string" ? init.body : "";
    let body: any = raw;
    try {
      body = JSON.parse(raw);
    } catch {
      if (raw.includes("=")) body = Object.fromEntries(new URLSearchParams(raw));
    }
    const call = { url, init, body };
    calls.push(call);
    return responder(call);
  };
  globalThis.fetch = fn as typeof fetch;
  return calls;
}

export const jsonRes = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Set-Cookie": "mk=server-cookie-secret" } });

let seq = 0;
/** A fresh token set like the new marketplace returns. Refresh tokens contain dots on purpose. */
export function tokenSet(userId = USER_A, over: Record<string, unknown> = {}) {
  seq++;
  return {
    accessToken: jwt({ sub: userId, bizDomainId: BIZ, jti: `jti-${seq}`, n: seq }),
    tokenType: "Bearer",
    expiresInSeconds: 300,
    context: { target: "extension", runtimeId: RUNTIME, location: 2, entityType: "deal", entityIds: ["d1"], payload: {}, extraField: "kept" },
    refreshToken: `rt.${seq}.part.${Math.random().toString(36).slice(2)}`,
    refreshTokenExpiresAt: new Date(Date.now() + 7 * 86400 * 1000).toISOString(),
    ...over,
  };
}
export const envelope = (data: unknown) => ({ succeeded: true, data, error: null, meta: { traceId: "trace-ok" } });
export const errorEnvelope = (code: string, traceId = "trace-err") => ({ succeeded: false, data: null, error: { code, message: "x" }, meta: { traceId } });

export const req = (path: string, init: RequestInit & { cookie?: string } = {}) => {
  const headers = new Headers(init.headers);
  if (init.cookie) headers.set("Cookie", init.cookie);
  headers.set("CF-Connecting-IP", "203.0.113.9");
  return new Request(`https://plugin.test${path}`, { ...init, headers });
};

/** "didar_run=<id>" from a Set-Cookie header. */
export function runCookie(res: Response): string | null {
  const sc = res.headers.get("Set-Cookie") ?? "";
  const m = /didar_run=([^;]+)/.exec(sc);
  return m ? `didar_run=${m[1]}` : null;
}
