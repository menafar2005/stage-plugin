# stage-plugin (didar-smart-lead codebase)

Cloudflare Worker **`stage-plugin`** with its own D1 database **`stage-plugin-db`**. The code started as `didar-smart-lead`, which is still a separate Worker with its own database (`didar-smart-lead-db`). The two share nothing in Cloudflare.

A Didar marketplace plugin (Cloudflare Worker + D1) that uses **every extension type** Didar offers.
The data model is ported from the Pipedrive `pipedrive-smart-lead-db`.

Docs it follows: https://didar-developers-docs.ehsan2005-ir.workers.dev/plugin-anatomy

## Extensions and locations

Register these in Developer Hub → **App extensions**. `BASE` = **`https://stage-plugin.ehsan2005-ir.workers.dev`** (deployed).

**Locations:** the backend no longer ties an extension to specific pages. Each launch's `context.location` from the Runtime Token must be one of Didar's Location codes, otherwise the run is rejected with «محل اجرای این اکستنشن معتبر نیست.»:

| Code | Location | Code | Location |
|---|---|---|---|
| 1 | DealsList | 6 | CompanyDetail |
| 2 | DealDetail | 7 | CaseList |
| 3 | PersonList | 8 | CaseDetail |
| 4 | PersonDetail | 9 | ActivitiesList |
| 5 | CompanyList | | |

App settings is the exception: there, Didar sends `location: null`, and that's the only accepted value. The Locations column below shows what was registered originally. You can register any extension on any page Developer Hub allows.

| Extension | Locations | Address field | Value | Response |
|---|---|---|---|---|
| Links | Deals list, Deal details | URL | `BASE/didar/link` | White "Hello DIDAR!" page |
| JSON modal | Any (currently Case list, Case details) | API endpoint + JSON schema | `BASE/didar/json-modal` + [`didar/json-modal.schema.json`](didar/json-modal.schema.json) | `POST` → `{ ok, message, errors?, close? }` |
| Custom modal | Entry points: Deals list, Deal details | Iframe URL | `BASE/didar/custom-modal` | White "Hello DIDAR!" iframe |
| Custom panel | Deal details, Person details | Iframe URL | `BASE/didar/custom-panel` | White "Hello DIDAR!" iframe |
| JSON panel | Organization details | API endpoint + JSON data structure | `BASE/didar/json-panel` + [`didar/json-panel.structure.json`](didar/json-panel.structure.json) | `POST` `extension.load` → `{ ok, data: { values } }` |
| App settings | Custom UI | Iframe URL | `BASE/didar/settings` | White "Hello DIDAR!" iframe |

Basic info → **Callback URL**: `BASE/didar/callback`. Scopes: **basicinfo** only, because the plugin reads nothing beyond the BizDomain info.

Capacity check: each menu location (Deals list, Deal details) has 3 menu extensions (Link + JSON modal + Custom modal), which is Didar's maximum. Each details page holds one panel. There are only 3 panel locations, so the Custom panel gets 2 of them and the JSON panel gets 1.

Every extension needs its own **JWT secret** in Developer Hub. Generate a separate 32-byte random value for each one and keep them only on the server.

### Notes on the JSON files
Both files follow Didar's "JSON extension structure v1" (https://didar-developers-docs.ehsan2005-ir.workers.dev/json-extension-schema). They validate against the official `didar-json-extension.schema.json`, which accepts no unknown keys.

- **JSON modal** (`layout: "form"`, `loadOnOpen: false`): one section with one item of each of the 11 types. The input items are `assignedUserId` (text, required), `priority` (select), `assignmentMode` (radio), `score` (number, 0–100), `followUpDate` (date), `note` (textarea) and `updateRoundRobinPointer` (checkbox). The display items are `message`, `divider`, `value` (`status`) and `link`.
- **JSON panel** (`layout: "details"`, `loadOnOpen: true`): display items only: `message`, three `value` items (`totalAssignments`, `todayAssignments`, `lastAssignment`), `divider` and `link`.
- **Compatibility**: on 2026-11-10 the live Didar app still called the JSON endpoints with `GET ?launchCode=` and no body, which is the previous contract. Both are accepted:
  - `GET` on the modal is a submit, with the values taken from the Runtime Context's `payload`.
  - `GET` on the panel is a load.
  - Replies carry both `ok` and `succeeded`. Once Didar has switched to `POST`, the `GET` branch in `src/json-ext.ts` can be removed.
- **Endpoint contract** (per the docs): Didar sends `POST` with `{ event, runtimeId, context, values }`, and CORS allows `GET, POST, OPTIONS`.
  - On `extension.submit`, `values` is re-validated against the same file on the server (required, min/max, minLength/maxLength, options, types). Invalid values return per-field `errors` without spending the launchCode.
  - The panel answers `extension.load` with `data.values`.
  - Record ids and the tenant come only from the Runtime Context. One assumption is still unconfirmed in the docs: that Didar appends `?launchCode=` to the JSON endpoint as it does for the other extensions.

## Database (D1: `stage-plugin-db`, id `3a281721-2d40-4722-ac2a-9feca8f9f4a7`)

This repo deploys the `stage-plugin` Worker. It has its own D1 database, separate from `didar-smart-lead-db` (the `didar-smart-lead` Worker). The new database was created on 2026-11-16 with the same `0001` schema and no data.

Schema: [`migrations/0001_init.sql`](migrations/0001_init.sql), plus the additive migrations below. Never edit an applied migration. Add a new file instead.

State of the remote `stage-plugin-db`: only `0001` is applied, with `wrangler d1 execute`, the same way the original database was built. That means there is no `d1_migrations` table yet. `npm run db:migrate:remote` will therefore run `0001` again, which is safe because every statement is `IF NOT EXISTS`, and then apply `0002`–`0004`. Run it together with the first deploy of this code.

| Migration | What it does |
|---|---|
| [`0002_runtime_refresh_sessions.sql`](migrations/0002_runtime_refresh_sessions.sql) | `runtime_sessions`: encrypted access/refresh tokens, separate access-token expiry and absolute session expiry, full `context_json`, `launch_code_hash`, `status`/`status_reason`, plus `version` and `refresh_lease_*` for the single-refresh lease. Existing rows are kept, and they have no refresh token. |
| [`0003_installation_scope.sql`](migrations/0003_installation_scope.sql) | `installations`: `scope` (raw string from the token endpoint) and `installed_by_user_id` |
| [`0005_runtime_refresh_tokens.sql`](migrations/0005_runtime_refresh_tokens.sql) | New table `runtime_refresh_tokens`: one row per issued refresh token, with history (`active` → `rotated` → … , or `ended` with a reason). There is exactly one `active` token per session, enforced by a partial unique index. Moves the tokens stored by `0002` into it and clears that column. |
| [`0004_redact_api_logs.sql`](migrations/0004_redact_api_logs.sql) | `external_api_calls`: `error_code`, `trace_id`, `redaction_version`, `legacy_scrubbed_at`, plus a one-time scrub of rows written before redaction. See [Old logs](#old-logs). |

| Pipedrive table | Didar table | What changed |
|---|---|---|
| oauth_tokens | installations | Stores the `/install/auth/token` result: `api_key` AES-GCM encrypted in `api_key_encrypted`, `scope`. **This `api_key` is the key for every Didar OpenAPI call of that BizDomain.** UNIQUE `biz_domain_id`. `installation_id`, `app_public_id`, `installed_at` and `scopes` come from the old CompleteInstallation contract. They are kept on reinstall and left NULL for new installs. |
| temprory_tokens | runtime_sessions | One row per launch (server-side session). Lookup by `session_id_hash` (SHA-256 of the cookie). Holds the AES-GCM encrypted access token (`ENCRYPTION_KEY`) and the trusted Runtime Context. `expires_at` = absolute session end. |
| — | runtime_refresh_tokens | The refresh tokens, AES-GCM encrypted, linked to their session (`session_id`) with user, BizDomain and runtime. Only the `active` row keeps its ciphertext. Rotated and ended rows stay as history, with `replaced_by_id`, `rotated_at` and `status_reason`, and are deleted with their session. |
| user_capacities | user_capacities | `pipedrive_user_id` → `didar_user_id` (TEXT) |
| assignment_state | assignment_state | Keyed by `biz_domain_id` |
| assignment_logs | assignment_logs | Deal/user IDs are GUID TEXT. Adds `source_location` |
| webhook_events | extension_events | Didar has no webhooks, so every extension launch is logged here |
| external_api_calls | external_api_calls | Every outgoing call, **redacted**. Secret keys are matched in any case and separator style (`refreshToken`, `refresh_token`, `ACCESS-TOKEN`, `client_secret`, `api_key`, `launchCode`, `authorization`, `set-cookie`, `*token`, `*secret`, ...) in nested objects, arrays, form bodies, headers and URL query strings. The exact values sent and received in the call (refresh tokens may contain dots) are also scrubbed from any text, including error messages. `error.code` and `traceId` stay visible, in the body and in the `error_code` / `trace_id` columns. A single value is cut past 500,000 characters. |
| rate_limits | rate_limits | Per IP + route, 60s window. Query and headers are redacted |

Throughout, `company_id INTEGER` becomes `biz_domain_id TEXT`. The BizDomain never comes from the query string. It comes from the Runtime Token's `biz_domain_id` claim, which real tokens carry along with `user_id`, `installation_id`, `runtime_id` and `scope`. That BizDomain selects the installation whose `api_key` is used for the Didar OpenAPI. There is no global `DIDAR_API_KEY` any more, and the old OpenAPI-based BizDomain lookup, which needed one, is gone. The plugin calls no marketplace data-proxy endpoint (`marketplace.didar.me/api/v1/proxy/...`). Only the install token, Runtime Token and Runtime refresh calls go to the marketplace. The migration also adds the indexes the original database was missing. A daily cron deletes expired sessions, old rate-limit windows, and API logs older than 30 days.

What gets written where:
- Every launch → `runtime_sessions` + `extension_events` + `external_api_calls` + `rate_limits`
- JSON modal submit → one row in `extension_events` (`event_action = 'json_modal'`) with the location, entity type, entity ids and the form values in `payload`. Nothing else happens: there's no location or entity-type restriction, no tenant requirement and no assignment logic. Values are still re-validated against the schema, and invalid ones return per-field `errors`.
- Install callback → `installations`
- JSON panel → reads the stats back
- Runtime refresh → updates the same `runtime_sessions` row (one atomic UPDATE) + `external_api_calls`

## Installation flow

1. `/didar/install` redirects to `DIDAR_INSTALLATION_URL` with a one-time `state` (cookie, 10 minutes).
2. Didar redirects to `/didar/callback?code=...&state=...`. The state is checked when the flow started at `/didar/install`.
3. These are checked before the one-time code is spent:
   - `DIDAR_REDIRECT_URI` is set and its path is this callback path.
   - The code has the shape `{UserId-GUID}.{BizDomainId-GUID}.{UniqueKey}`.
4. The backend sends the **full, unchanged** code to `POST {MARKETPLACE_URL}/install/auth/token` as `application/x-www-form-urlencoded`, built with `URLSearchParams`: `grant_type=authorization_code`, `code`, `redirect_uri` (= `DIDAR_REDIRECT_URI`), `client_id`, `client_secret`. The JWT path `/api/v1/auth/token` is not used.
5. The success reply has no envelope: `{"api_key":"...","scope":"..."}`. Only a 2xx with a non-empty string `api_key` and a string `scope` counts as success. Only then are the BizDomain (2nd part of the code) and the user (1st part) used to upsert `installations`, with `api_key` AES-GCM encrypted.
6. Errors are never retried, because the code is one-time. They produce no success message and no install record:

   | Error | Response |
   |---|---|
   | Invalid client | 502 |
   | Invalid code | 400 |
   | Expired code | 400 |
   | Used code | 409 |
   | DidarService / network error | 502 |

   The official docs don't list the error codes of this endpoint yet, so `classifyInstallError` in `src/didar.ts` accepts both shapes: the marketplace envelope (`error.code`, e.g. `INVALID_CLIENT_CREDENTIALS`, `*_EXPIRED`, `*_ALREADY_USED`, `DIDAR_SERVICE*`) and OAuth-style (`error: "invalid_client" | "invalid_grant"`). When no code matches, it falls back to the HTTP status (401/400/410/409/5xx).

   The install code, `client_secret` and `api_key` never reach the logs.

## Runtime sessions (refresh without a new launch)

- **Start**: an extension launch exchanges its one-time `launchCode` at `/api/v1/runtime/token`, exactly once.
  - The response's `accessToken` (in `runtime_sessions`) and `refreshToken` (in `runtime_refresh_tokens`) are stored encrypted, server-side only. Both are written in one atomic batch.
  - The access-token expiry comes from `expiresInSeconds`. The absolute session end comes from `refreshTokenExpiresAt`. They are separate columns.
  - The browser gets only the `didar_run` cookie: a random id (`HttpOnly; Secure; SameSite=None; Partitioned` for Didar's iframe).
  - The cookie's `Max-Age` is the session end, not the 5-minute JWT.
  - No token goes into HTML, JavaScript, localStorage, sessionStorage or a URL.
- **Resume**: requests that use the existing session:
  - `GET /didar/session`: JSON with the trusted context and expiries, never a token.
  - A custom modal/panel/settings iframe reload with the *same* (already spent) `launchCode`, or with no `launchCode`.

  All of them go through `getValidRuntimeSession` (`src/session.ts`), which never exchanges a launchCode. A resumed session must belong to the same extension kind and target.
- **Refresh**: when the JWT has less than 30s left, a single `POST /api/v1/runtime/refresh` is sent with the latest refresh token. Everything is written in one atomic D1 batch, gated by the session's compare-and-swap: the session's new access token, the new access expiry, `version + 1` and a cleared lease; the old refresh-token row marked `rotated`, with its ciphertext wiped; and the new row inserted as `active` and linked from the old one. The absolute end never moves later: `min(stored, server)`.
- **Concurrency** (works across isolates, no in-memory lock):
  - A request first takes a D1 lease by compare-and-swap: `UPDATE ... WHERE version = ? AND lease free`.
  - Requests that lose the CAS use the current JWT while it is still valid. Otherwise they poll D1 for a bounded time (≈4s) for the stored result, then answer 503 "busy". They never refresh themselves.
  - The lease (30s) is longer than the marketplace timeout (10s).
- **Errors**: read from `error.code`, never retried.

  | Code | Result |
  |---|---|
  | `REFRESH_TOKEN_INVALID` | First re-reads D1 for a concurrent replacement. If there is none, a new launch is required. |
  | `REFRESH_TOKEN_EXPIRED` | Session expired. |
  | `INSTALLATION_ACCESS_DENIED` | Session revoked. Tokens are wiped. |
  | `RUNTIME_UNAVAILABLE`, `EXTENSION_RUNTIME_UNAVAILABLE`, `SETTINGS_PAGE_RUNTIME_UNAVAILABLE` | Session unavailable. |
  | `INVALID_CLIENT_CREDENTIALS` | Configuration error (503). The session is kept, with a 60s cool-down and no retry loop. |
  | `DIDAR_API_KEY_NOT_CONFIGURED` | Installation configuration error (409). Not treated as JWT expiry. Same cool-down. |
  | Timeout, connection loss, 5xx without a code, or a 2xx without a replacement token | **Outcome unknown.** The old token is never re-sent, and the session needs a new launch. |
- **Old sessions** (created before migration 0002) have no refresh token, so they get "open the extension again from Didar".
- **Cleanup**: the daily cron deletes sessions one day after `expires_at` (the absolute end for refreshable sessions), and ended sessions (which hold no tokens) one day after their last use. A live session is not deleted after five minutes.

**Limits of session recovery**
- One `didar_run` cookie per browser partition. Opening a second iframe extension replaces the first one's session, and a reload of the first one then needs a new launch from Didar.
- JSON modal/panel calls come from Didar's frontend with their own `launchCode` each time, so they don't use the cookie session.
- Partitioned third-party cookies can be blocked by the browser. The user then has to launch again.
- A session can't outlive `refreshTokenExpiresAt` (default 7 days).

**Didar OpenAPI uses the installation's `api_key`, not the Runtime JWT.**
- `didarOpenApi(env, ctx, path, payload, bizDomainId)` reads `installations.api_key_encrypted` for that BizDomain. The installation must be `active`; otherwise nothing is sent (`INSTALLATION_NOT_FOUND` or `INSTALLATION_INACTIVE`). It calls `${DIDAR_APP_URL}<path>?apikey=<that key>` (`DIDAR_APP_URL` is in `src/config.ts`; staging: `https://stapp.didar.me`). The key is masked in the logs, and the JWT is never sent there.
- For work done on behalf of a user, use `sessionOpenApi` (`src/session.ts`). It first validates and, if needed, refreshes the Runtime session, then uses **that session's** BizDomain key. When the session is invalid, revoked or its refresh failed, nothing is sent, and there is no fallback key.
- Marketplace permissions (user access, scopes) are still **not** enforced by the OpenAPI itself; they are only checked through the Runtime session. These endpoints were intentionally not moved to the marketplace proxy in this change.

## Old logs

Up to commit `0f335a2`, `external_api_calls` was written **unredacted**. It may hold the client secret, launchCodes, Runtime Tokens and `?apikey=`. Fixing the code does not clean those rows.

- **`stage-plugin-db`** (this Worker, since 2026-11-16): the version deployed now is still `0f335a2`, so it keeps writing unredacted rows until this code is deployed. Clean it with the steps below.
- **`didar-smart-lead-db`**: `stage-plugin` used this shared database before 2026-11-16, so its earlier rows are still there. That database now belongs only to the `didar-smart-lead` Worker. Cleaning it is a separate decision for that Worker. The same scripts work there with the database name changed.

To clean them:

1. Migration `0004` scrubs rows with `redaction_version IS NULL`. It keeps service, path, status, timings, `error_name`, `error_code` and `trace_id`. It removes query strings, headers, bodies and error messages, and never prints a value.
2. After deploying, run the same scrub again. It is re-runnable, and the previous Worker version may have written rows in between:

   ```bash
   npx wrangler d1 execute stage-plugin-db --remote --file scripts/scrub-legacy-api-logs.sql
   ```
3. Check with counts only:

   ```bash
   npx wrangler d1 execute stage-plugin-db --remote --file scripts/check-legacy-secrets.sql
   ```

Not covered:
- D1 Time Travel keeps earlier database states for its retention window.
- Workers Logs (observability) may still hold earlier `console` output.

Rotate `DIDAR_CLIENT_SECRET` and the OpenAPI key used back then if those rows may have been seen.

## Tests

```bash
npm test
```

Vitest tests run against an in-memory SQLite that applies the real migrations (D1 is SQLite), with a fake marketplace. They cover:
- Redaction: nested objects, arrays, case variants, URLs and form bodies; `error.code` and `traceId` kept.
- Encrypted tokens, and no tokens in the browser response or the logs.
- Refresh near expiry and reuse of the rotated token. Fixed absolute expiry.
- Exactly one refresh when two separate module instances (two "Workers") race.
- Resume by cookie without re-exchanging the launchCode. Per-user isolation.
- All refresh error codes, and timeout or ambiguous outcomes.
- The new install contract and its errors.
- Migrations applied on a 0001 database with existing data, and a re-runnable scrub.

`npm run typecheck` type-checks `src`.

## Run / deploy

```bash
npm install
```

```bash
cp src/secrets.example.ts src/secrets.ts
```

Fill in `src/secrets.ts`, then:

```bash
npm run dev
```

**Where settings live**

| Setting | Where | In git? |
|---|---|---|
| `DIDAR_ORIGIN`, `DIDAR_APP_URL`, `MARKETPLACE_URL`, `RATE_LIMIT_PER_MINUTE`, `DIDAR_REDIRECT_URI` | [`src/config.ts`](src/config.ts). A Cloudflare variable with the same name is ignored. | Yes |
| `DIDAR_CLIENT_ID`, `DIDAR_CLIENT_SECRET`, `ENCRYPTION_KEY`, `DIDAR_INSTALLATION_URL` | The Worker's own settings: Cloudflare → `stage-plugin` → Settings → **Variables and Secrets** | No |
| Same four, local fallback | `src/secrets.ts`, used only where the Worker variable is not set (local `wrangler dev`/deploy) | **No** (git-ignored; the GitHub repo is public) |

- **Precedence:** `withConfig` (`src/util.ts`) uses the Worker's variable first and falls back to `src/secrets.ts`.
- **Keeping the variables:** `wrangler.jsonc` has `"keep_vars": true`, so deploys keep the variables set in the dashboard. Without it, a deploy would delete them, because the file declares no `vars` of its own.
- **Use type Secret** for `DIDAR_CLIENT_SECRET` and `ENCRYPTION_KEY` in the dashboard. Plain "Variable" shows the value to anyone who opens the settings.
- **Cloudflare's Git build** clones the repo, which has no `src/secrets.ts`. `wrangler.jsonc` → `build.command` runs [`scripts/write-secrets.mjs`](scripts/write-secrets.mjs), which creates an **empty** one so the build never fails on it. The real values then come from the Worker's variables. Nothing needs to be set under Settings → Build.
- **Locally**, the script never touches an existing `src/secrets.ts`.
- **`ENCRYPTION_KEY`** must stay the same once data is encrypted with it, because changing it makes stored installations and live sessions unreadable.
- **Tests:** they never read `src/secrets.ts`. `test/setup.ts` replaces it with test values.
- **Values:**
  - There is no OpenAPI key setting. Each BizDomain's key is the `api_key` saved at install, in `installations.api_key_encrypted`.
  - `DIDAR_REDIRECT_URI` must be exactly the Callback URL registered in Developer Hub (`BASE/didar/callback`). It is sent as `redirect_uri` to `/install/auth/token`, and if its path is not `/didar/callback`, the callback refuses before spending the code.
  - `ENCRYPTION_KEY` encrypts the installation `api_key` and the Runtime tokens. Changing it makes stored installations and live sessions unreadable.

Deploy: `wrangler.jsonc` targets the **`stage-plugin`** Worker and `stage-plugin-db`, so a deploy from this repo can't overwrite `didar-smart-lead`.

**Migrations are not applied by the Git build.** Apply new migrations to the remote database *before* pushing code that needs them. The code writes the new tables and columns:

```bash
npm run db:migrate:remote
```

`/didar/install` redirects the admin to the install link with a one-time `state`. The callback verifies that state when it exists.
