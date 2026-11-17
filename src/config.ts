// App configuration, kept in the project (not in the Worker's Cloudflare variables).
// These values were the Worker's "vars" until 2026-11-17. They are bundled into the code, so changing one needs a
// deploy. Values set in Cloudflare under the same names are IGNORED: this file always wins (see withConfig in util.ts).
// Only non-secret values belong here. The repo is on GitHub: never put a client secret, API key or encryption key here.
// Didar STAGING (the stage-plugin app is registered in the staging Developer Hub, stapp.didar.me).
// Production would be app.didar.me / marketplace.didar.me; client credentials of one environment don't work on the other.
export const CONFIG = {
  /** Didar app origin: allowed to frame the iframe pages (CSP frame-ancestors) and to call the JSON endpoints (CORS). */
  DIDAR_ORIGIN: "https://stapp.didar.me",
  /** Didar OpenAPI base URL (POST <path>?apikey=...). */
  DIDAR_APP_URL: "https://stapp.didar.me",
  /** Marketplace base URL: install token, Runtime Token and Runtime refresh. */
  MARKETPLACE_URL: "https://stmarketplace.didar.me",
  /** Requests per minute per IP and route (rate_limits table). */
  RATE_LIMIT_PER_MINUTE: "120",
  /** Exactly the Callback URL registered in Developer Hub; sent as redirect_uri to /install/auth/token. */
  DIDAR_REDIRECT_URI: "https://stage-plugin.ehsan2005-ir.workers.dev/didar/callback",
} as const;

export type AppConfig = { readonly [K in keyof typeof CONFIG]: string };

/**
 * Secret values. They live in src/secrets.ts, which is git-ignored (the GitHub repo is public) and bundled into the
 * Worker on deploy. Copy src/secrets.example.ts to src/secrets.ts and fill it in. An empty string means "not set".
 */
export interface Secrets {
  /** Developer Hub -> OAuth & access scopes. */
  DIDAR_CLIENT_ID: string;
  DIDAR_CLIENT_SECRET: string;
  /** 32 random bytes, base64. Encrypts the installation api_key and the Runtime tokens (AES-GCM). Never change it once used. */
  ENCRYPTION_KEY: string;
  /** Developer Hub -> Share install link (used by /didar/install to add a one-time state). */
  DIDAR_INSTALLATION_URL: string;
  // No OpenAPI key here: each BizDomain's api_key comes from its installation row (installations.api_key_encrypted).
}
