// Template for src/secrets.ts (git-ignored). Copy this file to src/secrets.ts and fill in the values.
// Never put real values in THIS file: it is committed, and the GitHub repo is public.
//   ENCRYPTION_KEY: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
import type { Secrets } from "./config";

export const SECRETS: Secrets = {
  DIDAR_CLIENT_ID: "",
  DIDAR_CLIENT_SECRET: "",
  ENCRYPTION_KEY: "",
  DIDAR_INSTALLATION_URL: "",
};
