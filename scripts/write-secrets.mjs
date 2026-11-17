// Makes sure src/secrets.ts exists before bundling (wrangler.jsonc -> build.command), so a build never fails on it.
//
// src/secrets.ts is git-ignored (the GitHub repo is public), so Cloudflare's Git build has no such file.
//   - The file exists (your machine): it is left untouched.
//   - It is missing (Cloudflare's build, a fresh clone): it is created EMPTY. The Worker then reads its secrets from
//     the Worker's own variables (Cloudflare -> stage-plugin -> Settings -> Variables and Secrets), see withConfig.
// Never prints a value.
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const target = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "secrets.ts");

if (existsSync(target)) {
  console.log("[secrets] using the existing src/secrets.ts (Worker variables still take precedence)");
  process.exit(0);
}

writeFileSync(
  target,
  `// GENERATED EMPTY by scripts/write-secrets.mjs: secrets come from the Worker's variables in Cloudflare.\n` +
    `// Git-ignored: never commit real values here.\n` +
    `import type { Secrets } from "./config";\n\n` +
    `export const SECRETS: Secrets = {\n  DIDAR_CLIENT_ID: "",\n  DIDAR_CLIENT_SECRET: "",\n  ENCRYPTION_KEY: "",\n  DIDAR_INSTALLATION_URL: "",\n};\n`,
);
console.log("[secrets] no src/secrets.ts: created an empty one; secrets will come from the Worker's variables");
