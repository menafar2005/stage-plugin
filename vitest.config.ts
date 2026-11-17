import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Replaces src/secrets.ts with test values, so tests run without (and never touch) the real secrets.
    setupFiles: ["test/setup.ts"],
  },
});
