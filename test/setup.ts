// Tests never see the real src/secrets.ts: every test file gets these test-only values instead.
import { vi } from "vitest";

vi.mock("../src/secrets", () => ({
  SECRETS: {
    DIDAR_CLIENT_ID: "test-client-id",
    DIDAR_CLIENT_SECRET: "test-client-secret-value-123",
    ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
    DIDAR_INSTALLATION_URL: "https://marketplace.didar.test/install?app=test",
  },
}));
