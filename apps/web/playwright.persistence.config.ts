import { defineConfig, devices } from "@playwright/test";

if (!process.env.TEST_DATABASE_URL) throw new Error("An isolated TEST_DATABASE_URL is required.");
const database = new URL(process.env.TEST_DATABASE_URL);
if (!["127.0.0.1", "localhost"].includes(database.hostname) || database.pathname !== "/entra_review_test") throw new Error("Persistence tests require the isolated loopback entra_review_test database.");

export default defineConfig({
  testDir: "./persistence-tests", workers: 1, retries: 0,
  use: { baseURL: "http://127.0.0.1:3101", ...devices["Desktop Chrome"] },
  webServer: {
    command: "pnpm start --hostname 127.0.0.1 --port 3101",
    url: "http://127.0.0.1:3101/overview", reuseExistingServer: false, timeout: 30000,
    env: {
      ENTRA_ENABLE_LIVE: "true", ENTRA_ALLOW_LOCAL_CLIENT_SECRET: "true",
      ENTRA_TENANT_ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      ENTRA_CLIENT_ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ENTRA_CLIENT_SECRET: "synthetic-test-only-never-used-for-authentication",
      ENTRA_DATA_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      ENTRA_REDIRECT_URI: "http://127.0.0.1:3101/api/auth/callback",
      ENTRA_OPTIONAL_GRAPH_SCOPES: "", ENTRA_COLLECT_DIRECTORY_AUDITS: "false",
      DATABASE_URL: process.env.TEST_DATABASE_URL,
    },
  },
});
