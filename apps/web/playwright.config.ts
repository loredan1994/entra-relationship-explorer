import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:3102",
    trace: "retain-on-first-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-chromium", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: "pnpm start --hostname 127.0.0.1 --port 3102",
    url: "http://127.0.0.1:3102/overview",
    // Always test the build produced by verification, never an older preview.
    // Keep this port separate from preview (3100) and persistence tests (3101).
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
