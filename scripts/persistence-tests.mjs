import { spawnSync } from "node:child_process";

if (!process.env.TEST_DATABASE_URL) {
  console.log("Skipped persistence browser test: set TEST_DATABASE_URL to an isolated loopback entra_review_test database.");
} else {
  const result = spawnSync("pnpm", ["--filter", "@entra-explorer/web", "exec", "playwright", "test", "--config", "playwright.persistence.config.ts"], { stdio: "inherit", env: process.env });
  process.exitCode = result.status ?? 1;
}
