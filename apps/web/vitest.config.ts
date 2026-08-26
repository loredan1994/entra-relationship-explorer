import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "server-only": fileURLToPath(new URL("./tests/server-only.ts", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    // The standalone build copies server/ verbatim, test files included. Those copies
    // cannot resolve the workspace tsconfig, so a test run after a build would fail on
    // duplicates of tests that already passed.
    exclude: ["**/node_modules/**", "**/.next/**"],
  },
});
