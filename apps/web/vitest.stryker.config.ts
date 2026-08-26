import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Stryker runs vitest through this config so only the server unit tests execute;
// the default include pattern would also pick up the Playwright specs in tests/.
export default defineConfig({
  resolve: {
    alias: {
      "server-only": fileURLToPath(new URL("./tests/server-only.ts", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["server/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/.next/**", "**/.stryker-tmp/**"],
  },
});
