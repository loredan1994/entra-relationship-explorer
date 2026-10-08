import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Failed mutation runs can leave sandbox copies; never discover those as real tests.
    include: ["src/**/*.test.ts"],
  },
});
