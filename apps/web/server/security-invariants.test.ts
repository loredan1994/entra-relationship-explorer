import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function source(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");
}

describe("API and log redaction invariants", () => {
  it("does not serialize session tokens or MSAL cache from the session API", () => {
    const route = source("../app/api/auth/session/route.ts");
    expect(route).not.toMatch(/accessToken|tokenCache|clientSecret|encryptionKey/);
  });

  it("does not echo caught worker or migration exceptions", () => {
    for (const file of ["../worker.ts", "../migrate.ts"]) {
      const contents = source(file);
      expect(contents).not.toMatch(/console\.error\s*\(\s*(?:error|caught)(?:\.message)?/);
      expect(contents).not.toMatch(/JSON\.stringify\s*\(\s*(?:error|caught)/);
    }
  });
});
