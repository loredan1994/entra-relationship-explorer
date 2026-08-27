import { afterEach, describe, expect, it } from "vitest";
import { getEntraConfig } from "./config";

const original = { ...process.env };
afterEach(() => { process.env = { ...original }; });

describe("process environment binding", () => {
  it("reads live settings from the real process environment", () => {
    process.env.ENTRA_ENABLE_LIVE = "true";
    process.env.ENTRA_TENANT_ID = "11111111-1111-4111-8111-111111111111";
    process.env.ENTRA_CLIENT_ID = "22222222-2222-4222-8222-222222222222";
    process.env.ENTRA_CLIENT_SECRET = "local-test-placeholder";
    process.env.ENTRA_REDIRECT_URI = "http://127.0.0.1:3000/api/auth/callback";
    process.env.ENTRA_DATA_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
    process.env.DATABASE_URL = "postgresql://entra:test@127.0.0.1:54320/entra_explorer";
    (process.env as Record<string, string>).NODE_ENV = "development";
    const config = getEntraConfig();
    expect(config.enabled).toBe(true);
    if (config.enabled) expect(config.tenantId).toBe("11111111-1111-4111-8111-111111111111");
  });

  it("stays disabled when the environment does not opt into live access", () => {
    delete process.env.ENTRA_ENABLE_LIVE;
    expect(getEntraConfig().enabled).toBe(false);
  });

  it("re-reads the environment on each call rather than caching a stale answer", () => {
    delete process.env.ENTRA_ENABLE_LIVE;
    expect(getEntraConfig().enabled).toBe(false);
    process.env.ENTRA_ENABLE_LIVE = "true";
    // Live is now requested but incompletely configured, so it must fail loudly
    // rather than quietly returning the previously cached disabled config.
    delete process.env.ENTRA_TENANT_ID;
    expect(() => getEntraConfig()).toThrow(/ENTRA_TENANT_ID is required/);
  });
});
