import { describe, expect, it } from "vitest";
import { parseEntraConfig } from "./config-core";

const validEnvironment: NodeJS.ProcessEnv = {
  NODE_ENV: "development",
  ENTRA_ENABLE_LIVE: "true",
  ENTRA_TENANT_ID: "11111111-1111-4111-8111-111111111111",
  ENTRA_CLIENT_ID: "22222222-2222-4222-8222-222222222222",
  ENTRA_CLIENT_SECRET: "local-test-placeholder",
  ENTRA_REDIRECT_URI: "http://127.0.0.1:3000/api/auth/callback",
  ENTRA_DATA_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
  DATABASE_URL: "postgresql://entra:test@127.0.0.1:54320/entra_explorer",
};

describe("Phase 1 configuration boundary", () => {
  it("stays disabled unless explicitly enabled", () => {
    expect(parseEntraConfig({ NODE_ENV: "test" }).enabled).toBe(false);
  });

  it("uses a concrete tenant and only read-only scopes", () => {
    const config = parseEntraConfig(validEnvironment);
    expect(config).toMatchObject({
      enabled: true,
      tenantId: validEnvironment.ENTRA_TENANT_ID,
      graphScopes: [
        "https://graph.microsoft.com/Application.Read.All",
        "https://graph.microsoft.com/Directory.Read.All",
      ],
    });
    if (config.enabled) expect(config.scopes.join(" ")).not.toMatch(/readwrite|\.write\b/i);
  });

  it("rejects broad tenant authorities, insecure remote redirects, and production secrets", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_TENANT_ID: "organizations" })).toThrow(/concrete tenant/i);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "http://example.com/api/auth/callback" })).toThrow(/HTTPS/i);
    expect(() => parseEntraConfig({ ...validEnvironment, NODE_ENV: "production" })).toThrow(/must not use a client secret/i);
  });

  it("allows production-style local containers only with an explicit loopback exception", () => {
    const config = parseEntraConfig({ ...validEnvironment, NODE_ENV: "production", ENTRA_ALLOW_LOCAL_CLIENT_SECRET: "true" });
    expect(config.enabled).toBe(true);
    expect(() => parseEntraConfig({ ...validEnvironment, NODE_ENV: "production", ENTRA_ALLOW_LOCAL_CLIENT_SECRET: "true", ENTRA_REDIRECT_URI: "https://example.com/api/auth/callback" })).toThrow(/must not use a client secret/i);
  });

  it("adds only explicitly requested optional read-only evidence scopes", () => {
    const config = parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "RoleManagement.Read.Directory Policy.Read.All AuditLog.Read.All" });
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.graphScopes).toContain("https://graph.microsoft.com/RoleManagement.Read.Directory");
    expect(config.graphScopes).toContain("https://graph.microsoft.com/Policy.Read.All");
    expect(config.graphScopes).toContain("https://graph.microsoft.com/AuditLog.Read.All");
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "Sites.Read.All" })).toThrow(/optional|approved/i);
  });
});
