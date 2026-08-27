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

describe("required settings", () => {
  it.each(["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "ENTRA_REDIRECT_URI", "ENTRA_DATA_ENCRYPTION_KEY", "DATABASE_URL"])(
    "refuses to start live without %s",
    (name) => {
      expect(() => parseEntraConfig({ ...validEnvironment, [name]: undefined })).toThrow(new RegExp(`${name} is required`));
      expect(() => parseEntraConfig({ ...validEnvironment, [name]: "   " })).toThrow(new RegExp(`${name} is required`));
    },
  );

  it("stays disabled for any value other than the exact string true", () => {
    for (const value of [undefined, "", "false", "TRUE", "1", "yes"]) {
      expect(parseEntraConfig({ ...validEnvironment, ENTRA_ENABLE_LIVE: value }).enabled, String(value)).toBe(false);
    }
  });

  it("explains why live access is disabled", () => {
    const config = parseEntraConfig({ NODE_ENV: "test" });
    expect(config.enabled).toBe(false);
    if (!config.enabled) expect(config.reason).toMatch(/synthetic fixtures/);
  });

  it("rejects an identifier that merely contains a UUID", () => {
    const uuid = "11111111-1111-4111-8111-111111111111";
    for (const tenantId of [`${uuid}-extra`, `prefix-${uuid}`]) {
      expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_TENANT_ID: tenantId }), tenantId).toThrow(/concrete tenant UUID/i);
    }
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_CLIENT_ID: `${uuid}-extra` })).toThrow(/must be a UUID/i);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_CLIENT_ID: `urn:${uuid}` })).toThrow(/must be a UUID/i);
  });

  it("rejects a client id that is not a UUID", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_CLIENT_ID: "not-a-uuid" })).toThrow(/ENTRA_CLIENT_ID must be a UUID/);
  });

  it("rejects an encryption key that does not decode to 32 bytes", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_DATA_ENCRYPTION_KEY: Buffer.alloc(16, 1).toString("base64") })).toThrow(/32-byte key/);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_DATA_ENCRYPTION_KEY: Buffer.alloc(64, 1).toString("base64") })).toThrow(/32-byte key/);
  });
});

describe("redirect URI", () => {
  it("requires the callback path the app actually serves", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "http://127.0.0.1:3000/" })).toThrow(/\/api\/auth\/callback/);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "http://127.0.0.1:3000/api/auth/callback/extra" })).toThrow(/\/api\/auth\/callback/);
  });

  it("accepts HTTPS on a remote host outside production", () => {
    const config = parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "https://explorer.contoso.test/api/auth/callback" });
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.redirectUri).toBe("https://explorer.contoso.test/api/auth/callback");
  });

  it("allows plain HTTP only on a loopback address", () => {
    expect(parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "http://localhost:3000/api/auth/callback" }).enabled).toBe(true);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: "http://internal.contoso.test/api/auth/callback" })).toThrow(/HTTPS/);
  });

  it("refuses a redirect scheme that is neither HTTPS nor loopback HTTP", () => {
    for (const uri of ["ftp://localhost/api/auth/callback", "ws://127.0.0.1:3000/api/auth/callback"]) {
      expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_REDIRECT_URI: uri }), uri).toThrow(/must use HTTPS/i);
    }
  });

  it("derives the authority from the configured tenant, never a shared endpoint", () => {
    const config = parseEntraConfig(validEnvironment);
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.authority).toBe(`https://login.microsoftonline.com/${validEnvironment.ENTRA_TENANT_ID}`);
    expect(config.authority).not.toMatch(/\/(common|organizations|consumers)$/);
  });
});

describe("session lifetime", () => {
  it("defaults to eight hours when unset or blank", () => {
    for (const raw of [undefined, "", "   "]) {
      const config = parseEntraConfig({ ...validEnvironment, ENTRA_SESSION_MAX_AGE_SECONDS: raw });
      if (!config.enabled) throw new Error("Expected live config");
      expect(config.sessionMaxAgeSeconds).toBe(8 * 60 * 60);
    }
  });

  it("clamps a requested lifetime to between fifteen minutes and twenty-four hours", () => {
    const at = (raw: string) => {
      const config = parseEntraConfig({ ...validEnvironment, ENTRA_SESSION_MAX_AGE_SECONDS: raw });
      if (!config.enabled) throw new Error("Expected live config");
      return config.sessionMaxAgeSeconds;
    };
    expect(at("60")).toBe(15 * 60);
    expect(at("0")).toBe(15 * 60);
    expect(at("-3600")).toBe(15 * 60);
    expect(at("999999")).toBe(24 * 60 * 60);
    expect(at("3600")).toBe(3600);
    expect(at("900")).toBe(900);
    expect(at("86400")).toBe(86400);
  });

  it("rejects a lifetime that is not an integer number of seconds", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_SESSION_MAX_AGE_SECONDS: "eight hours" })).toThrow(/integer number of seconds/);
  });
});

describe("optional scope parsing", () => {
  it("accepts fully qualified scope URIs as well as short names", () => {
    const config = parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "https://graph.microsoft.com/Policy.Read.All" });
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.graphScopes).toContain("https://graph.microsoft.com/Policy.Read.All");
  });

  it("splits on commas and whitespace and ignores empty entries", () => {
    const config = parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: " Policy.Read.All,,  AuditLog.Read.All " });
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.graphScopes).toEqual([
      "https://graph.microsoft.com/Application.Read.All",
      "https://graph.microsoft.com/Directory.Read.All",
      "https://graph.microsoft.com/Policy.Read.All",
      "https://graph.microsoft.com/AuditLog.Read.All",
    ]);
  });

  it("requests only the core scopes when none are configured", () => {
    const config = parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "" });
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.graphScopes).toEqual([
      "https://graph.microsoft.com/Application.Read.All",
      "https://graph.microsoft.com/Directory.Read.All",
    ]);
  });

  it("rejects a write-capable scope even if it were somehow approved", () => {
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "Directory.ReadWrite.All" })).toThrow(/approved|write/i);
  });

  it("names the product's own optional-scope rule when refusing an unapproved scope", () => {
    // The message must come from the product allow-list, not from the downstream
    // read-only assertion; otherwise an unapproved read scope would slip through it.
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "Sites.Read.All" }))
      .toThrow(/Optional Graph scope is not approved by the product: https:\/\/graph\.microsoft\.com\/Sites\.Read\.All/);
    expect(() => parseEntraConfig({ ...validEnvironment, ENTRA_OPTIONAL_GRAPH_SCOPES: "https://graph.microsoft.com/Files.Read.All" }))
      .toThrow(/Optional Graph scope is not approved by the product/);
  });

  it("always includes the identity scopes needed for sign-in", () => {
    const config = parseEntraConfig(validEnvironment);
    if (!config.enabled) throw new Error("Expected live config");
    expect(config.scopes.slice(0, 3)).toEqual(["openid", "profile", "offline_access"]);
  });
});
