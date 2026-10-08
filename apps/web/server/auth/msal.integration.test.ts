import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Configuration, INetworkModule, NetworkRequestOptions } from "@azure/msal-node";
import type { LiveEntraConfig } from "../config-core";

const transport = vi.hoisted(() => ({
  requests: [] as { url: string; body: string }[],
  rejectRefresh: false,
  clients: 0,
}));

// Keep the real SDK, including PKCE, response parsing and cache logic. Replace
// only its network transport: this suite cannot contact a real identity service.
vi.mock("@azure/msal-node", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@azure/msal-node")>();
  const tenant = "11111111-1111-4111-8111-111111111111";
  const clientId = "22222222-2222-4222-8222-222222222222";
  const user = "33333333-3333-4333-8333-333333333333";
  const authority = `https://login.microsoftonline.com/${tenant}`;
  const scope = "https://graph.microsoft.com/Directory.Read.All";
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const network: INetworkModule = {
    async sendGetRequestAsync<T>(url: string) {
      const parsed = new URL(url);
      if (parsed.origin !== "https://login.microsoftonline.com") throw new Error("Unexpected authority");
      if (parsed.pathname.endsWith("/.well-known/openid-configuration")) {
        return { status: 200, headers: {}, body: {
          authorization_endpoint: `${authority}/oauth2/v2.0/authorize`,
          token_endpoint: `${authority}/oauth2/v2.0/token`,
          issuer: `${authority}/v2.0`,
          end_session_endpoint: `${authority}/oauth2/v2.0/logout`,
          jwks_uri: `${authority}/discovery/v2.0/keys`,
        } as T };
      }
      if (parsed.pathname === "/common/discovery/instance") {
        return { status: 200, headers: {}, body: {
          tenant_discovery_endpoint: `${authority}/v2.0/.well-known/openid-configuration`,
          metadata: [{ preferred_network: parsed.hostname, preferred_cache: parsed.hostname, aliases: [parsed.hostname] }],
        } as T };
      }
      throw new Error(`Unexpected metadata path: ${parsed.pathname}`);
    },
    async sendPostRequestAsync<T>(url: string, options?: NetworkRequestOptions) {
      const endpoint = new URL(url);
      if (endpoint.origin + endpoint.pathname !== `${authority}/oauth2/v2.0/token`) throw new Error("Unexpected token endpoint");
      const body = options?.body ?? "";
      transport.requests.push({ url, body });
      const refresh = new URLSearchParams(body).get("grant_type") === "refresh_token";
      if (refresh && transport.rejectRefresh) {
        return { status: 400, headers: {}, body: { error: "invalid_grant", error_description: "Synthetic revoked session" } as T };
      }
      const now = Math.floor(Date.now() / 1000);
      return { status: 200, headers: {}, body: {
        token_type: "Bearer", scope, expires_in: 3600,
        access_token: refresh ? "synthetic-refreshed-access" : "synthetic-initial-access",
        refresh_token: refresh ? "synthetic-rotated-refresh" : "synthetic-initial-refresh",
        client_info: encode({ uid: user, utid: tenant }),
        id_token: `${encode({ alg: "RS256", typ: "JWT" })}.${encode({
          aud: clientId, iss: `${authority}/v2.0`, iat: now, nbf: now, exp: now + 3600,
          oid: user, sub: user, tid: tenant, preferred_username: "reviewer@example.test",
        })}.synthetic-signature`,
      } as T };
    },
  };
  return { ...actual, ConfidentialClientApplication: class extends actual.ConfidentialClientApplication {
    constructor(config: Configuration) {
      transport.clients++;
      super({ ...config, system: { ...config.system, networkClient: network } });
    }
  } };
});

const { acquireSilent, authorizationUrl, createAuthorizationRequest, redeemAuthorizationCode } = await import("./msal");
const tenant = "11111111-1111-4111-8111-111111111111";
const config = {
  clientId: "22222222-2222-4222-8222-222222222222", clientSecret: "synthetic-client-secret",
  authority: `https://login.microsoftonline.com/${tenant}`,
  redirectUri: "http://127.0.0.1:3200/api/auth/callback",
  scopes: ["openid", "profile", "offline_access", "https://graph.microsoft.com/Directory.Read.All"],
  graphScopes: ["https://graph.microsoft.com/Directory.Read.All"],
} as LiveEntraConfig;

function expireAccessTokens(serialized: string): string {
  const cache = JSON.parse(serialized) as { AccessToken: Record<string, { expires_on: string; extended_expires_on: string }> };
  const tokens = Object.values(cache.AccessToken);
  expect(tokens).toHaveLength(1);
  for (const token of tokens) {
    expect(Number(token.expires_on)).toBeGreaterThan(1);
    token.expires_on = "1";
    token.extended_expires_on = "1";
  }
  return JSON.stringify(cache);
}

beforeEach(() => {
  transport.requests.length = 0;
  transport.rejectRefresh = false;
  transport.clients = 0;
});

describe("real MSAL protocol and cache compatibility", () => {
  it("creates a verifiable PKCE challenge and tenant-bound query callback", async () => {
    const { verifier, challenge } = await createAuthorizationRequest(config);
    expect(createHash("sha256").update(verifier).digest("base64url")).toBe(challenge);
    const url = new URL(await authorizationUrl(config, "synthetic-state", challenge));
    expect(url.origin + url.pathname).toBe(`${config.authority}/oauth2/v2.0/authorize`);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      client_id: config.clientId, redirect_uri: config.redirectUri, state: "synthetic-state",
      response_mode: "query", response_type: "code", code_challenge: challenge,
      code_challenge_method: "S256", prompt: "select_account",
    });
    expect(new Set(url.searchParams.get("scope")?.split(" "))).toEqual(new Set(config.scopes));
    expect(transport.requests).toHaveLength(0);
  });

  it("redeems the code, restores the serialized cache in a fresh client and avoids needless refresh", async () => {
    const initial = await redeemAuthorizationCode(config, "synthetic-code", "synthetic-verifier");
    expect(initial.result.account?.tenantId).toBe(tenant);
    expect(initial.result.accessToken).toBe("synthetic-initial-access");
    expect(Object.fromEntries(new URLSearchParams(transport.requests[0]!.body))).toMatchObject({
      grant_type: "authorization_code", code: "synthetic-code", code_verifier: "synthetic-verifier",
      client_id: config.clientId, redirect_uri: config.redirectUri,
    });
    const cached = await acquireSilent(config, initial.result.account!, initial.tokenCache);
    expect(cached?.result.accessToken).toBe("synthetic-initial-access");
    expect(cached?.result.fromCache).toBe(true);
    expect(transport.clients).toBe(2);
    expect(transport.requests).toHaveLength(1);
  });

  it("refreshes an expired cached token and persists refresh-token rotation across another restart", async () => {
    const initial = await redeemAuthorizationCode(config, "synthetic-code", "synthetic-verifier");
    const refreshed = await acquireSilent(config, initial.result.account!, expireAccessTokens(initial.tokenCache));
    expect(refreshed?.result.accessToken).toBe("synthetic-refreshed-access");
    expect(Object.fromEntries(new URLSearchParams(transport.requests[1]!.body))).toMatchObject({
      grant_type: "refresh_token", refresh_token: "synthetic-initial-refresh",
    });
    await acquireSilent(config, initial.result.account!, expireAccessTokens(refreshed!.tokenCache));
    expect(new URLSearchParams(transport.requests[2]!.body).get("refresh_token")).toBe("synthetic-rotated-refresh");
    expect(transport.clients).toBe(3);
  });

  it("rejects revoked refresh credentials instead of returning the expired token", async () => {
    const initial = await redeemAuthorizationCode(config, "synthetic-code", "synthetic-verifier");
    transport.rejectRefresh = true;
    await expect(acquireSilent(config, initial.result.account!, expireAccessTokens(initial.tokenCache))).rejects.toThrow("invalid_grant");
  });
});
