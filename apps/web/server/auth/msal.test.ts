import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountInfo } from "@azure/msal-node";
import type { LiveEntraConfig } from "../config-core";

const TENANT = "11111111-1111-4111-8111-111111111111";

const getAuthCodeUrl = vi.fn();
const acquireTokenByCode = vi.fn();
const acquireTokenSilent = vi.fn();
const serialize = vi.fn();
const deserialize = vi.fn();
const generatePkceCodes = vi.fn();
const constructed: unknown[] = [];

vi.mock("@azure/msal-node", () => ({
  ConfidentialClientApplication: class {
    constructor(options: unknown) { constructed.push(options); }
    getAuthCodeUrl = getAuthCodeUrl;
    acquireTokenByCode = acquireTokenByCode;
    acquireTokenSilent = acquireTokenSilent;
    getTokenCache = () => ({ serialize, deserialize });
  },
  CryptoProvider: class { generatePkceCodes = generatePkceCodes; },
  LogLevel: { Error: 1 },
  ResponseMode: { QUERY: "query" },
}));

const { acquireSilent, authorizationUrl, createAuthorizationRequest, getMsalClient, redeemAuthorizationCode } =
  await import("./msal");

const config = {
  clientId: "22222222-2222-4222-8222-222222222222",
  clientSecret: "secret-value",
  authority: `https://login.microsoftonline.com/${TENANT}`,
  redirectUri: "https://explorer.contoso.test/api/auth/callback",
  scopes: ["openid", "https://graph.microsoft.com/Directory.Read.All"],
  graphScopes: ["https://graph.microsoft.com/Directory.Read.All"],
} as unknown as LiveEntraConfig;

const account = { tenantId: TENANT, homeAccountId: "home-1" } as unknown as AccountInfo;

beforeEach(() => {
  vi.clearAllMocks();
  constructed.length = 0;
  serialize.mockReturnValue("serialized-cache");
});

describe("client construction", () => {
  it("builds the client against the tenant-specific authority", () => {
    getMsalClient(config);
    expect(constructed).toHaveLength(1);
    expect(constructed[0]).toMatchObject({
      auth: { clientId: config.clientId, authority: config.authority, clientSecret: "secret-value" },
    });
  });

  it("disables personally identifiable logging and swallows the logger callback", () => {
    getMsalClient(config);
    const options = constructed[0] as { system: { loggerOptions: { piiLoggingEnabled: boolean; loggerCallback: () => unknown } } };
    expect(options.system.loggerOptions.piiLoggingEnabled).toBe(false);
    expect(options.system.loggerOptions.loggerCallback()).toBeUndefined();
  });
});

describe("PKCE", () => {
  it("returns a verifier and challenge pair from the crypto provider", async () => {
    generatePkceCodes.mockResolvedValue({ verifier: "v-1", challenge: "c-1" });
    expect(await createAuthorizationRequest(config)).toEqual({ verifier: "v-1", challenge: "c-1" });
  });
});

describe("authorization URL", () => {
  it("requests the configured scopes with the S256 challenge and query response mode", async () => {
    getAuthCodeUrl.mockResolvedValue("https://login.microsoftonline.com/authorize?x=1");
    expect(await authorizationUrl(config, "state-1", "challenge-1")).toBe("https://login.microsoftonline.com/authorize?x=1");
    expect(getAuthCodeUrl).toHaveBeenCalledWith({
      scopes: config.scopes,
      redirectUri: config.redirectUri,
      state: "state-1",
      codeChallenge: "challenge-1",
      codeChallengeMethod: "S256",
      responseMode: "query",
      prompt: "select_account",
    });
  });

  it("always prompts for account selection rather than silently reusing one", async () => {
    getAuthCodeUrl.mockResolvedValue("https://example.test");
    await authorizationUrl(config, "s", "c");
    expect(getAuthCodeUrl.mock.calls[0]![0]).toMatchObject({ prompt: "select_account" });
  });
});

describe("code redemption", () => {
  it("redeems the code with the matching verifier and returns the serialized cache", async () => {
    acquireTokenByCode.mockResolvedValue({ accessToken: "graph-token", account });
    const redeemed = await redeemAuthorizationCode(config, "auth-code", "verifier-1");
    expect(acquireTokenByCode).toHaveBeenCalledWith({
      code: "auth-code", scopes: config.scopes, redirectUri: config.redirectUri, codeVerifier: "verifier-1",
    });
    expect(redeemed).toEqual({ result: { accessToken: "graph-token", account }, tokenCache: "serialized-cache" });
  });

  it("propagates a redemption failure rather than returning a partial result", async () => {
    acquireTokenByCode.mockRejectedValue(new Error("invalid_grant"));
    await expect(redeemAuthorizationCode(config, "bad-code", "v")).rejects.toThrow("invalid_grant");
  });
});

describe("silent refresh", () => {
  it("restores the stored cache and asks only for the Graph scopes", async () => {
    acquireTokenSilent.mockResolvedValue({ accessToken: "fresh-token" });
    const refreshed = await acquireSilent(config, account, "stored-cache");
    expect(deserialize).toHaveBeenCalledWith("stored-cache");
    expect(acquireTokenSilent).toHaveBeenCalledWith({ account, scopes: config.graphScopes });
    expect(refreshed).toEqual({ result: { accessToken: "fresh-token" }, tokenCache: "serialized-cache" });
  });

  it("returns nothing when the identity platform yields no result", async () => {
    acquireTokenSilent.mockResolvedValue(null);
    expect(await acquireSilent(config, account, "stored-cache")).toBeNull();
  });

  it("returns the cache as it stands after the refresh, not the cache it was given", async () => {
    acquireTokenSilent.mockResolvedValue({ accessToken: "fresh-token" });
    serialize.mockReturnValue("rotated-cache");
    expect((await acquireSilent(config, account, "stored-cache"))?.tokenCache).toBe("rotated-cache");
  });
});
