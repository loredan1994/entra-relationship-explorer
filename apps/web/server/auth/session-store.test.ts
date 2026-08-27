import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountInfo, AuthenticationResult } from "@azure/msal-node";
import type { LiveEntraConfig } from "../config-core";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";

const createSession = vi.fn();
const getSession = vi.fn();
const updateSession = vi.fn();
const deleteSession = vi.fn();
const acquireSilent = vi.fn();

vi.mock("../backend", () => ({ getBackend: async () => ({ createSession, getSession, updateSession, deleteSession }) }));
vi.mock("./msal", () => ({ acquireSilent: (...args: unknown[]) => acquireSilent(...args) }));

const { AUTH_FLOW_COOKIE, createServerSession, deleteServerSession, getServerSession, getSessionAccessToken, SESSION_COOKIE } =
  await import("./session-store");

const config = { tenantId: TENANT, sessionMaxAgeSeconds: 8 * 60 * 60, graphScopes: ["https://graph.microsoft.com/Directory.Read.All"] } as unknown as LiveEntraConfig;

const account = { tenantId: TENANT, homeAccountId: "home-1", username: "person@contoso.test" } as unknown as AccountInfo;

function authResult(overrides: Partial<AuthenticationResult> = {}): AuthenticationResult {
  return { account, accessToken: "graph-token", expiresOn: new Date("2026-08-26T11:00:00.000Z"), ...overrides } as AuthenticationResult;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("session cookie name", () => {
  it("is a stable, non-generic name", () => {
    expect(SESSION_COOKIE).toBe("entra_explorer_session");
  });

  it("keeps the sign-in flow on its own cookie, distinct from the session", () => {
    expect(AUTH_FLOW_COOKIE).toBe("entra_explorer_auth_flow");
    expect(AUTH_FLOW_COOKIE).not.toBe(SESSION_COOKIE);
  });
});

describe("creating a session", () => {
  it("refuses an account from a tenant other than the configured one", async () => {
    const foreign = { ...account, tenantId: OTHER_TENANT } as AccountInfo;
    await expect(createServerSession(config, authResult({ account: foreign }), "cache")).rejects.toThrow(/does not belong to the configured tenant/);
    expect(createSession).not.toHaveBeenCalled();
  });

  it("refuses a result that carries no account at all", async () => {
    await expect(createServerSession(config, authResult({ account: null }), "cache")).rejects.toThrow(/does not belong to the configured tenant/);
  });

  it("refuses a result with no Graph access token", async () => {
    await expect(createServerSession(config, authResult({ accessToken: "" }), "cache")).rejects.toThrow(/did not return a Graph access token/);
    expect(createSession).not.toHaveBeenCalled();
  });

  it("stores a session bound to the account tenant with a fresh identifier", async () => {
    const session = await createServerSession(config, authResult(), "serialized-cache");
    expect(session.tenantId).toBe(TENANT);
    expect(session.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(session.accessToken).toBe("graph-token");
    expect(session.tokenCache).toBe("serialized-cache");
    expect(createSession).toHaveBeenCalledWith(session);
  });

  it("takes the token expiry from the identity result", async () => {
    const session = await createServerSession(config, authResult(), "cache");
    expect(session.accessTokenExpiresAt).toBe(Date.parse("2026-08-26T11:00:00.000Z"));
  });

  it("falls back to a conservative expiry when the result omits one", async () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    const session = await createServerSession(config, authResult({ expiresOn: null }), "cache");
    expect(session.accessTokenExpiresAt).toBe(Date.parse("2026-08-26T10:55:00.000Z"));
  });

  it("expires the app session after the configured maximum age", async () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    const session = await createServerSession(config, authResult(), "cache");
    expect(session.sessionExpiresAt).toBe(Date.parse("2026-08-26T18:00:00.000Z"));
  });
});

describe("reading a session", () => {
  it("returns nothing without a cookie value, never consulting the backend", async () => {
    expect(await getServerSession(undefined, config)).toBeNull();
    expect(getSession).not.toHaveBeenCalled();
  });

  it("looks the session up scoped to the configured tenant", async () => {
    getSession.mockResolvedValue({ id: "session-1", tenantId: TENANT });
    expect(await getServerSession("session-1", config)).toMatchObject({ id: "session-1" });
    expect(getSession).toHaveBeenCalledWith("session-1", TENANT);
  });

  it("passes through a backend miss", async () => {
    getSession.mockResolvedValue(null);
    expect(await getServerSession("session-1", config)).toBeNull();
  });
});

describe("access tokens", () => {
  const storedSession = (accessTokenExpiresAt: number, tenantId = TENANT) => ({
    id: "session-1", tenantId, account, accessToken: "current-token",
    accessTokenExpiresAt, tokenCache: "cache", sessionExpiresAt: Date.now() + 3_600_000,
  });

  it("returns nothing when there is no session", async () => {
    getSession.mockResolvedValue(null);
    expect(await getSessionAccessToken("session-1", config)).toBeNull();
    expect(acquireSilent).not.toHaveBeenCalled();
  });

  it("returns nothing for a session outside the configured tenant", async () => {
    getSession.mockResolvedValue(storedSession(Date.now() + 3_600_000, OTHER_TENANT));
    expect(await getSessionAccessToken("session-1", config)).toBeNull();
    expect(acquireSilent).not.toHaveBeenCalled();
  });

  it("reuses a token that still has more than five minutes of life", async () => {
    getSession.mockResolvedValue(storedSession(Date.now() + 6 * 60 * 1_000));
    expect(await getSessionAccessToken("session-1", config)).toBe("current-token");
    expect(acquireSilent).not.toHaveBeenCalled();
    expect(updateSession).not.toHaveBeenCalled();
  });

  it("refreshes a token sitting exactly on the five-minute boundary", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    try {
      getSession.mockResolvedValue(storedSession(Date.now() + 5 * 60 * 1_000));
      acquireSilent.mockResolvedValue({ result: { accessToken: "fresh-token", expiresOn: new Date(Date.now() + 3_600_000) }, tokenCache: "new-cache" });
      // The window is "more than five minutes left"; exactly five minutes is not enough.
      expect(await getSessionAccessToken("session-1", config)).toBe("fresh-token");
      expect(acquireSilent).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it("reuses a token one millisecond past the five-minute boundary", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    try {
      getSession.mockResolvedValue(storedSession(Date.now() + 5 * 60 * 1_000 + 1));
      expect(await getSessionAccessToken("session-1", config)).toBe("current-token");
      expect(acquireSilent).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("refreshes a token inside the five-minute window", async () => {
    getSession.mockResolvedValue(storedSession(Date.now() + 60 * 1_000));
    acquireSilent.mockResolvedValue({ result: { accessToken: "fresh-token", expiresOn: new Date(Date.now() + 3_600_000) }, tokenCache: "new-cache" });
    expect(await getSessionAccessToken("session-1", config)).toBe("fresh-token");
    expect(acquireSilent).toHaveBeenCalledWith(config, account, "cache");
    expect(updateSession).toHaveBeenCalledWith(expect.objectContaining({ accessToken: "fresh-token", tokenCache: "new-cache" }));
  });

  it("refreshes a token that has already expired", async () => {
    getSession.mockResolvedValue(storedSession(Date.now() - 1_000));
    acquireSilent.mockResolvedValue({ result: { accessToken: "fresh-token", expiresOn: new Date(Date.now() + 3_600_000) }, tokenCache: "new-cache" });
    expect(await getSessionAccessToken("session-1", config)).toBe("fresh-token");
  });

  it("returns nothing when a silent refresh fails or yields no token", async () => {
    getSession.mockResolvedValue(storedSession(Date.now() + 60 * 1_000));
    acquireSilent.mockResolvedValue(null);
    expect(await getSessionAccessToken("session-1", config)).toBeNull();
    acquireSilent.mockResolvedValue({ result: { accessToken: "" }, tokenCache: "c" });
    expect(await getSessionAccessToken("session-1", config)).toBeNull();
    expect(updateSession).not.toHaveBeenCalled();
  });

  it("stores a conservative expiry when the refreshed result omits one", async () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    getSession.mockResolvedValue(storedSession(Date.parse("2026-08-26T10:01:00.000Z")));
    acquireSilent.mockResolvedValue({ result: { accessToken: "fresh-token", expiresOn: null }, tokenCache: "new-cache" });
    await getSessionAccessToken("session-1", config);
    expect(updateSession).toHaveBeenCalledWith(expect.objectContaining({ accessTokenExpiresAt: Date.parse("2026-08-26T10:55:00.000Z") }));
  });
});

describe("deleting a session", () => {
  it("deletes within the configured tenant", async () => {
    await deleteServerSession("session-1", config);
    expect(deleteSession).toHaveBeenCalledWith("session-1", TENANT);
  });

  it("does nothing without a cookie value", async () => {
    await deleteServerSession(undefined, config);
    expect(deleteSession).not.toHaveBeenCalled();
  });
});
