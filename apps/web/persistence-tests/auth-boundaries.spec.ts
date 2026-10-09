import { randomUUID } from "node:crypto";
import { PostgresBackend } from "@entra-explorer/backend";
import { expect, test } from "@playwright/test";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
test.beforeAll(async () => { await backend.migrate(); });
test.afterAll(async () => { await backend.close(); });

test("a malformed session cookie renders signed-out data and sign-out clears the broken cookie", async ({ page, context }) => {
  await context.addCookies([{ name: "entra_explorer_session", value: "not-a-uuid", url: "http://127.0.0.1:3101", httpOnly: true }]);
  const session = await context.request.get("/api/v1/session");
  expect(session.status()).toBe(200);
  expect(await session.json()).toEqual({ enabled: true, connected: false });
  const response = await page.goto("/overview");
  expect(response?.status()).toBe(200);
  await expect(page.getByText("You are signed out, so everything below is sample data.", { exact: true })).toBeVisible();
  const signOut = await context.request.post("/api/auth/sign-out", { headers: { origin: "http://127.0.0.1:3101" } });
  expect(signOut.status()).toBe(200);
  expect(await signOut.json()).toEqual({ signedOut: true });
  expect((await context.cookies()).some(cookie => cookie.name === "entra_explorer_session")).toBe(false);
});

test("a malformed sign-in flow returns an invalid-state recovery redirect without contacting Microsoft", async ({ context }) => {
  await context.addCookies([{ name: "entra_explorer_auth_flow", value: "not-a-uuid", url: "http://127.0.0.1:3101/api/auth", httpOnly: true }]);
  const callback = await context.request.get("/api/auth/callback?state=synthetic-state&code=unused", { maxRedirects: 0 });
  expect(callback.status()).toBe(302);
  expect(callback.headers().location).toBe("http://127.0.0.1:3101/settings?authError=invalid_state");
});

test("uppercase opaque identifiers resolve encrypted session and sign-in records consistently", async ({ context }) => {
  const sessionId = `abcdefab${randomUUID().slice(8)}`;
  const flowId = `fedcbafe${randomUUID().slice(8)}`;
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-unused", tokenCache: "synthetic", accessTokenExpiresAt: Date.now() + 3_600_000, sessionExpiresAt: Date.now() + 3_600_000 });
  await backend.createAuthFlow({ id: flowId, tenantId, verifier: "synthetic-unused", state: "synthetic-state", expiresAt: Date.now() + 600_000 });
  try {
    await context.addCookies([
      { name: "entra_explorer_session", value: sessionId.toUpperCase(), url: "http://127.0.0.1:3101", httpOnly: true },
      { name: "entra_explorer_auth_flow", value: flowId.toUpperCase(), url: "http://127.0.0.1:3101/api/auth", httpOnly: true },
    ]);
    const session = await context.request.get("/api/v1/session");
    expect(session.status()).toBe(200);
    expect(await session.json()).toMatchObject({ enabled: true, connected: true, tenantId });
    // A callback from an older tab must not destroy this newer pending login.
    const olderCallback = await context.request.get("/api/auth/callback?state=older-tab-state&error=access_denied", { maxRedirects: 0 });
    expect(olderCallback.status()).toBe(302);
    expect(olderCallback.headers().location).toBe("http://127.0.0.1:3101/settings?authError=invalid_state");
    expect((await context.cookies()).find(cookie => cookie.name === "entra_explorer_auth_flow")?.value).toBe(flowId.toUpperCase());
    // Provider denial consumes the existing flow without performing token exchange.
    const callback = await context.request.get("/api/auth/callback?state=synthetic-state&error=access_denied", { maxRedirects: 0 });
    expect(callback.status()).toBe(302);
    expect(callback.headers().location).toBe("http://127.0.0.1:3101/settings?authError=access_denied");
    expect(await backend.consumeAuthFlow(flowId, tenantId, "synthetic-state")).toBeNull();
    const signOut = await context.request.post("/api/auth/sign-out", { headers: { origin: "http://127.0.0.1:3101" } });
    expect(signOut.status()).toBe(200);
    expect(await backend.getSession(sessionId, tenantId)).toBeNull();
  } finally {
    await backend.deleteSession(sessionId, tenantId);
    await backend.consumeAuthFlow(flowId, tenantId, "synthetic-state");
  }
});

test("both scan APIs reject malformed IDs without a database error and retain authentication precedence", async ({ context }) => {
  const sessionId = randomUUID();
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-unused", tokenCache: "synthetic", accessTokenExpiresAt: Date.now() + 3_600_000, sessionExpiresAt: Date.now() + 3_600_000 });
  try {
    for (const base of ["/api/scans", "/api/v1/scans"]) {
      for (const method of ["GET", "DELETE"]) {
        const missingSession = await context.request.fetch(`${base}/not-a-uuid`, { method, headers: { origin: "http://127.0.0.1:3101" } });
        expect(missingSession.status()).toBe(401);
      }
    }
    await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true }]);
    for (const base of ["/api/scans", "/api/v1/scans"]) {
      for (const method of ["GET", "DELETE"]) {
        const invalidId = await context.request.fetch(`${base}/not-a-uuid`, { method, headers: { origin: "http://127.0.0.1:3101" } });
        expect(invalidId.status()).toBe(404);
        expect(invalidId.headers()["cache-control"]).toContain("no-store");
        expect(await invalidId.json()).toHaveProperty("error");
      }
    }
    expect(await backend.getSession(sessionId, tenantId)).not.toBeNull();
  } finally {
    await backend.deleteSession(sessionId, tenantId);
  }
});
