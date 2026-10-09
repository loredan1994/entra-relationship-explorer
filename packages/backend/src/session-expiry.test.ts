import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MemoryBackend } from "./memory";
import type { DurableSession } from "./types";

const now = Date.parse("2026-10-09T12:00:00Z");
let backend: MemoryBackend;
let session: DurableSession;
beforeEach(async () => {
  vi.useFakeTimers();
  vi.setSystemTime(now);
  backend = new MemoryBackend();
  session = { id: "refreshing-session", tenantId: "synthetic-tenant", account: {}, accessToken: "original-synthetic-token", tokenCache: "original-synthetic-cache", accessTokenExpiresAt: now + 100, sessionExpiresAt: now + 1000 };
  await backend.createSession(session);
});
afterEach(() => vi.useRealTimers());

it("persists token refresh while the existing session remains valid", async () => {
  const pending = (await backend.getSession(session.id, session.tenantId))!;
  vi.setSystemTime(session.sessionExpiresAt - 1);
  await backend.updateSession({ ...pending, accessToken: "new-synthetic-token", tokenCache: "new-synthetic-cache" });
  expect(await backend.getSession(session.id, session.tenantId)).toMatchObject({ accessToken: "new-synthetic-token", tokenCache: "new-synthetic-cache", sessionExpiresAt: session.sessionExpiresAt });
});

it.each([0, 1])("rejects a pending token refresh %i ms after session expiry without changing stored credentials", async offset => {
  const pending = (await backend.getSession(session.id, session.tenantId))!;
  vi.setSystemTime(session.sessionExpiresAt + offset);
  await expect(backend.updateSession({ ...pending, accessToken: "new-synthetic-token", tokenCache: "new-synthetic-cache", sessionExpiresAt: now + 60000 })).rejects.toThrow("Session was not found in this tenant.");
  expect(await backend.getSession(session.id, session.tenantId)).toBeNull();
  vi.setSystemTime(now);
  expect(await backend.getSession(session.id, session.tenantId)).toEqual(session);
});
