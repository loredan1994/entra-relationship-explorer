import { randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { describe, expect, it } from "vitest";
import { MemoryBackend } from "./memory";

const tenantId = "11111111-1111-4111-8111-111111111111";
function session(id = randomUUID(), tenant = tenantId) { return { id, tenantId: tenant, account: {}, accessToken: "token", accessTokenExpiresAt: Date.now() + 60_000, tokenCache: "cache", sessionExpiresAt: Date.now() + 60_000 }; }

describe("Backend contract", () => {
  it("consumes auth flows once and consumes mismatched state", async () => {
    const backend = new MemoryBackend(); const id = randomUUID();
    await backend.createAuthFlow({ id, tenantId, state: "expected", verifier: "verifier", expiresAt: Date.now() + 60_000 });
    expect(await backend.consumeAuthFlow(id, tenantId, "wrong")).toBeNull();
    expect(await backend.consumeAuthFlow(id, tenantId, "expected")).toBeNull();
  });

  it("expires and tenant-binds OAuth flows", async () => {
    const backend = new MemoryBackend();
    const wrongTenant = randomUUID();
    const tenantBoundId = randomUUID();
    await backend.createAuthFlow({ id: tenantBoundId, tenantId, state: "expected", verifier: "verifier", expiresAt: Date.now() + 60_000 });
    expect(await backend.consumeAuthFlow(tenantBoundId, wrongTenant, "expected")).toBeNull();
    expect(await backend.consumeAuthFlow(tenantBoundId, tenantId, "expected")).toBeNull();
    const expiredId = randomUUID();
    await backend.createAuthFlow({ id: expiredId, tenantId, state: "expected", verifier: "verifier", expiresAt: Date.now() - 1 });
    expect(await backend.consumeAuthFlow(expiredId, tenantId, "expected")).toBeNull();
  });

  it("enforces tenant isolation and one active scan", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const first = await backend.enqueueScan(tenantId, valid.id); const second = await backend.enqueueScan(tenantId, valid.id);
    expect(second.id).toBe(first.id);
    expect(await backend.getJob(first.id, randomUUID())).toBeNull();
    expect(await backend.getSession(valid.id, randomUUID())).toBeNull();
    expect(await backend.recentSnapshots(randomUUID())).toEqual([]);
  });

  it("tenant-isolates access events", async () => {
    const backend = new MemoryBackend();
    const otherTenant = randomUUID();
    await backend.recordAccess(tenantId, null, "read", "snapshot", "snapshot-one");
    await backend.recordAccess(otherTenant, null, "export", "snapshot", "snapshot-two");
    expect(await backend.recentAccessEvents(tenantId)).toEqual([expect.objectContaining({ tenantId, resourceId: "snapshot-one" })]);
    expect(await backend.recentAccessEvents(otherTenant)).toEqual([expect.objectContaining({ tenantId: otherTenant, resourceId: "snapshot-two" })]);
  });

  it("claims, updates, and atomically completes a scan", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const queued = await backend.enqueueScan(tenantId, valid.id); const claimed = await backend.claimNextJob("worker-1");
    expect(claimed?.id).toBe(queued.id);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId }, scannedAt: new Date().toISOString() };
    await expect(backend.updateJobProgress(queued.id, "worker-2", "owners", 1, "wrong owner")).rejects.toThrow(/owned/i);
    await expect(backend.completeJob(queued.id, "worker-2", snapshot, new Date(0))).rejects.toThrow(/owned/i);
    await backend.completeJob(queued.id, "worker-1", snapshot, new Date(0));
    expect((await backend.getJob(queued.id, tenantId))?.status).toBe("complete");
    expect((await backend.recentSnapshots(tenantId, 1))[0]?.id).toBe(snapshot.id);
  });

  it("rejects a snapshot from another tenant", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const queued = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob("worker-1");
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId: randomUUID() }, scannedAt: new Date().toISOString() };
    await expect(backend.completeJob(queued.id, "worker-1", snapshot, new Date(0))).rejects.toThrow(/tenant boundaries/i);
  });
});
