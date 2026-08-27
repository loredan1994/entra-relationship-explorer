import { randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { describe, expect, it } from "vitest";
import { MemoryBackend } from "./memory";

const tenantId = "11111111-1111-4111-8111-111111111111";
function session(id = randomUUID(), tenant = tenantId) { return { id, tenantId: tenant, account: {}, accessToken: "token", accessTokenExpiresAt: Date.now() + 60_000, tokenCache: "cache", sessionExpiresAt: Date.now() + 60_000 }; }

describe("Backend contract", () => {
  it("consumes auth flows once without letting mismatched state destroy them", async () => {
    const backend = new MemoryBackend(); const id = randomUUID();
    await backend.createAuthFlow({ id, tenantId, state: "expected", verifier: "verifier", expiresAt: Date.now() + 60_000 });
    expect(await backend.consumeAuthFlow(id, tenantId, "wrong")).toBeNull();
    expect(await backend.consumeAuthFlow(id, tenantId, "expected")).toMatchObject({ id, tenantId });
    expect(await backend.consumeAuthFlow(id, tenantId, "expected")).toBeNull();
  });

  it("expires and tenant-binds OAuth flows", async () => {
    const backend = new MemoryBackend();
    const wrongTenant = randomUUID();
    const tenantBoundId = randomUUID();
    await backend.createAuthFlow({ id: tenantBoundId, tenantId, state: "expected", verifier: "verifier", expiresAt: Date.now() + 60_000 });
    expect(await backend.consumeAuthFlow(tenantBoundId, wrongTenant, "expected")).toBeNull();
    expect(await backend.consumeAuthFlow(tenantBoundId, tenantId, "expected")).toMatchObject({ id: tenantBoundId, tenantId });
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

  it("lets a worker claim only the tenant it is configured to scan", async () => {
    const backend = new MemoryBackend();
    const otherTenant = randomUUID();
    const first = session(randomUUID(), tenantId);
    const second = session(randomUUID(), otherTenant);
    await backend.createSession(first);
    await backend.createSession(second);
    const otherJob = await backend.enqueueScan(otherTenant, second.id);
    const ownJob = await backend.enqueueScan(tenantId, first.id);
    expect((await backend.claimNextJob("tenant-worker", tenantId))?.id).toBe(ownJob.id);
    expect((await backend.getJob(otherJob.id, otherTenant))?.status).toBe("queued");
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
    const queued = await backend.enqueueScan(tenantId, valid.id); const claimed = await backend.claimNextJob("worker-1", tenantId);
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
    const queued = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob("worker-1", tenantId);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId: randomUUID() }, scannedAt: new Date().toISOString() };
    await expect(backend.completeJob(queued.id, "worker-1", snapshot, new Date(0))).rejects.toThrow(/tenant boundaries/i);
  });

  it("tenant-binds resumable checkpoints and clears them on completion", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const queued = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob("worker-1", tenantId);
    await backend.saveScanCheckpoint({ jobId: queued.id, tenantId, payload: { completedStages: ["applications"] }, updatedAt: new Date().toISOString() }, "worker-1");
    expect(await backend.getScanCheckpoint(queued.id, randomUUID())).toBeNull();
    expect(await backend.getScanCheckpoint(queued.id, tenantId)).toMatchObject({ payload: { completedStages: ["applications"] } });
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId }, scannedAt: new Date().toISOString() };
    await backend.completeJob(queued.id, "worker-1", snapshot, new Date(0));
    expect(await backend.getScanCheckpoint(queued.id, tenantId)).toBeNull();
  });

  it("persists tenant-isolated finding decisions and editable attack-flow copies", async () => {
    const backend = new MemoryBackend();
    const review = { findingId: "finding-1", snapshotId: randomUUID(), tenantId, disposition: "mitigating" as const, owner: "IAM", expiresAt: null, assumption: "Control remains effective", flowDraft: [{ id: "step-1", title: "Review configured path", evidenceEdgeId: "edge-1" }], updatedAt: new Date().toISOString() };
    await backend.upsertThreatReview(review, null);
    expect(await backend.getThreatReview(tenantId, review.snapshotId, review.findingId)).toMatchObject({ owner: "IAM", flowDraft: review.flowDraft });
    expect(await backend.getThreatReview(randomUUID(), review.snapshotId, review.findingId)).toBeNull();
  });

  it("returns only the most recent prior review for each requested finding", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const saveSnapshot = async (id: string, scannedAt: string) => {
      const queued = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob(id, tenantId);
      await backend.completeJob(queued.id, id, { ...cleanProjectFixture, id, scannedAt, tenant: { ...cleanProjectFixture.tenant, tenantId } }, new Date(0));
    };
    await saveSnapshot("snap-old", "2026-08-25T00:00:00.000Z");
    await backend.upsertThreatReview({ findingId: "finding-1", snapshotId: "snap-old", tenantId, disposition: "open", owner: "Old", expiresAt: null, assumption: "", updatedAt: "" }, null);
    await saveSnapshot("snap-prior", "2026-08-26T00:00:00.000Z");
    await backend.upsertThreatReview({ findingId: "finding-1", snapshotId: "snap-prior", tenantId, disposition: "mitigating", owner: "Current", expiresAt: null, assumption: "", updatedAt: "" }, null);
    await saveSnapshot("snap-current", "2026-08-27T00:00:00.000Z");
    expect(await backend.priorThreatReviews(tenantId, "snap-current", ["finding-1", "missing"])).toEqual([expect.objectContaining({ snapshotId: "snap-prior", owner: "Current" })]);
    expect(await backend.priorThreatReviews(randomUUID(), "snap-current", ["finding-1"])).toEqual([]);
  });

  it("removes reviews when their snapshots age out of retention", async () => {
    const backend = new MemoryBackend(); const valid = session(); await backend.createSession(valid);
    const queued = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob("old-worker", tenantId);
    const old = { ...cleanProjectFixture, id: "snap-old", scannedAt: "2026-07-01T00:00:00.000Z", tenant: { ...cleanProjectFixture.tenant, tenantId } };
    await backend.completeJob(queued.id, "old-worker", old, new Date(0));
    await backend.upsertThreatReview({ findingId: "finding-1", snapshotId: old.id, tenantId, disposition: "open", owner: "IAM", expiresAt: null, assumption: "", updatedAt: "" }, null);
    const next = await backend.enqueueScan(tenantId, valid.id); await backend.claimNextJob("new-worker", tenantId);
    await backend.completeJob(next.id, "new-worker", { ...old, id: "snap-new", scannedAt: "2026-08-27T00:00:00.000Z" }, new Date("2026-08-01T00:00:00.000Z"));
    expect(await backend.getThreatReview(tenantId, old.id, "finding-1")).toBeNull();
  });
});
