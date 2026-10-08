import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { MemoryBackend } from "./memory";
import { WorkerPoller, LEASE_MS, RETENTION_MS } from "./maintenance";

const tenant = cleanProjectFixture.tenant.tenantId;
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-08T12:00:00Z")); });
afterEach(() => vi.useRealTimers());
async function setup() {
  const backend = new MemoryBackend();
  await backend.createSession({ id: "session", tenantId: tenant, account: {}, accessToken: "synthetic", accessTokenExpiresAt: Date.now() + RETENTION_MS * 3, sessionExpiresAt: Date.now() + RETENTION_MS * 3, tokenCache: "synthetic" });
  const job = await backend.enqueueScan(tenant, "session");
  await backend.claimNextJob("worker-old", tenant);
  return { backend, job };
}
describe("worker idle maintenance", () => {
  it("recovers an interrupted scan after a quick restart and later lease expiry", async () => {
    const { backend, job } = await setup();
    const poller = new WorkerPoller(backend, tenant, "worker-new");
    expect(await poller.poll()).toBeNull();
    vi.setSystemTime(Date.now() + LEASE_MS + 1);
    expect(await poller.poll()).toMatchObject({ id: job.id, workerId: "worker-new", attempt: 2 });
    expect(await backend.heartbeatJob(job.id, "worker-old")).toBe(false);
    await expect(backend.completeJob(job.id, "worker-old", cleanProjectFixture, new Date(0))).rejects.toThrow();
  });
  it("a live heartbeat prevents a second worker from reclaiming a long scan", async () => {
    const { backend, job } = await setup();
    vi.setSystemTime(Date.now() + LEASE_MS - 1000);
    expect(await backend.heartbeatJob(job.id, "worker-old")).toBe(true);
    vi.setSystemTime(Date.now() + 2000);
    expect(await new WorkerPoller(backend, tenant, "worker-new").poll()).toBeNull();
  });
  it("hides expired snapshots on read and prunes them while idle without a new completed scan", async () => {
    const { backend, job } = await setup();
    const snapshot = { ...cleanProjectFixture, scannedAt: new Date().toISOString() };
    await backend.completeJob(job.id, "worker-old", snapshot, new Date(0));
    await backend.upsertThreatReview({ tenantId: tenant, snapshotId: snapshot.id, findingId: "finding", disposition: "open", owner: "", assumption: "", expiresAt: null, updatedAt: new Date().toISOString() }, null, null);
    vi.setSystemTime(Date.now() + RETENTION_MS);
    expect(await backend.getThreatReview(tenant, snapshot.id, "finding")).not.toBeNull();
    vi.setSystemTime(Date.now() + 1);
    expect(await backend.recentSnapshots(tenant)).toEqual([]);
    expect(await backend.getThreatReview(tenant, snapshot.id, "finding")).toBeNull();
    expect(await backend.priorThreatReviews(tenant, snapshot.id, ["finding"])).toEqual([]);
    const next = await backend.enqueueScan(tenant, "session"); await backend.claimNextJob("publisher", tenant);
    const current = { ...snapshot, id: "current", scannedAt: new Date().toISOString() };
    await backend.completeJob(next.id, "publisher", current, new Date(0));
    expect(await backend.priorThreatReviews(tenant, current.id, ["finding"])).toEqual([]);
    await new WorkerPoller(backend, tenant, "maintenance").poll();
    expect(await backend.getThreatReview(tenant, snapshot.id, "finding")).toBeNull();
    expect((await backend.getJob(job.id, tenant))!.snapshotId).toBeNull();
  });
  it("rejects concurrent review edits with the same revision", async () => {
    const { backend, job } = await setup();
    const snapshot = { ...cleanProjectFixture, scannedAt: new Date().toISOString() };
    await backend.completeJob(job.id, "worker-old", snapshot, new Date(0));
    const review = { tenantId: tenant, snapshotId: snapshot.id, findingId: "finding", disposition: "open" as const, owner: "Original", assumption: "", expiresAt: null, updatedAt: new Date().toISOString() };
    const initial = await backend.upsertThreatReview(review, null, null);
    const results = await Promise.allSettled([backend.upsertThreatReview({ ...review, owner: "First" }, null, initial.revision), backend.upsertThreatReview({ ...review, owner: "Second" }, null, initial.revision)]);
    expect(results.map(r => r.status)).toEqual(["fulfilled", "rejected"]);
    expect((await backend.getThreatReview(tenant, snapshot.id, "finding"))!.owner).toBe("First");
  });
});
