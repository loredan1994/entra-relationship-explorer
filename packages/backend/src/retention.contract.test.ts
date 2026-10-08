import { randomUUID } from "node:crypto";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MemoryBackend } from "./memory";
import { WorkerPoller } from "./maintenance";
import type { ThreatReview } from "./types";
const NOW = Date.parse("2026-10-08T12:00:00Z");
const DAY = 86400000;
let backend: MemoryBackend;
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); backend = new MemoryBackend(); });
afterEach(() => vi.useRealTimers());
async function publish(id: string, age = 0, tenantId = "alpha", cutoff = new Date(0)) {
  const sessionId = randomUUID();
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic", accessTokenExpiresAt: NOW + DAY * 90, sessionExpiresAt: NOW + DAY * 90, tokenCache: "synthetic" });
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("owner", tenantId);
  const snapshot: TenantSnapshot = { ...cleanProjectFixture, id, tenant: { tenantId, tenantLabel: "Synthetic" }, scannedAt: new Date(NOW - age).toISOString() };
  await backend.completeJob(job.id, "owner", snapshot, cutoff);
  return { snapshot, job };
}
function review(snapshot: TenantSnapshot, findingId = "finding"): ThreatReview {
  return { tenantId: snapshot.tenant.tenantId, snapshotId: snapshot.id, findingId, disposition: "open", owner: snapshot.id, assumption: "Synthetic", expiresAt: null, updatedAt: "" };
}
it("runs maintenance once per minute, at the exact boundary, using independent lease and retention cutoffs", async () => {
  const recover = vi.spyOn(backend, "recoverStaleJobs");
  const prune = vi.spyOn(backend, "pruneExpiredData");
  const claim = vi.spyOn(backend, "claimNextJob");
  const poller = new WorkerPoller(backend, "alpha", "owner");
  await poller.poll(NOW); await poller.poll(NOW + 59999);
  expect(recover).toHaveBeenCalledTimes(1); expect(prune).toHaveBeenCalledTimes(1);
  expect(recover).toHaveBeenCalledWith("alpha", new Date(NOW - 600000));
  expect(prune).toHaveBeenCalledWith("alpha", new Date(NOW - 30 * DAY));
  await poller.poll(NOW + 60000);
  expect(recover).toHaveBeenCalledTimes(2); expect(prune).toHaveBeenCalledTimes(2);
  expect(claim).toHaveBeenCalledTimes(3); expect(claim).toHaveBeenLastCalledWith("owner", "alpha");
});
it("retries failed maintenance instead of extending its successful-run timestamp", async () => {
  vi.spyOn(backend, "pruneExpiredData").mockRejectedValueOnce(new Error("storage unavailable"));
  const poller = new WorkerPoller(backend, "alpha", "owner");
  await expect(poller.poll(NOW)).rejects.toThrow("storage unavailable");
  await expect(poller.poll(NOW + 1)).resolves.toBeNull();
  expect(backend.pruneExpiredData).toHaveBeenCalledTimes(2);
});
it("rejects a checkpoint whose tenant differs from the worker's job", async () => {
  const { job } = await publish("seed");
  const next = await backend.enqueueScan("alpha", job.sessionId!);
  await backend.claimNextJob("owner", "alpha");
  await expect(backend.saveScanCheckpoint({ jobId: next.id, tenantId: "beta", payload: {}, updatedAt: "" }, "owner")).rejects.toThrow("Checkpoint and job tenant boundaries do not match.");
  expect(await backend.getScanCheckpoint(next.id, "beta")).toBeNull();
  await backend.requestScanCancellation(next.id, "alpha");
  vi.setSystemTime(NOW + 1500);
  expect(await backend.heartbeatJob(next.id, "owner")).toBe(true);
  expect((await backend.getJob(next.id, "alpha"))!.updatedAt).toBe(new Date(NOW + 1500).toISOString());
  expect(await backend.heartbeatJob(next.id, "other")).toBe(false);
});
it.each(["idle", "completion"])("%s retention physically removes only expired evidence and decisions", async (mode) => {
  const old = await publish("old", 30 * DAY + 1);
  const boundary = await publish("boundary", 30 * DAY);
  const fresh = await publish("fresh", DAY);
  const foreign = await publish("foreign", 31 * DAY, "beta");
  // Seed reviews when their snapshots are within the supported read window.
  vi.setSystemTime(NOW - 2 * DAY);
  for (const item of [old, boundary, fresh, foreign]) await backend.upsertThreatReview(review(item.snapshot), null, null);
  vi.setSystemTime(NOW);
  if (mode === "idle") await backend.pruneExpiredData("alpha", new Date(NOW - 30 * DAY));
  else await publish("new", 0, "alpha", new Date(NOW - 30 * DAY));
  // A clock correction must not bring physically deleted data back into view.
  vi.setSystemTime(NOW - 2 * DAY);
  expect((await backend.recentSnapshots("alpha")).map(s => s.id)).toEqual(mode === "idle" ? ["fresh", "boundary"] : ["new", "fresh", "boundary"]);
  expect(await backend.getThreatReview("alpha", "boundary", "finding")).not.toBeNull();
  expect(await backend.getThreatReview("alpha", "fresh", "finding")).not.toBeNull();
  expect(await backend.getThreatReview("beta", "foreign", "finding")).not.toBeNull();
  // Reusing an ID in a synthetic snapshot must not resurrect a deleted decision.
  await publish("old");
  expect(await backend.getThreatReview("alpha", "old", "finding")).toBeNull();
  if (mode === "idle") {
    expect((await backend.getJob(old.job.id, "alpha"))!.snapshotId).toBeNull();
    expect((await backend.getJob(boundary.job.id, "alpha"))!.snapshotId).toBe("boundary");
    expect((await backend.getJob(foreign.job.id, "beta"))!.snapshotId).toBe("foreign");
  }
});
it("physically deletes expired sessions and authorization flows, preserving future and foreign entries", async () => {
  for (const tenantId of ["alpha", "beta"]) for (const offset of [-1, 0, 1]) {
    const id = `${tenantId}:${offset}`;
    await backend.createAuthFlow({ id, tenantId, state: "state", verifier: "verifier", expiresAt: NOW + offset });
    await backend.createSession({ id, tenantId, account: {}, accessToken: "synthetic", accessTokenExpiresAt: NOW + 100, sessionExpiresAt: NOW + offset, tokenCache: "synthetic" });
  }
  await backend.pruneExpiredData("alpha", new Date(NOW - 30 * DAY));
  vi.setSystemTime(NOW - 10);
  for (const tenantId of ["alpha", "beta"]) for (const offset of [-1, 0, 1]) {
    const id = `${tenantId}:${offset}`;
    const removed = tenantId === "alpha" && offset <= 0;
    expect(Boolean(await backend.getSession(id, tenantId))).toBe(!removed);
    expect(Boolean(await backend.consumeAuthFlow(id, tenantId, "state"))).toBe(!removed);
  }
});
it("retains the full 30th day and refuses missing or expired review targets even for unconditional writes", async () => {
  const { snapshot } = await publish("boundary", 30 * DAY);
  await publish("fresh");
  expect((await backend.recentSnapshots("alpha")).map(s => s.id)).toEqual(["fresh", "boundary"]);
  const saved = await backend.upsertThreatReview(review(snapshot), null, null);
  expect(saved.revision).toBeTruthy();
  await expect(backend.upsertThreatReview(review(snapshot), null, "stale")).rejects.toThrow("Review conflict: another decision was saved. Reload before saving.");
  await expect(backend.upsertThreatReview(review(snapshot), null, null)).rejects.toThrow("Review conflict");
  for (const target of [{ ...snapshot, id: "missing" }, { ...snapshot, tenant: { tenantId: "beta", tenantLabel: "Other" } }]) {
    await expect(backend.upsertThreatReview(review(target), null)).rejects.toThrow("Review conflict: the snapshot expired or is unavailable.");
  }
  vi.setSystemTime(NOW + 1);
  expect(await backend.getThreatReview("alpha", snapshot.id, "finding")).toBeNull();
  await expect(backend.upsertThreatReview(review(snapshot), null, saved.revision)).rejects.toThrow("Review conflict: the snapshot expired or is unavailable.");
});
it("prior context uses the nearest strictly older snapshot, excluding newer, current and missing selections", async () => {
  for (const [id, age] of [["old", 30 * DAY], ["middle", DAY], ["new", 0]] as const) {
    const { snapshot } = await publish(id, age);
    await backend.upsertThreatReview(review(snapshot), null, null);
  }
  expect(await backend.priorThreatReviews("alpha", "missing", ["finding"])).toEqual([]);
  expect(await backend.priorThreatReviews("alpha", "middle", [])).toEqual([]);
  expect(await backend.priorThreatReviews("alpha", "middle", ["finding"])).toEqual([expect.objectContaining({ owner: "old" })]);
  expect(await backend.priorThreatReviews("alpha", "new", ["finding"])).toEqual([expect.objectContaining({ owner: "middle" })]);
  expect(await backend.priorThreatReviews("alpha", "old", ["finding"])).toEqual([]);
});
it("limits prior context to 5000 distinct findings after de-duplication", async () => {
  const { snapshot } = await publish("old", 1000);
  for (const id of ["last", "overflow"]) await backend.upsertThreatReview(review(snapshot, id), null, null);
  await publish("current");
  const ids = [...Array(5000).fill("duplicate") as string[], ...Array.from({ length: 4998 }, (_, i) => `absent-${i}`), "last", "overflow"];
  expect(await backend.priorThreatReviews("alpha", "current", ids)).toEqual([expect.objectContaining({ findingId: "last" })]);
});
