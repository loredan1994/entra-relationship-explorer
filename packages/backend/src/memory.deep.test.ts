import { randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryBackend } from "./memory";
import type { DurableSession, ScanJob } from "./types";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";

function session(overrides: Partial<DurableSession> = {}): DurableSession {
  return {
    id: randomUUID(),
    tenantId: TENANT,
    account: { username: "person@contoso.test" },
    accessToken: "token",
    accessTokenExpiresAt: Date.now() + 60_000,
    tokenCache: "cache",
    sessionExpiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

function snapshotFor(tenantId = TENANT, scannedAt = new Date().toISOString()) {
  return { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId }, scannedAt };
}

let backend: MemoryBackend;
beforeEach(() => { backend = new MemoryBackend(); });

/** Queues a job and claims it, returning the running job. */
async function runningJob(workerId = "worker-1"): Promise<ScanJob> {
  const live = session();
  await backend.createSession(live);
  await backend.enqueueScan(TENANT, live.id);
  return (await backend.claimNextJob(workerId))!;
}

describe("backend health and lifecycle", () => {
  it("reports the in-memory driver as healthy and migrates and closes without effect", async () => {
    await expect(backend.migrate()).resolves.toBeUndefined();
    expect(await backend.health()).toEqual({ ok: true, database: "memory" });
    await expect(backend.close()).resolves.toBeUndefined();
  });
});

describe("authorization flows", () => {
  const flow = (overrides = {}) => ({
    id: randomUUID(), tenantId: TENANT, state: "state-value", verifier: "verifier-value",
    expiresAt: Date.now() + 60_000, ...overrides,
  });

  it("returns the stored flow when the callback replays the exact state, then never again", async () => {
    const pending = flow();
    await backend.createAuthFlow(pending);
    expect(await backend.consumeAuthFlow(pending.id, TENANT, "state-value")).toEqual(pending);
    expect(await backend.consumeAuthFlow(pending.id, TENANT, "state-value")).toBeNull();
  });

  it("rejects a state of the right length but the wrong value", async () => {
    const pending = flow();
    await backend.createAuthFlow(pending);
    expect("state-valve").toHaveLength("state-value".length);
    expect(await backend.consumeAuthFlow(pending.id, TENANT, "state-valve")).toBeNull();
  });

  it("hands back a copy so a caller cannot mutate the stored flow", async () => {
    const pending = flow();
    await backend.createAuthFlow(pending);
    pending.verifier = "changed-after-store";
    const consumed = await backend.consumeAuthFlow(pending.id, TENANT, "state-value");
    expect(consumed?.verifier).toBe("verifier-value");
  });

  it("consumes a flow that was never stored as nothing", async () => {
    expect(await backend.consumeAuthFlow(randomUUID(), TENANT, "state-value")).toBeNull();
  });

  it("refuses a flow replayed against another tenant or after it expired", async () => {
    const crossTenant = flow();
    await backend.createAuthFlow(crossTenant);
    expect(await backend.consumeAuthFlow(crossTenant.id, OTHER_TENANT, "state-value")).toBeNull();
    const expired = flow({ expiresAt: Date.now() - 1 });
    await backend.createAuthFlow(expired);
    expect(await backend.consumeAuthFlow(expired.id, TENANT, "state-value")).toBeNull();
  });
});

describe("session records", () => {
  it("refuses to update a session that belongs to another tenant", async () => {
    const live = session();
    await backend.createSession(live);
    await expect(backend.updateSession({ ...live, tenantId: OTHER_TENANT })).rejects.toThrow(/not found in this tenant/);
  });

  it("refuses to update a session that was never created", async () => {
    await expect(backend.updateSession(session())).rejects.toThrow(/not found in this tenant/);
  });

  it("stores an updated session and returns the new value", async () => {
    const live = session();
    await backend.createSession(live);
    await backend.updateSession({ ...live, accessToken: "rotated" });
    expect((await backend.getSession(live.id, TENANT))?.accessToken).toBe("rotated");
  });

  it("treats an expired session as absent", async () => {
    const expired = session({ sessionExpiresAt: Date.now() - 1 });
    await backend.createSession(expired);
    expect(await backend.getSession(expired.id, TENANT)).toBeNull();
  });

  it("deletes a session only within its own tenant", async () => {
    const live = session();
    await backend.createSession(live);
    await backend.deleteSession(live.id, OTHER_TENANT);
    expect(await backend.getSession(live.id, TENANT)).not.toBeNull();
    await backend.deleteSession(live.id, TENANT);
    expect(await backend.getSession(live.id, TENANT)).toBeNull();
  });

  it("ignores a delete for a session that does not exist", async () => {
    await expect(backend.deleteSession(randomUUID(), TENANT)).resolves.toBeUndefined();
  });

  it("hands out defensive copies so a caller cannot mutate stored state", async () => {
    const live = session();
    await backend.createSession(live);
    const first = (await backend.getSession(live.id, TENANT))!;
    first.accessToken = "tampered";
    expect((await backend.getSession(live.id, TENANT))?.accessToken).toBe("token");
  });
});

describe("scan queue", () => {
  it("requires a live session before a scan can be queued", async () => {
    await expect(backend.enqueueScan(TENANT, randomUUID())).rejects.toThrow(/valid tenant session/);
    const expired = session({ sessionExpiresAt: Date.now() - 1 });
    await backend.createSession(expired);
    await expect(backend.enqueueScan(TENANT, expired.id)).rejects.toThrow(/valid tenant session/);
  });

  it("starts a queued job at the first stage with no collection recorded", async () => {
    const live = session();
    await backend.createSession(live);
    const job = await backend.enqueueScan(TENANT, live.id);
    expect(job).toMatchObject({
      tenantId: TENANT, sessionId: live.id, status: "queued", stage: "applications",
      collected: 0, snapshotId: null, completion: null, error: null, attempt: 0, workerId: null, finishedAt: null,
      detail: "Waiting to begin the read-only scan",
    });
  });

  it("returns the latest job for a tenant and nothing for a tenant with no jobs", async () => {
    const live = session();
    await backend.createSession(live);
    const job = await backend.enqueueScan(TENANT, live.id);
    expect((await backend.getLatestJob(TENANT))?.id).toBe(job.id);
    expect(await backend.getLatestJob(OTHER_TENANT)).toBeNull();
  });

  it("claims nothing when no job is queued", async () => {
    expect(await backend.claimNextJob("worker-1")).toBeNull();
  });

  it("counts each claim as an attempt and records the owning worker", async () => {
    const job = await runningJob("worker-7");
    expect(job).toMatchObject({ status: "running", workerId: "worker-7", attempt: 1, detail: "Starting Microsoft Graph reads" });
  });

  it("does not re-claim a job that is already running", async () => {
    await runningJob("worker-1");
    expect(await backend.claimNextJob("worker-2")).toBeNull();
  });

  it("refuses progress, completion, and failure from a worker that does not own the job", async () => {
    const job = await runningJob("worker-1");
    await expect(backend.updateJobProgress(job.id, "worker-2", "owners", 3, "x")).rejects.toThrow(/not owned/);
    await expect(backend.failJob(job.id, "worker-2", "boom")).rejects.toThrow(/not owned/);
    await expect(backend.saveScanCheckpoint({ jobId: job.id, tenantId: TENANT, payload: {}, updatedAt: "" }, "worker-2")).rejects.toThrow(/not owned/);
  });

  it("records progress from the owning worker", async () => {
    const job = await runningJob();
    await backend.updateJobProgress(job.id, "worker-1", "groupMemberships", 42, "Direct group memberships collected");
    expect(await backend.getJob(job.id, TENANT)).toMatchObject({ stage: "groupMemberships", collected: 42, detail: "Direct group memberships collected" });
  });

  it("marks a failed scan without publishing a snapshot", async () => {
    const job = await runningJob();
    await backend.failJob(job.id, "worker-1", "Graph returned 503");
    const failed = (await backend.getJob(job.id, TENANT))!;
    expect(failed).toMatchObject({ status: "failed", error: "Graph returned 503", workerId: null });
    expect(failed.detail).toBe("The read-only scan stopped before a snapshot could be saved");
    expect(failed.finishedAt).not.toBeNull();
    expect(await backend.recentSnapshots(TENANT)).toEqual([]);
  });
});

describe("stale job recovery", () => {
  /** Rewinds a job's updatedAt by re-running recovery against a future cutoff. */
  const future = () => new Date(Date.now() + 60_000);

  it("returns a running job to the queue when its worker went silent", async () => {
    const job = await runningJob("worker-gone");
    expect(await backend.recoverStaleJobs(future())).toBe(1);
    const recovered = (await backend.getJob(job.id, TENANT))!;
    expect(recovered).toMatchObject({ status: "queued", workerId: null, detail: "Recovered after the previous worker stopped" });
    expect(await backend.claimNextJob("worker-new")).toMatchObject({ id: job.id, attempt: 2 });
  });

  it("finishes a cancellation whose worker never acknowledged it", async () => {
    const job = await runningJob("worker-gone");
    await backend.requestScanCancellation(job.id, TENANT);
    expect(await backend.recoverStaleJobs(future())).toBe(1);
    const recovered = (await backend.getJob(job.id, TENANT))!;
    expect(recovered).toMatchObject({ status: "cancelled", workerId: null, detail: "Cancellation completed after the previous worker stopped" });
    expect(recovered.finishedAt).toBe(recovered.updatedAt);
  });

  it("discards the resumable checkpoint when it completes a stale cancellation", async () => {
    const job = await runningJob("worker-gone");
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId: TENANT, payload: { completedStages: ["applications"] }, updatedAt: "" }, "worker-gone");
    await backend.requestScanCancellation(job.id, TENANT);
    await backend.recoverStaleJobs(future());
    expect(await backend.getScanCheckpoint(job.id, TENANT)).toBeNull();
  });

  it("keeps the checkpoint of a job it merely requeues, so the retry can resume", async () => {
    const job = await runningJob("worker-gone");
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId: TENANT, payload: { completedStages: ["applications"] }, updatedAt: "" }, "worker-gone");
    await backend.recoverStaleJobs(future());
    expect(await backend.getScanCheckpoint(job.id, TENANT)).toMatchObject({ payload: { completedStages: ["applications"] } });
  });

  it("leaves a job alone while its worker is still within the stale window", async () => {
    const job = await runningJob("worker-live");
    expect(await backend.recoverStaleJobs(new Date(Date.now() - 60_000))).toBe(0);
    expect((await backend.getJob(job.id, TENANT))?.status).toBe("running");
  });

  it("never recovers a job that already reached a terminal state", async () => {
    const job = await runningJob();
    await backend.failJob(job.id, "worker-1", "boom");
    expect(await backend.recoverStaleJobs(future())).toBe(0);
    expect((await backend.getJob(job.id, TENANT))?.status).toBe("failed");
  });

  it("counts every stale job it recovers", async () => {
    const first = await runningJob("worker-a");
    await backend.recoverStaleJobs(future());
    await backend.claimNextJob("worker-b");
    await backend.requestScanCancellation(first.id, TENANT);
    expect(await backend.recoverStaleJobs(future())).toBe(1);
  });
});

describe("scan cancellation", () => {
  it("cancels a queued scan outright, because no Graph read has begun", async () => {
    const live = session();
    await backend.createSession(live);
    const job = await backend.enqueueScan(TENANT, live.id);
    const cancelled = (await backend.requestScanCancellation(job.id, TENANT))!;
    expect(cancelled).toMatchObject({ status: "cancelled", detail: "Cancelled before Microsoft Graph collection began" });
    expect(cancelled.finishedAt).not.toBeNull();
  });

  it("asks a running scan to stop rather than cutting it off mid-read", async () => {
    const job = await runningJob();
    const requested = (await backend.requestScanCancellation(job.id, TENANT))!;
    expect(requested).toMatchObject({ status: "cancel_requested", detail: "Cancellation requested; finishing the current read safely" });
    expect(requested.finishedAt).toBeNull();
  });

  it("is idempotent while a cancellation is already pending", async () => {
    const job = await runningJob();
    await backend.requestScanCancellation(job.id, TENANT);
    expect((await backend.requestScanCancellation(job.id, TENANT))?.status).toBe("cancel_requested");
  });

  it("refuses to cancel across a tenant boundary, for an unknown job, or once terminal", async () => {
    const job = await runningJob();
    expect(await backend.requestScanCancellation(job.id, OTHER_TENANT)).toBeNull();
    expect(await backend.requestScanCancellation(randomUUID(), TENANT)).toBeNull();
    await backend.failJob(job.id, "worker-1", "boom");
    expect(await backend.requestScanCancellation(job.id, TENANT)).toBeNull();
  });

  it("tells only the owning worker that a cancellation is pending", async () => {
    const job = await runningJob("worker-1");
    expect(await backend.isScanCancellationRequested(job.id, "worker-1")).toBe(false);
    await backend.requestScanCancellation(job.id, TENANT);
    expect(await backend.isScanCancellationRequested(job.id, "worker-1")).toBe(true);
    expect(await backend.isScanCancellationRequested(job.id, "worker-2")).toBe(false);
    expect(await backend.isScanCancellationRequested(randomUUID(), "worker-1")).toBe(false);
  });

  it("completes a cancellation and discards the checkpoint without publishing a snapshot", async () => {
    const job = await runningJob();
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId: TENANT, payload: { completedStages: ["applications"] }, updatedAt: "" }, "worker-1");
    await backend.requestScanCancellation(job.id, TENANT);
    await backend.cancelJob(job.id, "worker-1");
    expect(await backend.getJob(job.id, TENANT)).toMatchObject({
      status: "cancelled", workerId: null, detail: "Scan cancelled safely; no partial snapshot was published",
    });
    expect(await backend.getScanCheckpoint(job.id, TENANT)).toBeNull();
    expect(await backend.recentSnapshots(TENANT)).toEqual([]);
  });

  it("refuses to finish a cancellation that was never requested or is not this worker's", async () => {
    const job = await runningJob("worker-1");
    await expect(backend.cancelJob(job.id, "worker-1")).rejects.toThrow(/not cancellable/);
    await backend.requestScanCancellation(job.id, TENANT);
    await expect(backend.cancelJob(job.id, "worker-2")).rejects.toThrow(/not cancellable/);
    await expect(backend.cancelJob(randomUUID(), "worker-1")).rejects.toThrow(/not cancellable/);
  });
});

describe("snapshot retention", () => {
  it("discards snapshots older than the retention cutoff on completion", async () => {
    const job = await runningJob();
    const stale = snapshotFor(TENANT, "2020-01-01T00:00:00.000Z");
    const fresh = snapshotFor(TENANT, "2026-08-26T00:00:00.000Z");
    await backend.completeJob(job.id, "worker-1", stale, new Date(0));
    const second = await runningJobAfterCompletion();
    await backend.completeJob(second.id, "worker-2", fresh, new Date("2024-01-01T00:00:00.000Z"));
    const kept = await backend.recentSnapshots(TENANT);
    expect(kept.map((item) => item.id)).toEqual([fresh.id]);
  });

  async function runningJobAfterCompletion(): Promise<ScanJob> {
    const live = session();
    await backend.createSession(live);
    await backend.enqueueScan(TENANT, live.id);
    return (await backend.claimNextJob("worker-2"))!;
  }

  it("returns snapshots newest first", async () => {
    const job = await runningJob();
    await backend.completeJob(job.id, "worker-1", snapshotFor(TENANT, "2026-01-01T00:00:00.000Z"), new Date(0));
    const second = await runningJobAfterCompletion();
    const newer = snapshotFor(TENANT, "2026-08-01T00:00:00.000Z");
    await backend.completeJob(second.id, "worker-2", newer, new Date(0));
    expect((await backend.recentSnapshots(TENANT))[0]?.id).toBe(newer.id);
  });

  it("clamps the snapshot page size into a sane range", async () => {
    const job = await runningJob();
    await backend.completeJob(job.id, "worker-1", snapshotFor(), new Date(0));
    expect(await backend.recentSnapshots(TENANT, 0)).toHaveLength(1);
    expect(await backend.recentSnapshots(TENANT, -5)).toHaveLength(1);
    expect(await backend.recentSnapshots(TENANT, 1_000)).toHaveLength(1);
  });

  it("summarizes the completed scan on the job record", async () => {
    const job = await runningJob();
    const snapshot = snapshotFor();
    await backend.completeJob(job.id, "worker-1", snapshot, new Date(0));
    expect(await backend.getJob(job.id, TENANT)).toMatchObject({
      status: "complete", stage: "complete", snapshotId: snapshot.id,
      completion: snapshot.completion.status,
      collected: snapshot.nodes.length + snapshot.edges.length,
      detail: `${snapshot.nodes.length} objects and ${snapshot.edges.length} relationships normalized`,
      workerId: null,
    });
  });
});

describe("access events", () => {
  it("clamps the access-event page size and orders newest first", async () => {
    for (let index = 0; index < 3; index += 1) await backend.recordAccess(TENANT, null, "read", "snapshot", `snapshot-${index}`);
    expect(await backend.recentAccessEvents(TENANT, 0)).toHaveLength(1);
    expect(await backend.recentAccessEvents(TENANT, 1_000)).toHaveLength(3);
    const ordered = await backend.recentAccessEvents(TENANT);
    expect(ordered).toHaveLength(3);
    for (let index = 1; index < ordered.length; index += 1) {
      expect(ordered[index - 1]!.createdAt >= ordered[index]!.createdAt).toBe(true);
    }
  });

  it("stores an absent resource id as null rather than undefined", async () => {
    await backend.recordAccess(TENANT, null, "list", "scan_job");
    expect((await backend.recentAccessEvents(TENANT))[0]).toMatchObject({ resourceId: null, sessionId: null, action: "list", resourceType: "scan_job" });
  });
});

describe("threat reviews", () => {
  const review = (overrides = {}) => ({
    findingId: "finding-1", snapshotId: randomUUID(), tenantId: TENANT,
    disposition: "open" as const, owner: "IAM", expiresAt: null,
    assumption: "Control remains effective", updatedAt: "1970-01-01T00:00:00.000Z", ...overrides,
  });

  it("stamps its own update time rather than trusting the caller's", async () => {
    const stored = await backend.upsertThreatReview(review(), null);
    expect(stored.updatedAt).not.toBe("1970-01-01T00:00:00.000Z");
    expect(Date.parse(stored.updatedAt)).toBeGreaterThan(0);
  });

  it("replaces an existing decision for the same finding instead of duplicating it", async () => {
    const first = review();
    await backend.upsertThreatReview(first, null);
    await backend.upsertThreatReview({ ...first, disposition: "resolved", owner: "Security" }, null);
    expect(await backend.getThreatReview(TENANT, first.snapshotId, first.findingId)).toMatchObject({ disposition: "resolved", owner: "Security" });
  });

  it("records an audit event naming the reviewed finding", async () => {
    const first = review();
    await backend.upsertThreatReview(first, "session-9");
    expect((await backend.recentAccessEvents(TENANT))[0]).toMatchObject({
      action: "update", resourceType: "threat_review", resourceId: first.findingId, sessionId: "session-9",
    });
  });

  it("returns nothing for an unreviewed finding", async () => {
    expect(await backend.getThreatReview(TENANT, randomUUID(), "finding-absent")).toBeNull();
  });
});

describe("time boundaries and ordering", () => {
  const START = new Date("2026-08-26T10:00:00.000Z");
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(START); });
  afterEach(() => { vi.useRealTimers(); });

  /** Queues a job for `tenant`, then cancels it so the tenant can queue another. */
  async function queueAndRelease(tenantId: string): Promise<ScanJob> {
    const live = session({ tenantId });
    await backend.createSession(live);
    const job = await backend.enqueueScan(tenantId, live.id);
    await backend.requestScanCancellation(job.id, tenantId);
    return job;
  }

  it("treats a flow that expires exactly now as expired", async () => {
    const id = randomUUID();
    await backend.createAuthFlow({ id, tenantId: TENANT, state: "state-value", verifier: "v", expiresAt: Date.now() });
    expect(await backend.consumeAuthFlow(id, TENANT, "state-value")).toBeNull();
  });

  it("accepts a flow with a single millisecond of life left", async () => {
    const id = randomUUID();
    await backend.createAuthFlow({ id, tenantId: TENANT, state: "state-value", verifier: "v", expiresAt: Date.now() + 1 });
    expect(await backend.consumeAuthFlow(id, TENANT, "state-value")).not.toBeNull();
  });

  it("treats a session that expires exactly now as absent", async () => {
    const expiring = session({ sessionExpiresAt: Date.now() });
    await backend.createSession(expiring);
    expect(await backend.getSession(expiring.id, TENANT)).toBeNull();
    const live = session({ sessionExpiresAt: Date.now() + 1 });
    await backend.createSession(live);
    expect(await backend.getSession(live.id, TENANT)).not.toBeNull();
  });

  it("returns the newest job for a tenant, not the first one it recorded", async () => {
    const first = await queueAndRelease(TENANT);
    vi.advanceTimersByTime(60_000);
    const live = session();
    await backend.createSession(live);
    const second = await backend.enqueueScan(TENANT, live.id);
    expect(second.createdAt > first.createdAt).toBe(true);
    expect((await backend.getLatestJob(TENANT))?.id).toBe(second.id);
  });

  it("orders access events newest first and honours a page size below the total", async () => {
    for (const resource of ["oldest", "middle", "newest"]) {
      await backend.recordAccess(TENANT, null, "read", "snapshot", resource);
      vi.advanceTimersByTime(1_000);
    }
    expect((await backend.recentAccessEvents(TENANT)).map((event) => event.resourceId)).toEqual(["newest", "middle", "oldest"]);
    expect((await backend.recentAccessEvents(TENANT, 2)).map((event) => event.resourceId)).toEqual(["newest", "middle"]);
  });

  it("leaves a job whose heartbeat lands exactly on the cutoff alone", async () => {
    const running = await runningJob("worker-quiet");
    const cutoff = new Date(Date.now());
    expect(await backend.recoverStaleJobs(cutoff)).toBe(0);
    expect((await backend.getJob(running.id, TENANT))?.status).toBe("running");
    await backend.requestScanCancellation(running.id, TENANT);
    expect(await backend.recoverStaleJobs(new Date(Date.now()))).toBe(0);
    expect((await backend.getJob(running.id, TENANT))?.status).toBe("cancel_requested");
  });

  it("recovers a job whose heartbeat is a millisecond older than the cutoff", async () => {
    const running = await runningJob("worker-quiet");
    expect(await backend.recoverStaleJobs(new Date(Date.now() + 1))).toBe(1);
    expect((await backend.getJob(running.id, TENANT))?.status).toBe("queued");
  });

  it("keeps a snapshot scanned exactly at the retention cutoff", async () => {
    const job = await runningJob();
    const boundary = snapshotFor(TENANT, START.toISOString());
    await backend.completeJob(job.id, "worker-1", boundary, START);
    expect((await backend.recentSnapshots(TENANT)).map((item) => item.id)).toEqual([boundary.id]);
  });

  it("returns only the requested number of snapshots when more are retained", async () => {
    const ids: string[] = [];
    for (const scannedAt of ["2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z"]) {
      const live = session();
      await backend.createSession(live);
      await backend.enqueueScan(TENANT, live.id);
      const claimed = (await backend.claimNextJob("worker-page"))!;
      const snapshot = snapshotFor(TENANT, scannedAt);
      ids.unshift(snapshot.id);
      await backend.completeJob(claimed.id, "worker-page", snapshot, new Date(0));
    }
    expect(await backend.recentSnapshots(TENANT)).toHaveLength(3);
    expect((await backend.recentSnapshots(TENANT, 2)).map((item) => item.id)).toEqual(ids.slice(0, 2));
  });
});

describe("one active scan per tenant", () => {
  async function queue(tenantId: string): Promise<ScanJob> {
    const live = session({ tenantId });
    await backend.createSession(live);
    return backend.enqueueScan(tenantId, live.id);
  }

  it("does not let another tenant's active scan block this tenant", async () => {
    const other = await queue(OTHER_TENANT);
    const mine = await queue(TENANT);
    expect(mine.id).not.toBe(other.id);
    expect(mine.tenantId).toBe(TENANT);
  });

  it("returns the running job rather than queuing a second one", async () => {
    const queued = await queue(TENANT);
    const claimed = (await backend.claimNextJob("worker-1"))!;
    expect(claimed.id).toBe(queued.id);
    expect((await queue(TENANT)).id).toBe(queued.id);
  });

  it("returns the job awaiting cancellation rather than queuing alongside it", async () => {
    const queued = await queue(TENANT);
    await backend.claimNextJob("worker-1");
    await backend.requestScanCancellation(queued.id, TENANT);
    const again = await queue(TENANT);
    expect(again).toMatchObject({ id: queued.id, status: "cancel_requested" });
  });

  it("queues afresh once the previous scan reached a terminal state", async () => {
    const queued = await queue(TENANT);
    await backend.claimNextJob("worker-1");
    await backend.failJob(queued.id, "worker-1", "boom");
    expect((await queue(TENANT)).id).not.toBe(queued.id);
  });
});

describe("job ownership", () => {
  it("reports nothing for a job id this backend never issued", async () => {
    expect(await backend.getJob(randomUUID(), TENANT)).toBeNull();
    expect(await backend.getScanCheckpoint(randomUUID(), TENANT)).toBeNull();
    expect(await backend.isScanCancellationRequested(randomUUID(), "worker-1")).toBe(false);
  });

  it("refuses worker operations on a job that is queued rather than running", async () => {
    const live = session();
    await backend.createSession(live);
    const queued = await backend.enqueueScan(TENANT, live.id);
    await expect(backend.updateJobProgress(queued.id, "worker-1", "owners", 1, "detail")).rejects.toThrow(/not owned by this worker/);
    await expect(backend.failJob(queued.id, "worker-1", "boom")).rejects.toThrow(/not owned by this worker/);
    await expect(backend.completeJob(queued.id, "worker-1", snapshotFor(), new Date(0))).rejects.toThrow(/not owned by this worker/);
    await expect(backend.saveScanCheckpoint({ jobId: queued.id, tenantId: TENANT, payload: {}, updatedAt: "" }, "worker-1"))
      .rejects.toThrow(/not owned by this worker/);
  });

  it("refuses further work from the owning worker once cancellation was requested", async () => {
    const running = await runningJob("worker-1");
    await backend.requestScanCancellation(running.id, TENANT);
    // The worker still owns the job, but it is no longer running, so nothing may be written to it.
    await expect(backend.updateJobProgress(running.id, "worker-1", "owners", 1, "detail")).rejects.toThrow(/not owned by this worker/);
    await expect(backend.completeJob(running.id, "worker-1", snapshotFor(), new Date(0))).rejects.toThrow(/not owned by this worker/);
    await expect(backend.saveScanCheckpoint({ jobId: running.id, tenantId: TENANT, payload: {}, updatedAt: "" }, "worker-1"))
      .rejects.toThrow(/not owned by this worker/);
    expect((await backend.getJob(running.id, TENANT))?.stage).toBe("applications");
  });

  it("refuses worker operations on a job id that does not exist", async () => {
    await expect(backend.updateJobProgress(randomUUID(), "worker-1", "owners", 1, "d")).rejects.toThrow(/not owned by this worker/);
  });
});
