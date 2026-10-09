import { randomUUID } from "node:crypto";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryBackend } from "./memory";
import type { DurableSession, ScanJob } from "./types";

describe("session authorization at snapshot publication", () => {
  const now = Date.parse("2026-10-09T12:00:00Z");
  const tenantId = "synthetic-publication-tenant";
  const workerId = "synthetic-publication-worker";
  let backend: MemoryBackend;
  let session: DurableSession;
  let job: ScanJob;
  let snapshot: TenantSnapshot;

  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    backend = new MemoryBackend();
    session = { id: randomUUID(), tenantId, account: {}, accessToken: "synthetic-token", tokenCache: "synthetic-cache", accessTokenExpiresAt: now + 100, sessionExpiresAt: now + 60_000 };
    await backend.createSession(session);
    job = await backend.enqueueScan(tenantId, session.id);
    expect((await backend.claimNextJob(workerId, tenantId))?.id).toBe(job.id);
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { completedStages: ["applications"], syntheticEvidence: "unpublished" }, updatedAt: "" }, workerId);
    snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic publication" }, scannedAt: new Date().toISOString() };
    expect(await backend.getScanAccessState(job.id, workerId, tenantId)).toBe("running");
  });

  afterEach(() => vi.useRealTimers());

  async function expectPublicationRejected() {
    const jobBefore = await backend.getJob(job.id, tenantId);
    const checkpointBefore = await backend.getScanCheckpoint(job.id, tenantId);
    const eventsBefore = await backend.recentAccessEvents(tenantId);
    await expect(backend.completeJob(job.id, workerId, snapshot, new Date(0))).rejects.toThrow("The scan job is not owned by this worker.");
    expect(await backend.getJob(job.id, tenantId)).toEqual(jobBefore);
    expect(jobBefore).toMatchObject({ status: "running", workerId, snapshotId: null, finishedAt: null });
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toEqual(checkpointBefore);
    expect(checkpointBefore).not.toBeNull();
    expect(await backend.recentSnapshots(tenantId)).toEqual([]);
    expect(await backend.recentAccessEvents(tenantId)).toEqual(eventsBefore);
  }

  it("publishes one millisecond before session expiry and removes the finished checkpoint", async () => {
    vi.setSystemTime(session.sessionExpiresAt - 1);
    await backend.completeJob(job.id, workerId, snapshot, new Date(0));
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", snapshotId: snapshot.id, workerId: null });
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
    expect(await backend.recentSnapshots(tenantId)).toEqual([snapshot]);
  });

  it.each([0, 1])("rechecks session expiry %i ms after the deadline despite the previous running guard", async offset => {
    vi.setSystemTime(session.sessionExpiresAt + offset);
    await expectPublicationRejected();
  });

  it("rejects publication after logout even when collection previously had a running guard", async () => {
    await backend.deleteSession(session.id, tenantId);
    await expectPublicationRejected();
  });

  it("does not publish using a session ID that now belongs to another tenant", async () => {
    await backend.createSession({ ...session, tenantId: "another-synthetic-tenant" });
    await expectPublicationRejected();
  });
});
