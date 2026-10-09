import { randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryBackend } from "./memory";
import type { DurableSession, ScanJob } from "./types";

describe("worker access to a claimed scan", () => {
  const now = Date.parse("2026-10-09T12:00:00Z");
  const tenantId = "synthetic-scan-access-tenant";
  const workerId = "synthetic-scan-owner";
  let backend: MemoryBackend;
  let session: DurableSession;
  let job: ScanJob;

  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    backend = new MemoryBackend();
    session = { id: randomUUID(), tenantId, account: {}, accessToken: "synthetic-token", tokenCache: "synthetic-cache", accessTokenExpiresAt: now + 100, sessionExpiresAt: now + 60_000 };
    await backend.createSession(session);
    job = await backend.enqueueScan(tenantId, session.id);
  });

  afterEach(() => vi.useRealTimers());

  const state = () => backend.getScanAccessState(job.id, workerId, tenantId);
  async function claim() { expect((await backend.claimNextJob(workerId, tenantId))?.id).toBe(job.id); }

  it("permits the current owner without changing its lease, session, or job progress", async () => {
    await claim();
    const before = await backend.getJob(job.id, tenantId);
    vi.setSystemTime(now + 500);
    expect(await state()).toBe("running");
    expect(await backend.getJob(job.id, tenantId)).toEqual(before);
    // An expired Graph access token can still be refreshed within a valid login session.
    expect(await backend.getSession(session.id, tenantId)).toEqual(session);
  });

  it.each([-1, 0, 1])("stops reads at the session deadline (%i ms from expiry)", async offset => {
    await claim();
    vi.setSystemTime(session.sessionExpiresAt + offset);
    expect(await state()).toBe(offset < 0 ? "running" : "session_unavailable");
    expect((await backend.getJob(job.id, tenantId))?.status).toBe("running");
  });

  it("detects logout without letting another tenant revoke the owning session", async () => {
    await claim();
    await backend.deleteSession(session.id, "another-tenant");
    expect(await state()).toBe("running");
    await backend.deleteSession(session.id, tenantId);
    expect(await state()).toBe("session_unavailable");
  });

  it("rejects a session ID that now belongs to another tenant", async () => {
    await claim();
    await backend.createSession({ ...session, tenantId: "another-tenant" });
    expect(await state()).toBe("session_unavailable");
  });

  it.each(["valid", "expired", "revoked"])("lets the owner finish cancellation with a %s session", async sessionState => {
    await claim();
    await backend.requestScanCancellation(job.id, tenantId);
    if (sessionState === "expired") vi.setSystemTime(session.sessionExpiresAt);
    if (sessionState === "revoked") await backend.deleteSession(session.id, tenantId);
    expect(await state()).toBe("cancel_requested");
    expect(await backend.getScanAccessState(job.id, "another-worker", tenantId)).toBe("lease_lost");
    expect(await backend.getScanAccessState(job.id, workerId, "another-tenant")).toBe("lease_lost");
  });

  it.each(["job", "worker", "tenant"])("rejects a mismatched %s even when the owner has a valid session", async mismatch => {
    await claim();
    expect(await backend.getScanAccessState(mismatch === "job" ? randomUUID() : job.id, mismatch === "worker" ? "another-worker" : workerId, mismatch === "tenant" ? "another-tenant" : tenantId)).toBe("lease_lost");
    expect(await state()).toBe("running");
  });

  it("does not grant access before any worker has claimed a queued scan", async () => {
    expect(await state()).toBe("lease_lost");
    expect((await backend.getJob(job.id, tenantId))?.status).toBe("queued");
  });

  it.each(["complete", "failed", "cancelled"])("revokes access after a scan is %s", async outcome => {
    await claim();
    if (outcome === "complete") {
      await backend.completeJob(job.id, workerId, { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic access check" }, scannedAt: new Date().toISOString() }, new Date(0));
    } else if (outcome === "failed") {
      await backend.failJob(job.id, workerId, "Synthetic collection interruption");
    } else {
      await backend.requestScanCancellation(job.id, tenantId);
      await backend.cancelJob(job.id, workerId);
    }
    expect(await state()).toBe("lease_lost");
    expect((await backend.getJob(job.id, tenantId))?.status).toBe(outcome);
  });

  it("revokes the old worker after recovery and grants only the replacement worker", async () => {
    await claim();
    vi.setSystemTime(now + 1000);
    expect(await backend.recoverStaleJobs(tenantId, new Date(now + 1))).toBe(1);
    expect(await state()).toBe("lease_lost");
    expect((await backend.claimNextJob("replacement-worker", tenantId))?.id).toBe(job.id);
    expect(await state()).toBe("lease_lost");
    expect(await backend.getScanAccessState(job.id, "replacement-worker", tenantId)).toBe("running");
  });
});
