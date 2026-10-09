import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { PostgresBackend } from "./postgres";
import type { ThreatReview } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}
describe.skipIf(!connectionString)("real PostgreSQL boundaries", () => {
  const tenantId = randomUUID();
  const key = randomBytes(32);
  let backend: PostgresBackend;
  let sql: Pool;
  const sessionId = randomUUID();
  let lastScannedAt = 0;
  async function saveSnapshot(scannedAt = new Date(Math.max(Date.now(), lastScannedAt + 1)).toISOString()) {
    lastScannedAt = Math.max(lastScannedAt, Date.parse(scannedAt));
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("integration", tenantId);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic integration tenant" }, scannedAt };
    await backend.completeJob(job.id, "integration", snapshot, new Date(0));
    return snapshot;
  }
  beforeAll(async () => {
    backend = new PostgresBackend({ connectionString: connectionString!, encryptionKey: key });
    sql = new Pool({ connectionString });
    await backend.migrate(); await backend.migrate();
    await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-only", accessTokenExpiresAt: Date.now() + 3600000, sessionExpiresAt: Date.now() + 3600000, tokenCache: "synthetic" });
  });
  afterAll(async () => {
    if (sql) {
      for (const table of ["threat_reviews", "scan_checkpoints", "scan_jobs", "snapshots", "sessions", "auth_flows", "access_events"]) await sql.query(`DELETE FROM ${table} WHERE tenant_id=$1`, [tenantId]);
      await sql.end();
    }
    await backend?.close();
  });
  it("round-trips encrypted evidence and accepts exactly one competing decision", async () => {
    const snapshot = await saveSnapshot();
    expect((await backend.recentSnapshots(tenantId))[0]!.id).toBe(snapshot.id);
    expect(await backend.recentSnapshots(randomUUID())).toEqual([]);
    const review: ThreatReview = { tenantId, snapshotId: snapshot.id, findingId: "finding", disposition: "open", owner: "Original", expiresAt: null, assumption: "synthetic rationale", updatedAt: snapshot.scannedAt };
    const saved = await backend.upsertThreatReview(review, sessionId, null);
    const results = await Promise.allSettled([backend.upsertThreatReview({ ...review, owner: "First" }, sessionId, saved.revision), backend.upsertThreatReview({ ...review, owner: "Second" }, sessionId, saved.revision)]);
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter(r => r.status === "rejected")).toHaveLength(1);
    const stored = (await backend.getThreatReview(tenantId, snapshot.id, "finding"))!;
    expect(["First", "Second"]).toContain(stored.owner);
    const raw = (await sql.query("SELECT ciphertext FROM threat_reviews WHERE tenant_id=$1", [tenantId])).rows[0];
    expect(raw.ciphertext.toString()).not.toContain("synthetic rationale");
    await expect(backend.upsertThreatReview({ ...review, tenantId: randomUUID() }, sessionId, null)).rejects.toThrow("Review conflict");
  });
  it("filters expired evidence before idle maintenance physically removes it", async () => {
    const expired = await saveSnapshot(new Date(Date.now() - 31 * 86400000).toISOString());
    expect((await backend.recentSnapshots(tenantId)).some(s => s.id === expired.id)).toBe(false);
    await backend.pruneExpiredData(tenantId, new Date(Date.now() - 30 * 86400000));
    expect((await sql.query("SELECT id FROM snapshots WHERE tenant_id=$1 AND id=$2", [tenantId, expired.id])).rowCount).toBe(0);
  });
  it.each(["publication-first", "review-first"])("serializes overlapping snapshot publication and review writes (%s)", async order => {
    const old = await saveSnapshot();
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("integration", tenantId);
    const current = { ...old, id: randomUUID(), scannedAt: new Date(lastScannedAt + 1).toISOString() };
    lastScannedAt += 1;
    const review: ThreatReview = { tenantId, snapshotId: old.id, findingId: `racing-${order}`, disposition: "open", owner: "Reviewer", assumption: "Loaded before publication", expiresAt: null, updatedAt: "" };
    const blocker = await sql.connect();
    let publication: Promise<void> | undefined;
    let decision: Promise<PromiseSettledResult<ThreatReview>> | undefined;
    try {
      await blocker.query("BEGIN");
      await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended('snapshot-review:' || $1, 0))", [tenantId]);
      const pid = (await blocker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      const waitForBlocked = (count: number) => vi.waitFor(async () => {
        const result = await sql.query("SELECT count(*)::int AS count FROM pg_locks held JOIN pg_locks waiting ON held.locktype=waiting.locktype AND held.database IS NOT DISTINCT FROM waiting.database AND held.classid=waiting.classid AND held.objid=waiting.objid AND held.objsubid=waiting.objsubid WHERE held.pid=$1 AND held.locktype='advisory' AND held.granted AND NOT waiting.granted", [pid]);
        expect(result.rows[0].count).toBe(count);
      }, { timeout: 2000, interval: 10 });
      const publish = () => { publication = backend.completeJob(job.id, "integration", current, new Date(0)); };
      const decide = () => {
        decision = backend.upsertThreatReview(review, sessionId, null).then(value => ({ status: "fulfilled" as const, value }), reason => ({ status: "rejected" as const, reason }));
      };
      (order === "publication-first" ? publish : decide)();
      await waitForBlocked(1);
      (order === "publication-first" ? decide : publish)();
      await waitForBlocked(2);
      await blocker.query("COMMIT");
      await publication;
      const result = await decision;
      if (order === "publication-first") {
        expect(result).toMatchObject({ status: "rejected", reason: expect.objectContaining({ message: expect.stringContaining("Review conflict:") }) });
        expect(await backend.getThreatReview(tenantId, old.id, review.findingId)).toBeNull();
        expect((await sql.query("SELECT id FROM access_events WHERE tenant_id=$1 AND resource_type='threat_review' AND resource_id=$2", [tenantId, review.findingId])).rowCount).toBe(0);
      } else {
        expect(result).toMatchObject({ status: "fulfilled", value: { snapshotId: old.id } });
        expect(await backend.getThreatReview(tenantId, old.id, review.findingId)).toMatchObject({ owner: "Reviewer" });
      }
      expect((await backend.recentSnapshots(tenantId))[0]!.id).toBe(current.id);
      await expect(backend.upsertThreatReview({ ...review, findingId: `late-${order}` }, sessionId, null)).rejects.toThrow("Review conflict:");
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
      await Promise.allSettled([publication, decision]);
    }
  });
  it("does not expose expired decisions before cleanup, including as prior context", async () => {
    const old = await saveSnapshot();
    await backend.upsertThreatReview({ tenantId, snapshotId: old.id, findingId: "expired-review", disposition: "open", owner: "Expired owner", assumption: "Expired rationale", expiresAt: null, updatedAt: old.scannedAt }, null, null);
    const current = await saveSnapshot();
    expect(await backend.priorThreatReviews(tenantId, current.id, ["expired-review"])).toHaveLength(1);
    await sql.query("UPDATE snapshots SET scanned_at=now()-interval '31 days' WHERE tenant_id=$1 AND id=$2", [tenantId, old.id]);
    expect(await backend.getThreatReview(tenantId, old.id, "expired-review")).toBeNull();
    expect(await backend.priorThreatReviews(tenantId, current.id, ["expired-review"])).toEqual([]);
    expect(await backend.priorThreatReviews(tenantId, old.id, ["expired-review"])).toEqual([]);
    expect((await sql.query("SELECT finding_id FROM threat_reviews WHERE tenant_id=$1 AND snapshot_id=$2", [tenantId, old.id])).rowCount).toBe(1);
  });
  it("bulk reads only requested retained decisions from their exact tenant and snapshot", async () => {
    const snapshot = await saveSnapshot();
    const review: ThreatReview = { tenantId, snapshotId: snapshot.id, findingId: "first", disposition: "accepted", owner: "Original", assumption: "Synthetic rationale", expiresAt: null, updatedAt: "" };
    const first = await backend.upsertThreatReview(review, sessionId, null);
    const second = await backend.upsertThreatReview({ ...review, findingId: "second" }, sessionId, null);
    await backend.upsertThreatReview({ ...review, findingId: "unrequested" }, sessionId, null);
    const newer = await saveSnapshot();
    await backend.upsertThreatReview({ ...review, snapshotId: newer.id, owner: "Different scan" }, sessionId, null);
    expect(await backend.currentThreatReviews(tenantId, snapshot.id, ["second", "missing", "first", "second", ""])).toEqual([second, first]);
    expect(await backend.currentThreatReviews(tenantId, snapshot.id, [])).toEqual([]);
    expect(await backend.currentThreatReviews(tenantId, randomUUID(), ["first"])).toEqual([]);
    expect(await backend.currentThreatReviews(randomUUID(), snapshot.id, ["first"])).toEqual([]);
    await sql.query("UPDATE snapshots SET scanned_at=now()-interval '31 days' WHERE tenant_id=$1 AND id=$2", [tenantId, snapshot.id]);
    expect(await backend.currentThreatReviews(tenantId, snapshot.id, ["first", "second"])).toEqual([]);
    expect(await backend.currentThreatReviews(tenantId, newer.id, ["first"])).toEqual([expect.objectContaining({ owner: "Different scan" })]);
    expect((await sql.query("SELECT finding_id FROM threat_reviews WHERE tenant_id=$1 AND snapshot_id=$2", [tenantId, snapshot.id])).rowCount).toBe(3);
  });
  it("recovers expired leases and rejects writes by the old owner", async () => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("old", tenantId);
    expect(await backend.heartbeatJob(job.id, "wrong")).toBe(false);
    expect(await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 600000))).toBe(0);
    await sql.query("UPDATE scan_jobs SET updated_at=now()-interval '11 minutes',locked_at=now()-interval '11 minutes' WHERE id=$1 AND tenant_id=$2", [job.id, tenantId]);
    expect(await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 600000))).toBe(1);
    expect((await backend.claimNextJob("new", tenantId))!.id).toBe(job.id);
    expect(await backend.heartbeatJob(job.id, "old")).toBe(false);
    await expect(backend.updateJobProgress(job.id, "old", "applications", 1, "stale")).rejects.toThrow();
    await backend.failJob(job.id, "new", "Synthetic test complete");
  });
  it.each(["recovery", "cancellation"])("serializes a blocked checkpoint save with %s before changing ownership", async transition => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("old-checkpoint-worker", tenantId);
    const checkpoint = { jobId: job.id, tenantId, payload: { stage: "initial" }, updatedAt: "" };
    await backend.saveScanCheckpoint(checkpoint, "old-checkpoint-worker");
    await sql.query("UPDATE scan_jobs SET updated_at=now()-interval '11 minutes' WHERE id=$1", [job.id]);
    const blocker = await sql.connect();
    let write: Promise<void> | undefined;
    let change: Promise<unknown> | undefined;
    try {
      await blocker.query("BEGIN");
      await blocker.query("SELECT job_id FROM scan_checkpoints WHERE job_id=$1 FOR UPDATE", [job.id]);
      const blockerPid = (await blocker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      write = backend.saveScanCheckpoint({ ...checkpoint, payload: { stage: "old" } }, "old-checkpoint-worker");
      let writerPid = 0;
      await vi.waitFor(async () => {
        const waiting = await sql.query("SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%INSERT INTO scan_checkpoints%'", [blockerPid]);
        expect(waiting.rows).toHaveLength(1);
        writerPid = waiting.rows[0].pid;
      }, { timeout: 2000, interval: 10 });
      change = transition === "recovery"
        ? backend.recoverStaleJobs(tenantId, new Date(Date.now() - 600000))
        : backend.requestScanCancellation(job.id, tenantId);
      // Ownership must remain locked until the checkpoint statement finishes;
      // otherwise its stale INSERT SELECT can overwrite a recovered worker.
      await vi.waitFor(async () => {
        const waiting = await sql.query("SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%UPDATE scan_jobs%'", [writerPid]);
        expect(waiting.rows).toHaveLength(1);
      }, { timeout: 2000, interval: 10 });
      await blocker.query("COMMIT");
      await write;
      await change;
      if (transition === "recovery") {
        expect((await backend.claimNextJob("new-checkpoint-worker", tenantId))!.id).toBe(job.id);
        await backend.saveScanCheckpoint({ ...checkpoint, payload: { stage: "new" } }, "new-checkpoint-worker");
        await expect(backend.saveScanCheckpoint(checkpoint, "old-checkpoint-worker")).rejects.toThrow("not owned by this worker");
        expect((await backend.getScanCheckpoint(job.id, tenantId))!.payload).toEqual({ stage: "new" });
        await backend.failJob(job.id, "new-checkpoint-worker", "Synthetic test complete");
      } else {
        await backend.cancelJob(job.id, "old-checkpoint-worker");
        await expect(backend.saveScanCheckpoint(checkpoint, "old-checkpoint-worker")).rejects.toThrow("not owned by this worker");
        expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
      }
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
      await Promise.allSettled([write, change]);
      const current = await backend.getJob(job.id, tenantId);
      if (current?.status === "queued") await backend.requestScanCancellation(job.id, tenantId);
      else if (current?.status === "cancel_requested") await backend.cancelJob(job.id, "old-checkpoint-worker");
    }
  });
  it.each(["idle", "completion"])("%s physically deletes expired review ciphertext", async (mode) => {
    const old = await saveSnapshot();
    await backend.upsertThreatReview({ tenantId, snapshotId: old.id, findingId: "purge", disposition: "open", owner: "Owner", expiresAt: null, assumption: "Synthetic", updatedAt: "" }, null, null);
    await sql.query("UPDATE snapshots SET scanned_at=now()-interval '31 days' WHERE id=$1 AND tenant_id=$2", [old.id, tenantId]);
    if (mode === "idle") await backend.pruneExpiredData(tenantId, new Date(Date.now() - 30 * 86400000));
    else {
      const job = await backend.enqueueScan(tenantId, sessionId); await backend.claimNextJob("integration", tenantId);
      await backend.completeJob(job.id, "integration", { ...old, id: randomUUID(), scannedAt: new Date().toISOString() }, new Date(Date.now() - 30 * 86400000));
    }
    expect((await sql.query("SELECT finding_id FROM threat_reviews WHERE tenant_id=$1 AND snapshot_id=$2", [tenantId, old.id])).rowCount).toBe(0);
  });
  it("physically removes expired auth records during idle maintenance", async () => {
    const expiredId = randomUUID(); const freshId = randomUUID();
    for (const [id, expiresAt] of [[expiredId, Date.now() - 1000], [freshId, Date.now() + 60000]] as const) {
      await backend.createAuthFlow({ id, tenantId, state: "synthetic", verifier: "synthetic", expiresAt });
      await backend.createSession({ id, tenantId, account: {}, accessToken: "synthetic", tokenCache: "synthetic", accessTokenExpiresAt: expiresAt, sessionExpiresAt: expiresAt });
    }
    await backend.pruneExpiredData(tenantId, new Date(0));
    for (const table of ["auth_flows", "sessions"]) {
      const result = await sql.query(`SELECT id FROM ${table} WHERE tenant_id=$1 AND id=ANY($2::uuid[])`, [tenantId, [expiredId, freshId]]);
      expect(result.rows).toEqual([{ id: freshId }]);
    }
  });
  it("renews both lease timestamps for the owner, including while cancellation is pending", async () => {
    const job = await backend.enqueueScan(tenantId, sessionId); await backend.claimNextJob("owner", tenantId);
    await sql.query("UPDATE scan_jobs SET updated_at=now()-interval '9 minutes',locked_at=now()-interval '9 minutes' WHERE id=$1 AND tenant_id=$2", [job.id, tenantId]);
    expect(await backend.heartbeatJob(job.id, "owner")).toBe(true);
    const row = (await sql.query("SELECT updated_at,locked_at FROM scan_jobs WHERE id=$1", [job.id])).rows[0];
    expect(row.locked_at.getTime()).toBeGreaterThan(Date.now() - 5000);
    expect(row.updated_at.getTime()).toBe(row.locked_at.getTime());
    await backend.requestScanCancellation(job.id, tenantId);
    expect(await backend.heartbeatJob(job.id, "owner")).toBe(true);
    await backend.cancelJob(job.id, "owner");
    expect(await backend.heartbeatJob(job.id, "owner")).toBe(false);
  });

});
