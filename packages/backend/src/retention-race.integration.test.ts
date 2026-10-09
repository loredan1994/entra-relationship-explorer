import { randomBytes, randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";
import { blockedTransactions, createIsolatedTestDatabase } from "./test-support";
import type { ThreatReview } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("retention while a review crosses its snapshot expiry", () => {
  const tenantId = randomUUID();
  const sessionId = randomUUID();
  const applicationName = `entra-retention-race-${tenantId}`;
  let database: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let backend: PostgresBackend;
  let unrelatedDatabase: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let unrelatedBackend: PostgresBackend;
  let sql: Pool;

  beforeAll(async () => {
    database = await createIsolatedTestDatabase(connectionString!, Pool);
    const backendUrl = new URL(database.connectionString);
    backendUrl.searchParams.set("application_name", applicationName);
    backend = new PostgresBackend({ connectionString: backendUrl.toString(), encryptionKey: randomBytes(32) });
    unrelatedDatabase = await createIsolatedTestDatabase(connectionString!, Pool);
    unrelatedBackend = new PostgresBackend({ connectionString: unrelatedDatabase.connectionString, encryptionKey: randomBytes(32) });
    sql = database.sql;
    await Promise.all([backend.migrate(), unrelatedBackend.migrate()]);
    await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-only", tokenCache: "synthetic-only", accessTokenExpiresAt: Date.now() + 3600000, sessionExpiresAt: Date.now() + 3600000 });
  });

  afterAll(async () => {
    try { await Promise.all([backend?.close(), unrelatedBackend?.close()]); }
    finally { await Promise.all([database?.close(), unrelatedDatabase?.close()]); }
  });

  it("deletes a newly committed decision together with its expired snapshot instead of orphaning ciphertext", async () => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("retention-test", tenantId);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic retention race" }, scannedAt: new Date().toISOString() };
    await backend.completeJob(job.id, "retention-test", snapshot, new Date(0));
    const review: ThreatReview = { tenantId, snapshotId: snapshot.id, findingId: "expiry-boundary", disposition: "open", owner: "Synthetic reviewer", assumption: "Pending review at the retention boundary", expiresAt: null, updatedAt: "" };
    const advisoryGate = await sql.connect();
    const snapshotGate = await sql.connect();
    let decision: Promise<PromiseSettledResult<ThreatReview>> | undefined;
    let pruning: Promise<PromiseSettledResult<void>> | undefined;
    try {
      await advisoryGate.query("BEGIN");
      await advisoryGate.query("SELECT pg_advisory_xact_lock(hashtextextended('snapshot-review:' || $1, 0))", [tenantId]);
      const advisoryPid = await pid(advisoryGate);
      decision = settle(backend.upsertThreatReview(review, sessionId, null));
      const pendingReview = await vi.waitFor(async () => {
        const result = await blockedTransactions(sql, applicationName, [advisoryPid]);
        expect(result.rows).toHaveLength(1);
        return result.rows[0]!;
      }, { timeout: 3000, interval: 10 });

      // Model expiry after this review began without waiting thirty days or
      // changing the process clock. PostgreSQL now() stays at transaction start.
      await sql.query("UPDATE snapshots SET scanned_at=$3::timestamptz-interval '30 days'+interval '1 millisecond' WHERE tenant_id=$1 AND id=$2", [tenantId, snapshot.id, pendingReview.started_at]);
      const retainAfter = await vi.waitFor(async () => {
        const result = await sql.query<{ expired: boolean; cutoff: Date }>("SELECT clock_timestamp()>$1::timestamptz+interval '2 milliseconds' AS expired,clock_timestamp()-interval '30 days' AS cutoff", [pendingReview.started_at]);
        expect(result.rows[0]!.expired).toBe(true);
        return result.rows[0]!.cutoff;
      }, { timeout: 3000, interval: 10 });
      await snapshotGate.query("BEGIN");
      await snapshotGate.query("SELECT id FROM snapshots WHERE tenant_id=$1 AND id=$2 FOR UPDATE", [tenantId, snapshot.id]);
      const snapshotPid = await pid(snapshotGate);
      pruning = settle(backend.pruneExpiredData(tenantId, retainAfter));
      await vi.waitFor(async () => {
        const result = await blockedTransactions(sql, applicationName, [advisoryPid, snapshotPid], pendingReview.pid);
        expect(result.rows).toHaveLength(1);
      }, { timeout: 3000, interval: 10 });

      // A correct implementation queues pruning behind the review. Without
      // that serialization, it already deleted reviews and is at snapshot DELETE.
      await advisoryGate.query("COMMIT");
      expect(await decision).toMatchObject({ status: "fulfilled", value: { snapshotId: snapshot.id } });
      await snapshotGate.query("COMMIT");
      expect(await pruning).toEqual({ status: "fulfilled", value: undefined });

      expect((await sql.query("SELECT id FROM snapshots WHERE tenant_id=$1 AND id=$2", [tenantId, snapshot.id])).rowCount).toBe(0);
      expect((await sql.query("SELECT finding_id FROM threat_reviews WHERE tenant_id=$1 AND snapshot_id=$2", [tenantId, snapshot.id])).rowCount).toBe(0);
      expect(await backend.getThreatReview(tenantId, snapshot.id, review.findingId)).toBeNull();
    } finally {
      await advisoryGate.query("ROLLBACK");
      await snapshotGate.query("ROLLBACK");
      advisoryGate.release();
      snapshotGate.release();
      await Promise.allSettled([decision, pruning]);
    }
  }, 15000);

  it("allows publication and expired-session pruning to finish without a job/advisory lock deadlock", async () => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("publishing-worker", tenantId);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic publication race" }, scannedAt: new Date().toISOString() };
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { stage: "synthetic-completed-read" }, updatedAt: "" }, "publishing-worker");
    await sql.query("UPDATE sessions SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2", [tenantId, sessionId]);
    // Force unrelated startup cleanup before establishing this test's row gate.
    const unrelatedSessionId = randomUUID();
    await unrelatedBackend.createSession({ id: unrelatedSessionId, tenantId, account: {}, accessToken: "synthetic-only", tokenCache: "synthetic-only", accessTokenExpiresAt: Date.now() - 1000, sessionExpiresAt: Date.now() - 1000 });
    await Promise.all([unrelatedBackend.migrate(), unrelatedBackend.migrate()]);
    expect((await unrelatedDatabase.sql.query("SELECT id FROM sessions WHERE id=$1", [unrelatedSessionId])).rows).toEqual([]);
    const sessionGate = await sql.connect();
    let pruning: Promise<PromiseSettledResult<void>> | undefined;
    let publication: Promise<PromiseSettledResult<void>> | undefined;
    try {
      await sessionGate.query("BEGIN");
      await sessionGate.query("SELECT id FROM sessions WHERE tenant_id=$1 AND id=$2 FOR UPDATE", [tenantId, sessionId]);
      const sessionPid = await pid(sessionGate);
      pruning = settle(backend.pruneExpiredData(tenantId, new Date(0)));
      const pruningPid = await vi.waitFor(async () => {
        const result = await blockedTransactions(sql, applicationName, [sessionPid]);
        expect(result.rows).toHaveLength(1);
        return result.rows[0]!.pid;
      }, { timeout: 3000, interval: 10 });
      publication = settle(backend.completeJob(job.id, "publishing-worker", snapshot, new Date(0)));
      await vi.waitFor(async () => {
        const result = await blockedTransactions(sql, applicationName, [pruningPid]);
        expect(result.rows).toHaveLength(1);
      }, { timeout: 3000, interval: 10 });

      // Session deletion sets the active job's session_id to null. Publication
      // must not hold that job row while waiting for pruning's advisory lock.
      await sessionGate.query("COMMIT");
      expect(await pruning).toEqual({ status: "fulfilled", value: undefined });
      expect(await publication).toMatchObject({ status: "rejected", reason: expect.objectContaining({ message: "The scan job is not owned by this worker." }) });
      expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", sessionId: null, snapshotId: null });
      expect((await backend.recentSnapshots(tenantId)).map(item => item.id)).not.toContain(snapshot.id);
      expect(await backend.getScanCheckpoint(job.id, tenantId)).toMatchObject({ payload: { stage: "synthetic-completed-read" } });
      expect(await backend.getSession(sessionId, tenantId)).toBeNull();
    } finally {
      await sessionGate.query("ROLLBACK");
      sessionGate.release();
      await Promise.allSettled([pruning, publication]);
    }
  }, 15000);
});

async function pid(client: PoolClient): Promise<number> { return (await client.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid; }
function settle<T>(promise: Promise<T>): Promise<PromiseSettledResult<T>> { return promise.then(value => ({ status: "fulfilled" as const, value }), reason => ({ status: "rejected" as const, reason })); }
