import { randomBytes, randomUUID } from "node:crypto";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";
import { blockedTransactions, createIsolatedTestDatabase } from "./test-support";
import type { DurableSession, ScanJob } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("PostgreSQL session authorization at snapshot publication", () => {
  const applicationName = `entra-publication-session-${randomUUID()}`;
  const workerId = "synthetic-publication-worker";
  let database: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let backend: PostgresBackend;
  let unrelatedDatabase: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let unrelatedBackend: PostgresBackend;
  let sql: Pool;
  let tenantId: string;
  let session: DurableSession;
  let job: ScanJob;
  let snapshot: TenantSnapshot;

  beforeAll(async () => {
    database = await createIsolatedTestDatabase(connectionString!, Pool);
    const backendUrl = new URL(database.connectionString);
    backendUrl.searchParams.set("application_name", applicationName);
    backend = new PostgresBackend({ connectionString: backendUrl.toString(), encryptionKey: randomBytes(32) });
    unrelatedDatabase = await createIsolatedTestDatabase(connectionString!, Pool);
    unrelatedBackend = new PostgresBackend({ connectionString: unrelatedDatabase.connectionString, encryptionKey: randomBytes(32) });
    sql = database.sql;
    await Promise.all([backend.migrate(), unrelatedBackend.migrate()]);
  });

  beforeEach(async () => {
    tenantId = randomUUID();
    session = { id: randomUUID(), tenantId, account: {}, accessToken: "synthetic-token", tokenCache: "synthetic-cache", accessTokenExpiresAt: Date.now() - 1000, sessionExpiresAt: Date.now() + 3_600_000 };
    await backend.createSession(session);
    job = await backend.enqueueScan(tenantId, session.id);
    expect((await backend.claimNextJob(workerId, tenantId))?.id).toBe(job.id);
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { completedStages: ["applications"], syntheticEvidence: "unpublished" }, updatedAt: "" }, workerId);
    snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic publication" }, scannedAt: new Date().toISOString() };
    expect(await backend.getScanAccessState(job.id, workerId, tenantId)).toBe("running");
  });

  afterAll(async () => {
    try { await Promise.all([backend?.close(), unrelatedBackend?.close()]); }
    finally { await Promise.all([database?.close(), unrelatedDatabase?.close()]); }
  });

  async function expectUnpublished() {
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", workerId, snapshotId: null, finishedAt: null });
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toMatchObject({ payload: { completedStages: ["applications"], syntheticEvidence: "unpublished" } });
    expect(await backend.recentSnapshots(tenantId)).toEqual([]);
    expect(await backend.recentAccessEvents(tenantId)).toEqual([expect.objectContaining({ action: "enqueue", resourceType: "scan_job", resourceId: job.id })]);
  }

  it("publishes under a valid same-tenant session and records exactly one snapshot creation", async () => {
    await backend.completeJob(job.id, workerId, snapshot, new Date(0));
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", snapshotId: snapshot.id, workerId: null });
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
    expect(await backend.recentSnapshots(tenantId)).toEqual([snapshot]);
    expect((await backend.recentAccessEvents(tenantId)).filter(event => event.action === "create")).toEqual([expect.objectContaining({ resourceType: "snapshot", resourceId: snapshot.id, sessionId: session.id })]);
  });

  it.each(["expired", "revoked", "null", "foreign"])("rejects a %s session at publication despite the earlier running guard", async invalid => {
    if (invalid === "expired") await sql.query("UPDATE sessions SET expires_at=clock_timestamp()-interval '1 millisecond' WHERE id=$1 AND tenant_id=$2", [session.id, tenantId]);
    if (invalid === "revoked") await backend.deleteSession(session.id, tenantId);
    if (invalid === "null") await sql.query("UPDATE scan_jobs SET session_id=NULL WHERE id=$1 AND tenant_id=$2", [job.id, tenantId]);
    if (invalid === "foreign") {
      const foreignTenantId = randomUUID();
      const foreignSessionId = randomUUID();
      await backend.createSession({ ...session, id: foreignSessionId, tenantId: foreignTenantId });
      await sql.query("UPDATE scan_jobs SET session_id=$1 WHERE id=$2 AND tenant_id=$3", [foreignSessionId, job.id, tenantId]);
    }
    const jobBefore = await backend.getJob(job.id, tenantId);
    const checkpointBefore = await backend.getScanCheckpoint(job.id, tenantId);
    // Force another suite's startup cleanup into the exact rollback-check window.
    if (invalid === "expired") {
      const unrelatedSession = { ...session, id: randomUUID(), sessionExpiresAt: Date.now() - 1000 };
      await unrelatedBackend.createSession(unrelatedSession);
      await Promise.all([unrelatedBackend.migrate(), unrelatedBackend.migrate()]);
      expect((await unrelatedDatabase.sql.query("SELECT id FROM sessions WHERE id=$1", [unrelatedSession.id])).rows).toEqual([]);
    }
    await expect(backend.completeJob(job.id, workerId, snapshot, new Date(0))).rejects.toThrow("The scan job is not owned by this worker.");
    expect(await backend.getJob(job.id, tenantId)).toEqual(jobBefore);
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toEqual(checkpointBefore);
    await expectUnpublished();
  });

  it("rejects publication that waited for a concurrent logout to commit", async () => {
    const blocker = await sql.connect();
    let publication: Promise<PromiseSettledResult<void>> | undefined;
    try {
      await blocker.query("BEGIN");
      const blockerPid = (await blocker.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid;
      // ON DELETE SET NULL holds the job row until this logout commits.
      await blocker.query("DELETE FROM sessions WHERE id=$1 AND tenant_id=$2", [session.id, tenantId]);
      publication = settle(backend.completeJob(job.id, workerId, snapshot, new Date(0)));
      await waitForBlockedPublication(blockerPid);
      await blocker.query("COMMIT");
      expect(await publication).toMatchObject({ status: "rejected", reason: new Error("The scan job is not owned by this worker.") });
      expect((await backend.getJob(job.id, tenantId))?.sessionId).toBeNull();
      await expectUnpublished();
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
      await publication;
    }
  }, 15_000);

  it("rechecks actual session expiry after waiting for a job lock", async () => {
    const blocker = await sql.connect();
    let publication: Promise<PromiseSettledResult<void>> | undefined;
    try {
      await blocker.query("BEGIN");
      const blockerPid = (await blocker.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid;
      await blocker.query("SELECT id FROM scan_jobs WHERE id=$1 AND tenant_id=$2 FOR UPDATE", [job.id, tenantId]);
      publication = settle(backend.completeJob(job.id, workerId, snapshot, new Date(0)));
      const pending = await waitForBlockedPublication(blockerPid);
      // The session was valid at transaction start but expires before the lock is
      // released. A stale now() timestamp must not authorize publication.
      await sql.query("UPDATE sessions SET expires_at=$3::timestamptz+interval '1 millisecond' WHERE id=$1 AND tenant_id=$2", [session.id, tenantId, pending.started_at]);
      await vi.waitFor(async () => {
        const result = await sql.query<{ expired: boolean }>("SELECT clock_timestamp()>$1::timestamptz+interval '1 millisecond' AS expired", [pending.started_at]);
        expect(result.rows[0]!.expired).toBe(true);
      }, { timeout: 3000, interval: 10 });
      await blocker.query("COMMIT");
      expect(await publication).toMatchObject({ status: "rejected", reason: new Error("The scan job is not owned by this worker.") });
      await expectUnpublished();
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
      await publication;
    }
  }, 15_000);

  function waitForBlockedPublication(blockerPid: number) {
    return vi.waitFor(async () => {
      const result = await blockedTransactions(sql, applicationName, [blockerPid]);
      expect(result.rows).toHaveLength(1);
      return result.rows[0]!;
    }, { timeout: 3000, interval: 10 });
  }
});

function settle<T>(promise: Promise<T>): Promise<PromiseSettledResult<T>> {
  return promise.then(value => ({ status: "fulfilled" as const, value }), reason => ({ status: "rejected" as const, reason }));
}
