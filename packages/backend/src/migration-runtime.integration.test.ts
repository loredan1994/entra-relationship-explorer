import { randomBytes, randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";
import { createIsolatedTestDatabase } from "./test-support";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("migration coordination with runtime transactions", () => {
  const tenantId = randomUUID();
  const applicationName = `runtime-migration-${tenantId}`;
  const sessionId = randomUUID();
  let database: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let backend: PostgresBackend;
  let sql: Pool;
  beforeAll(async () => {
    database = await createIsolatedTestDatabase(connectionString!, Pool);
    const url = new URL(database.connectionString);
    url.searchParams.set("application_name", applicationName);
    backend = new PostgresBackend({ connectionString: url.toString(), encryptionKey: randomBytes(32) });
    sql = database.sql;
    await backend.migrate();
    await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic", tokenCache: "synthetic", accessTokenExpiresAt: Date.now() + 3600000, sessionExpiresAt: Date.now() + 3600000 });
  });
  afterAll(async () => {
    try { await backend?.close(); }
    finally { await database?.close(); }
  });

  it.each(["publication", "pruning"] as const)("waits before DDL while %s already owns a runtime transaction", async operation => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("runtime-worker", tenantId);
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { tenantId, tenantLabel: "Synthetic migration runtime" }, scannedAt: new Date().toISOString() };
    const gate = await sql.connect();
    let work: Promise<unknown> | undefined;
    let migration: Promise<unknown> | undefined;
    try {
      await gate.query("BEGIN");
      await gate.query("SELECT pg_advisory_xact_lock(hashtextextended('snapshot-review:' || $1, 0))", [tenantId]);
      work = operation === "publication" ? backend.completeJob(job.id, "runtime-worker", snapshot, new Date(0)) : backend.pruneExpiredData(tenantId, new Date(0));
      await vi.waitFor(async () => {
        const pending = await sql.query("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory' AND query LIKE '%snapshot-review:%'", [applicationName]);
        expect(pending.rows).toHaveLength(1);
      }, { timeout: 3000, interval: 10 });
      let migrationFinished = false;
      migration = backend.migrate().then(() => { migrationFinished = true; });
      await vi.waitFor(async () => {
        const pending = await sql.query("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND query LIKE '%entra-explorer:migrations%' AND wait_event='advisory'", [applicationName]);
        expect(migrationFinished).toBe(false);
        expect(pending.rows).toHaveLength(1);
        const locks = await sql.query("SELECT relation::regclass::text FROM pg_locks WHERE pid=$1 AND locktype='relation' AND granted", [pending.rows[0].pid]);
        expect(locks.rows).toEqual([]);
      }, { timeout: 1500, interval: 10 });
      await gate.query("COMMIT");
      await Promise.all([work, migration]);
      if (operation === "publication") expect((await backend.recentSnapshots(tenantId)).some(item => item.id === snapshot.id)).toBe(true);
      else await backend.failJob(job.id, "runtime-worker", "Synthetic test complete");
      expect(await backend.getSession(sessionId, tenantId)).not.toBeNull();
    } finally {
      await gate.query("ROLLBACK");
      gate.release();
      await Promise.allSettled([work, migration]);
      const current = await backend.getJob(job.id, tenantId);
      if (current?.status === "running") await backend.failJob(job.id, "runtime-worker", "Synthetic cleanup");
    }
  });

  it.each(["checkpoint", "logout"] as const)("waits before table writes when a migration gate already owns the schema (%s)", async operation => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("runtime-worker", tenantId);
    const gate = await sql.connect();
    let work: Promise<unknown> | undefined;
    try {
      await gate.query("BEGIN");
      await gate.query("SELECT pg_advisory_xact_lock(hashtextextended('entra-explorer:migrations', 0))");
      let finished = false;
      work = (operation === "checkpoint"
        ? backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { syntheticEvidence: "pending" }, updatedAt: "" }, "runtime-worker")
        : backend.deleteSession(sessionId, tenantId)).then(() => { finished = true; });
      await vi.waitFor(async () => {
        const pending = await sql.query("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [applicationName]);
        expect(finished).toBe(false);
        expect(pending.rows).toHaveLength(1);
      }, { timeout: 1500, interval: 10 });
      expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
      expect(await backend.getSession(sessionId, tenantId)).not.toBeNull();
      await gate.query("COMMIT");
      await work;
      if (operation === "checkpoint") expect(await backend.getScanCheckpoint(job.id, tenantId)).toMatchObject({ payload: { syntheticEvidence: "pending" } });
      else expect(await backend.getSession(sessionId, tenantId)).toBeNull();
    } finally {
      await gate.query("ROLLBACK");
      gate.release();
      await Promise.allSettled([work]);
      await backend.failJob(job.id, "runtime-worker", "Synthetic cleanup");
    }
  });

  it("rejects a session that expires while enqueue waits for the migration gate", async () => {
    const expiringSessionId = randomUUID();
    await backend.createSession({ id: expiringSessionId, tenantId, account: {}, accessToken: "synthetic", tokenCache: "synthetic", accessTokenExpiresAt: Date.now() + 60000, sessionExpiresAt: Date.now() + 60000 });
    const gate = await sql.connect();
    let enqueue: Promise<PromiseSettledResult<unknown>> | undefined;
    try {
      await gate.query("BEGIN");
      await gate.query("SELECT pg_advisory_xact_lock(hashtextextended('entra-explorer:migrations', 0))");
      enqueue = backend.enqueueScan(tenantId, expiringSessionId).then(value => ({ status: "fulfilled", value }), reason => ({ status: "rejected", reason }));
      await vi.waitFor(async () => {
        const pending = await sql.query("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [applicationName]);
        expect(pending.rows).toHaveLength(1);
      }, { timeout: 1500, interval: 10 });
      // Expire after BEGIN, so PostgreSQL's transaction-start now() is too old.
      await sql.query("UPDATE sessions SET expires_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2", [expiringSessionId, tenantId]);
      await gate.query("COMMIT");
      expect(await enqueue).toMatchObject({ status: "rejected", reason: { message: "A valid tenant session is required." } });
      expect((await sql.query("SELECT id FROM scan_jobs WHERE session_id=$1", [expiringSessionId])).rowCount).toBe(0);
    } finally {
      await gate.query("ROLLBACK");
      gate.release();
      await enqueue;
    }
  });
});
