import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresBackend } from "./postgres";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("atomic scan enqueue and access record", () => {
  const tenantId = randomUUID();
  const sessionId = randomUUID();
  let backend: PostgresBackend;
  let sql: Pool;
  const createSession = async (id: string) => backend.createSession({ id, tenantId, account: {}, accessToken: "synthetic-only", tokenCache: "synthetic-only", accessTokenExpiresAt: Date.now() + 3600000, sessionExpiresAt: Date.now() + 3600000 });

  beforeAll(async () => {
    backend = new PostgresBackend({ connectionString: connectionString!, encryptionKey: randomBytes(32) });
    sql = new Pool({ connectionString });
    await backend.migrate();
    await createSession(sessionId);
  });
  afterAll(async () => {
    if (sql) {
      for (const table of ["scan_checkpoints", "scan_jobs", "sessions", "access_events"]) await sql.query(`DELETE FROM ${table} WHERE tenant_id=$1`, [tenantId]);
      await sql.end();
    }
    await backend?.close();
  });

  it("leaves no claimable scan when its required enqueue access record fails, then retries cleanly", async () => {
    const faultName = `enqueue_fault_${randomUUID().replaceAll("-", "")}`;
    try {
      await sql.query(`CREATE FUNCTION ${faultName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id = '${tenantId}'::uuid AND NEW.action = 'enqueue' THEN RAISE EXCEPTION 'Synthetic enqueue audit interruption'; END IF; RETURN NEW; END $$`);
      await sql.query(`CREATE TRIGGER ${faultName} BEFORE INSERT ON access_events FOR EACH ROW EXECUTE FUNCTION ${faultName}()`);
      await expect(backend.enqueueScan(tenantId, sessionId)).rejects.toThrow("Synthetic enqueue audit interruption");
      expect((await sql.query("SELECT id FROM scan_jobs WHERE tenant_id=$1", [tenantId])).rowCount).toBe(0);
      expect(await backend.recentAccessEvents(tenantId)).toEqual([]);
      expect(await backend.claimNextJob("synthetic-worker", tenantId)).toBeNull();
      await sql.query(`DROP TRIGGER ${faultName} ON access_events`);
      const retry = await backend.enqueueScan(tenantId, sessionId);
      expect((await backend.claimNextJob("synthetic-worker", tenantId))?.id).toBe(retry.id);
      expect(await backend.recentAccessEvents(tenantId)).toMatchObject([{ action: "enqueue", resourceType: "scan_job", resourceId: retry.id }]);
      await backend.failJob(retry.id, "synthetic-worker", "Synthetic test complete");
    } finally {
      await sql.query(`DROP TRIGGER IF EXISTS ${faultName} ON access_events`);
      await sql.query(`DROP FUNCTION IF EXISTS ${faultName}()`);
      // Preserve independent tests even when the old implementation leaves a job behind.
      await sql.query("DELETE FROM scan_jobs WHERE tenant_id=$1", [tenantId]);
      await sql.query("DELETE FROM access_events WHERE tenant_id=$1", [tenantId]);
    }
  });

  it("reuses one queued job for concurrent valid requests and records only its actual creation", async () => {
    const otherSessionId = randomUUID();
    await createSession(otherSessionId);
    const jobs = await Promise.all([
      backend.enqueueScan(tenantId, sessionId),
      backend.enqueueScan(tenantId, sessionId),
      backend.enqueueScan(tenantId, otherSessionId),
    ]);
    try {
      expect(new Set(jobs.map(job => job.id)).size).toBe(1);
      expect((await sql.query("SELECT id FROM scan_jobs WHERE tenant_id=$1", [tenantId])).rows).toEqual([{ id: jobs[0]!.id }]);
      expect(await backend.recentAccessEvents(tenantId)).toEqual([expect.objectContaining({ action: "enqueue", resourceType: "scan_job", resourceId: jobs[0]!.id })]);
      await expect(backend.enqueueScan(tenantId, randomUUID())).rejects.toThrow("A valid tenant session is required.");
      expect(await backend.recentAccessEvents(tenantId)).toHaveLength(1);
    } finally {
      await backend.requestScanCancellation(jobs[0]!.id, tenantId);
    }
  });
});
