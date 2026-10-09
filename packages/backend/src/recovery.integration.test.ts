import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresBackend } from "./postgres";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("queue recovery during authentication and database failures", () => {
  const tenantId = randomUUID();
  const otherTenantId = randomUUID();
  const sessionId = randomUUID();
  let backend: PostgresBackend;
  let sql: Pool;

  const createSession = (id: string, tenant = tenantId, expiresAt = Date.now() + 3600000) => backend.createSession({
    id, tenantId: tenant, account: {}, accessToken: "synthetic-only", tokenCache: "synthetic-only",
    accessTokenExpiresAt: expiresAt, sessionExpiresAt: expiresAt,
  });

  beforeAll(async () => {
    backend = new PostgresBackend({ connectionString: connectionString!, encryptionKey: randomBytes(32) });
    sql = new Pool({ connectionString });
    await backend.migrate();
    await createSession(sessionId);
  });

  afterAll(async () => {
    if (sql) {
      for (const table of ["scan_checkpoints", "scan_jobs", "sessions", "access_events"]) {
        await sql.query(`DELETE FROM ${table} WHERE tenant_id=ANY($1::uuid[])`, [[tenantId, otherTenantId]]);
      }
      await sql.end();
    }
    await backend?.close();
  });

  it.each(["missing", "expired", "other tenant"])("rejects a %s session even when its requested tenant already has an active scan", async invalid => {
    const active = await backend.enqueueScan(tenantId, sessionId);
    const invalidSessionId = randomUUID();
    if (invalid === "expired") await createSession(invalidSessionId, tenantId, Date.now() - 60000);
    if (invalid === "other tenant") await createSession(invalidSessionId, otherTenantId);
    const accessBefore = await backend.recentAccessEvents(tenantId);
    try {
      await expect(backend.enqueueScan(tenantId, invalidSessionId)).rejects.toThrow("A valid tenant session is required.");
      expect(await backend.getJob(active.id, tenantId)).toEqual(active);
      expect(await backend.recentAccessEvents(tenantId)).toEqual(accessBefore);
    } finally {
      await backend.requestScanCancellation(active.id, tenantId);
    }
  });

  it("returns the same active scan to another valid session without creating a competing job", async () => {
    const anotherSessionId = randomUUID();
    await createSession(anotherSessionId);
    const active = await backend.enqueueScan(tenantId, sessionId);
    try {
      expect(await backend.enqueueScan(tenantId, anotherSessionId)).toEqual(active);
      const claimed = await backend.claimNextJob("synthetic-owner", tenantId);
      expect(claimed?.id).toBe(active.id);
      expect(await backend.claimNextJob("competing-owner", tenantId)).toBeNull();
    } finally {
      await backend.requestScanCancellation(active.id, tenantId);
      await backend.cancelJob(active.id, "synthetic-owner");
    }
  });

  it("keeps interrupted cancellation recoverable until encrypted checkpoint cleanup succeeds", async () => {
    const job = await backend.enqueueScan(tenantId, sessionId);
    await backend.claimNextJob("interrupted-worker", tenantId);
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { completedStages: ["applications"], syntheticEvidence: "unpublished" }, updatedAt: "" }, "interrupted-worker");
    await backend.requestScanCancellation(job.id, tenantId);
    await sql.query("UPDATE scan_jobs SET updated_at=now()-interval '11 minutes' WHERE id=$1 AND tenant_id=$2", [job.id, tenantId]);
    const cutoff = new Date(Date.now() - 600000);
    // A database-side fault occurs only for this test's encrypted checkpoint.
    // The observable contract is atomic cancellation, followed by a successful retry.
    const faultName = `checkpoint_fault_${randomUUID().replaceAll("-", "")}`;
    try {
      await sql.query(`CREATE FUNCTION ${faultName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.job_id = '${job.id}'::uuid THEN RAISE EXCEPTION 'Synthetic checkpoint cleanup interruption'; END IF; RETURN OLD; END $$`);
      await sql.query(`CREATE TRIGGER ${faultName} BEFORE DELETE ON scan_checkpoints FOR EACH ROW EXECUTE FUNCTION ${faultName}()`);
      await expect(backend.recoverStaleJobs(tenantId, cutoff)).rejects.toThrow("Synthetic checkpoint cleanup interruption");
      expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "cancel_requested", workerId: "interrupted-worker", finishedAt: null });
      expect(await backend.getScanCheckpoint(job.id, tenantId)).toMatchObject({ payload: { syntheticEvidence: "unpublished" } });
      await sql.query(`DROP TRIGGER ${faultName} ON scan_checkpoints`);
      expect(await backend.recoverStaleJobs(tenantId, cutoff)).toBe(1);
      expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "cancelled", workerId: null, finishedAt: expect.any(String) });
      expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
      expect(await backend.claimNextJob("replacement-worker", tenantId)).toBeNull();
    } finally {
      await sql.query(`DROP TRIGGER IF EXISTS ${faultName} ON scan_checkpoints`);
      await sql.query(`DROP FUNCTION IF EXISTS ${faultName}()`);
    }
  });
});
