import { randomBytes, randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PostgresBackend } from "./postgres";
import { createIsolatedTestDatabase } from "./test-support";
import type { DurableSession, ScanJob } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("PostgreSQL worker access to a claimed scan", () => {
  const workerId = "synthetic-scan-access-owner";
  let database: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let backend: PostgresBackend;
  let sql: Pool;
  let tenantId: string;
  let session: DurableSession;
  let job: ScanJob;

  beforeAll(async () => {
    database = await createIsolatedTestDatabase(connectionString!, Pool);
    backend = new PostgresBackend({ connectionString: database.connectionString, encryptionKey: randomBytes(32) });
    sql = database.sql;
    await backend.migrate();
  });

  beforeEach(async () => {
    tenantId = randomUUID();
    session = { id: randomUUID(), tenantId, account: {}, accessToken: "synthetic-token", tokenCache: "synthetic-cache", accessTokenExpiresAt: Date.now() - 1000, sessionExpiresAt: Date.now() + 3_600_000 };
    await backend.createSession(session);
    job = await backend.enqueueScan(tenantId, session.id);
  });

  afterAll(async () => {
    try { await backend?.close(); }
    finally { await database?.close(); }
  });

  const state = () => backend.getScanAccessState(job.id, workerId, tenantId);
  async function claim() { expect((await backend.claimNextJob(workerId, tenantId))?.id).toBe(job.id); }
  async function expireSession() {
    await sql.query("UPDATE sessions SET expires_at=now()-interval '1 millisecond' WHERE id=$1 AND tenant_id=$2", [session.id, tenantId]);
  }

  it("permits the owner with a valid login session even when the Graph access token needs refreshing", async () => {
    await claim();
    const before = await backend.getJob(job.id, tenantId);
    expect(await state()).toBe("running");
    expect(await backend.getJob(job.id, tenantId)).toEqual(before);
    expect(await backend.getSession(session.id, tenantId)).toEqual(session);
  });

  it("detects session expiry without changing the running job", async () => {
    await claim();
    const before = await backend.getJob(job.id, tenantId);
    await expireSession();
    expect(await state()).toBe("session_unavailable");
    expect(await backend.getJob(job.id, tenantId)).toEqual(before);
  });

  it("detects logout after PostgreSQL clears the deleted session reference", async () => {
    await claim();
    await backend.deleteSession(session.id, randomUUID());
    expect(await state()).toBe("running");
    await backend.deleteSession(session.id, tenantId);
    expect(await state()).toBe("session_unavailable");
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", sessionId: null, workerId });
  });

  it("rejects a foreign-tenant session reference even when that session remains valid", async () => {
    await claim();
    const foreignTenantId = randomUUID();
    const foreignSessionId = randomUUID();
    await backend.createSession({ ...session, id: foreignSessionId, tenantId: foreignTenantId });
    // A legacy/corrupt reference must not cross a tenant boundary through the session join.
    await sql.query("UPDATE scan_jobs SET session_id=$1 WHERE id=$2 AND tenant_id=$3", [foreignSessionId, job.id, tenantId]);
    expect(await state()).toBe("session_unavailable");
    expect(await backend.getSession(foreignSessionId, foreignTenantId)).not.toBeNull();
  });

  it.each(["valid", "expired", "revoked"])("preserves cancellation ownership with a %s session", async sessionState => {
    await claim();
    await backend.requestScanCancellation(job.id, tenantId);
    if (sessionState === "expired") await expireSession();
    if (sessionState === "revoked") await backend.deleteSession(session.id, tenantId);
    expect(await state()).toBe("cancel_requested");
    expect(await backend.getScanAccessState(job.id, "another-worker", tenantId)).toBe("lease_lost");
    expect(await backend.getScanAccessState(job.id, workerId, randomUUID())).toBe("lease_lost");
  });

  it.each(["job", "worker", "tenant"])("rejects a mismatched %s without disturbing the real owner", async mismatch => {
    await claim();
    expect(await backend.getScanAccessState(mismatch === "job" ? randomUUID() : job.id, mismatch === "worker" ? "another-worker" : workerId, mismatch === "tenant" ? randomUUID() : tenantId)).toBe("lease_lost");
    expect(await state()).toBe("running");
  });

  it("does not treat an unclaimed queued scan as accessible", async () => {
    expect(await state()).toBe("lease_lost");
    expect((await backend.getJob(job.id, tenantId))?.status).toBe("queued");
  });

  it.each(["complete", "failed", "cancelled"])("revokes access after the job is %s", async outcome => {
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

  it("rejects a recovered worker while permitting the new lease owner", async () => {
    await claim();
    await sql.query("UPDATE scan_jobs SET updated_at=now()-interval '11 minutes' WHERE id=$1 AND tenant_id=$2", [job.id, tenantId]);
    expect(await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 600_000))).toBe(1);
    expect(await state()).toBe("lease_lost");
    expect((await backend.claimNextJob("replacement-worker", tenantId))?.id).toBe(job.id);
    expect(await state()).toBe("lease_lost");
    expect(await backend.getScanAccessState(job.id, "replacement-worker", tenantId)).toBe("running");
  });
});
