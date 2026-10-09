import { randomBytes, randomUUID } from "node:crypto";
import { Pool, type PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("concurrent PostgreSQL migrations", () => {
  it("serializes fresh and repeated migrations before DDL and preserves the usable schema", async () => {
    const schema = `migration_${randomUUID().replaceAll("-", "")}`;
    const applicationName = `migration-test-${randomUUID()}`;
    const scopedUrl = new URL(connectionString!);
    scopedUrl.searchParams.set("options", `-c search_path=${schema}`);
    scopedUrl.searchParams.set("application_name", applicationName);
    const sql = new Pool({ connectionString, connectionTimeoutMillis: 2_000 });
    const key = randomBytes(32);
    const backends = Array.from({ length: 4 }, () => new PostgresBackend({ connectionString: scopedUrl.toString(), encryptionKey: key }));
    let blocker: PoolClient | undefined;
    let schemaCreated = false;
    let pending: Promise<PromiseSettledResult<void>[]> | undefined;
    try {
      // This schema belongs only to this test; the public schema and other tests are untouched.
      await sql.query(`CREATE SCHEMA "${schema}"`);
      schemaCreated = true;
      blocker = await sql.connect();
      await blocker.query("BEGIN");
      await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended('entra-explorer:migrations', 0))");
      const blockerPid = (await blocker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      let finished: PromiseSettledResult<void>[] | undefined;
      pending = Promise.allSettled(backends.map(backend => backend.migrate())).then(results => { finished = results; return results; });
      await vi.waitFor(async () => {
        if (finished) throw new Error(`Migrations finished before the migration lock was released: ${finished.map(result => result.status === "fulfilled" ? "completed" : (result.reason as { code?: string }).code ?? "failed").join(", ")}`);
        const waiting = await sql.query("SELECT count(*)::int AS count FROM pg_locks held JOIN pg_locks waiting ON held.locktype=waiting.locktype AND held.database IS NOT DISTINCT FROM waiting.database AND held.classid=waiting.classid AND held.objid=waiting.objid AND held.objsubid=waiting.objsubid JOIN pg_stat_activity activity ON activity.pid=waiting.pid WHERE held.pid=$1 AND held.locktype='advisory' AND held.granted AND NOT waiting.granted AND activity.application_name=$2", [blockerPid, applicationName]);
        expect(waiting.rows[0].count).toBe(backends.length);
      }, { timeout: 2_000, interval: 10 });
      expect((await sql.query("SELECT tablename FROM pg_tables WHERE schemaname=$1", [schema])).rows).toEqual([]);

      await blocker.query("COMMIT");
      expect((await pending).map(result => result.status)).toEqual(["fulfilled", "fulfilled", "fulfilled", "fulfilled"]);
      expect((await sql.query("SELECT tablename FROM pg_tables WHERE schemaname=$1 ORDER BY tablename", [schema])).rows.map(row => row.tablename)).toEqual([
        "access_events", "auth_flows", "scan_checkpoints", "scan_jobs", "sessions", "snapshots", "threat_reviews",
      ]);

      const tenantId = randomUUID();
      const session = { id: randomUUID(), tenantId, account: {}, accessToken: "synthetic-only", tokenCache: "synthetic-only", accessTokenExpiresAt: Date.now() + 60_000, sessionExpiresAt: Date.now() + 60_000 };
      await backends[0]!.createSession(session);
      pending = Promise.allSettled(backends.map(backend => backend.migrate()));
      expect((await pending).map(result => result.status)).toEqual(["fulfilled", "fulfilled", "fulfilled", "fulfilled"]);
      for (const backend of backends) expect(await backend.getSession(session.id, tenantId)).toEqual(session);

      // Rebuilding the partial unique index must still allow only one active scan per tenant.
      const jobs = await Promise.all(backends.map(backend => backend.enqueueScan(tenantId, session.id)));
      expect(new Set(jobs.map(job => job.id)).size).toBe(1);
      expect(await backends[0]!.requestScanCancellation(jobs[0]!.id, tenantId)).toMatchObject({ status: "cancelled" });
      expect(await backends[1]!.getJob(jobs[0]!.id, tenantId)).toMatchObject({ status: "cancelled" });
    } finally {
      if (blocker) { await blocker.query("ROLLBACK"); blocker.release(); }
      await pending;
      await Promise.all(backends.map(backend => backend.close()));
      try { if (schemaCreated) await sql.query(`DROP SCHEMA "${schema}" CASCADE`); }
      finally { await sql.end(); }
    }
  }, 10_000);
});
