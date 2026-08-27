import { randomBytes, randomUUID } from "node:crypto";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { encryptJson } from "./crypto";
import { DATABASE_SCHEMA } from "./schema";
import { FakePool, jobRow, respondTo, rows } from "./test-support";
import type { DurableSession, ScanCheckpoint, ThreatReview } from "./types";

vi.mock("pg", async () => {
  const { FakePool: Pool } = await import("./test-support");
  return { Pool };
});

const { PostgresBackend } = await import("./postgres");

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const KEY = randomBytes(32);

function backendUnderTest() {
  const backend = new PostgresBackend({ connectionString: "postgres://localhost/test", encryptionKey: KEY });
  return { backend, pool: FakePool.last };
}

function session(overrides: Partial<DurableSession> = {}): DurableSession {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    tenantId: TENANT,
    account: { username: "person@contoso.test" },
    accessToken: "token",
    accessTokenExpiresAt: Date.parse("2026-08-26T11:00:00.000Z"),
    tokenCache: "cache",
    sessionExpiresAt: Date.parse("2026-08-26T12:00:00.000Z"),
    ...overrides,
  };
}

/** Builds the encrypted row Postgres would have stored for `value` under `context`. */
function encryptedRow(value: unknown, context: string, extra: Record<string, unknown> = {}) {
  const payload = encryptJson(value, KEY, context);
  return { iv: payload.iv, ciphertext: payload.ciphertext, auth_tag: payload.authTag, ...extra };
}

beforeEach(() => { FakePool.reset(); });

describe("connection setup", () => {
  it("refuses to start without a connection string or a 32-byte key", () => {
    expect(() => new PostgresBackend({ connectionString: "", encryptionKey: KEY })).toThrow(/DATABASE_URL is required/);
    expect(() => new PostgresBackend({ connectionString: "postgres://x", encryptionKey: randomBytes(16) })).toThrow(/32-byte key/);
    expect(() => new PostgresBackend({ connectionString: "postgres://x", encryptionKey: randomBytes(64) })).toThrow(/32-byte key/);
  });

  it("bounds the connection pool and its timeouts", () => {
    const { pool } = backendUnderTest();
    expect(pool.config).toMatchObject({ connectionString: "postgres://localhost/test", max: 10, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000 });
  });

  it("applies the schema and clears expired auth state on migrate", async () => {
    const { backend, pool } = backendUnderTest();
    await backend.migrate();
    expect(pool.sql[0]).toBe(DATABASE_SCHEMA);
    expect(pool.matching("DELETE FROM auth_flows WHERE expires_at <= now()")).toHaveLength(1);
    expect(pool.matching("DELETE FROM sessions WHERE expires_at <= now()")).toHaveLength(1);
  });

  it("reports health from a live round trip and closes the pool", async () => {
    const { backend, pool } = backendUnderTest();
    expect(await backend.health()).toEqual({ ok: true, database: "postgres" });
    expect(pool.sql).toContain("SELECT 1");
    await backend.close();
    expect(pool.ended).toBe(true);
  });
});

describe("tenant scoping", () => {
  it("scopes every tenant-owned read and write by tenant_id", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("scan_jobs") ? rows(jobRow()) : { rows: [], rowCount: 0 });
    await backend.getSession("s-1", TENANT);
    await backend.deleteSession("s-1", TENANT);
    await backend.getJob("job-1", TENANT);
    await backend.getLatestJob(TENANT);
    await backend.requestScanCancellation("job-1", TENANT);
    await backend.getScanCheckpoint("job-1", TENANT).catch(() => {});
    await backend.recentSnapshots(TENANT).catch(() => {});
    await backend.recentAccessEvents(TENANT);
    await backend.getThreatReview(TENANT, "snap-1", "finding-1").catch(() => {});
    const tenantScoped = pool.queries.filter((query) => /FROM (sessions|scan_jobs|snapshots|access_events|threat_reviews|scan_checkpoints)/.test(query.sql));
    expect(tenantScoped.length).toBeGreaterThan(0);
    for (const query of tenantScoped) expect(query.sql, query.sql).toMatch(/tenant_id\s*=\s*\$\d/);
  });

  it("binds the encryption context to the tenant so a cross-tenant row cannot be read", async () => {
    const { backend, pool } = backendUnderTest();
    const live = session();
    pool.responder = respondTo("FROM sessions", {
      rows: [encryptedRow(live, `session:${live.id}:${OTHER_TENANT}`)],
    });
    await expect(backend.getSession(live.id, TENANT)).rejects.toThrow();
  });

  it("requires the auth flow's own tenant before consuming it", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    expect(await backend.consumeAuthFlow("flow-1", TENANT, "state")).toBeNull();
    expect(pool.only("SELECT * FROM auth_flows").sql).toContain("tenant_id=$2");
    expect(pool.only("SELECT * FROM auth_flows").sql).toContain("expires_at>now()");
  });
});

describe("encrypted round trips", () => {
  it("stores a session encrypted and reads it back under the same context", async () => {
    const { backend, pool } = backendUnderTest();
    const live = session();
    await backend.createSession(live);
    const insert = pool.only("INSERT INTO sessions");
    expect(insert.params[0]).toBe(live.id);
    expect(insert.params[1]).toBe(TENANT);
    expect(insert.params[2]).toEqual(new Date(live.sessionExpiresAt));
    // The plaintext access token must never appear in a bound parameter.
    expect(JSON.stringify(insert.params)).not.toContain("token");

    pool.responder = respondTo("FROM sessions", { rows: [encryptedRow(live, `session:${live.id}:${TENANT}`)] });
    expect(await backend.getSession(live.id, TENANT)).toEqual(live);
  });

  it("returns nothing when no session row matches", async () => {
    const { backend } = backendUnderTest();
    expect(await backend.getSession("absent", TENANT)).toBeNull();
  });

  it("accepts an auth flow only when the returned state matches in constant time", async () => {
    const { backend, pool } = backendUnderTest();
    const flow = { id: "flow-1", tenantId: TENANT, state: "expected-state", verifier: "verifier", expiresAt: Date.parse("2026-08-26T12:00:00.000Z") };
    pool.responder = (sql) => sql.includes("SELECT * FROM auth_flows")
      ? rows(encryptedRow(flow, `auth-flow:${flow.id}:${TENANT}`))
      : sql.includes("DELETE FROM auth_flows") ? { rows: [], rowCount: 1 } : { rows: [], rowCount: 0 };
    expect(await backend.consumeAuthFlow(flow.id, TENANT, "expected-state")).toEqual(flow);
    expect(pool.only("DELETE FROM auth_flows WHERE id=$1").params).toEqual([flow.id, TENANT]);
    expect(await backend.consumeAuthFlow(flow.id, TENANT, "wrong-state-x")).toBeNull();
    // A different length must be rejected before the constant-time compare.
    expect(await backend.consumeAuthFlow(flow.id, TENANT, "short")).toBeNull();
  });

  it("returns no auth flow when another callback already consumed the matching row", async () => {
    const { backend, pool } = backendUnderTest();
    const flow = { id: "flow-race", tenantId: TENANT, state: "expected-state", verifier: "verifier", expiresAt: Date.now() + 60_000 };
    pool.responder = (sql) => sql.includes("SELECT * FROM auth_flows")
      ? rows(encryptedRow(flow, `auth-flow:${flow.id}:${TENANT}`))
      : { rows: [], rowCount: 0 };
    expect(await backend.consumeAuthFlow(flow.id, TENANT, flow.state)).toBeNull();
  });

  it("encrypts the auth flow with its own identifier in the context", async () => {
    const { backend, pool } = backendUnderTest();
    const flow = { id: "flow-1", tenantId: TENANT, state: "s", verifier: "secret-verifier", expiresAt: Date.now() };
    await backend.createAuthFlow(flow);
    expect(JSON.stringify(pool.only("INSERT INTO auth_flows").params)).not.toContain("secret-verifier");
  });

  it("decrypts a stored checkpoint and refuses one written for another tenant", async () => {
    const { backend, pool } = backendUnderTest();
    const checkpoint: ScanCheckpoint = { jobId: "job-1", tenantId: TENANT, payload: { completedStages: ["applications"] }, updatedAt: "2026-08-26T10:00:00.000Z" };
    pool.responder = respondTo("FROM scan_checkpoints", { rows: [encryptedRow(checkpoint, `scan-checkpoint:job-1:${TENANT}`)] });
    expect(await backend.getScanCheckpoint("job-1", TENANT)).toEqual(checkpoint);
    pool.responder = respondTo("FROM scan_checkpoints", { rows: [encryptedRow(checkpoint, `scan-checkpoint:job-1:${OTHER_TENANT}`)] });
    await expect(backend.getScanCheckpoint("job-1", TENANT)).rejects.toThrow();
  });

  it("returns no checkpoint when the job has none", async () => {
    const { backend } = backendUnderTest();
    expect(await backend.getScanCheckpoint("job-1", TENANT)).toBeNull();
  });

  it("decrypts each retained snapshot with its own scanned-at context", async () => {
    const { backend, pool } = backendUnderTest();
    const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId: TENANT }, scannedAt: "2026-08-26T10:00:00.000Z" };
    pool.responder = respondTo("FROM snapshots", {
      rows: [encryptedRow(snapshot, `snapshot:${snapshot.id}:${TENANT}:${snapshot.scannedAt}`, {
        id: snapshot.id, tenant_id: TENANT, scanned_at: new Date(snapshot.scannedAt),
      })],
    });
    expect(await backend.recentSnapshots(TENANT)).toEqual([snapshot]);
  });

  it("stores and returns a threat review stamped with its own update time", async () => {
    const { backend, pool } = backendUnderTest();
    const review: ThreatReview = {
      findingId: "finding-1", snapshotId: "snap-1", tenantId: TENANT, disposition: "mitigating",
      owner: "IAM", expiresAt: null, assumption: "Control holds", updatedAt: "1970-01-01T00:00:00.000Z",
    };
    const stored = await backend.upsertThreatReview(review, "session-1");
    expect(stored.updatedAt).not.toBe(review.updatedAt);
    expect(pool.matching("INSERT INTO threat_reviews")).toHaveLength(1);
    // Upserting also writes the audit trail.
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, "session-1", "update", "threat_review", "finding-1"]);
  });

  it("decrypts a stored review with the tenant, snapshot, and finding it was sealed under", async () => {
    const { backend, pool } = backendUnderTest();
    const review: ThreatReview = {
      findingId: "finding-1", snapshotId: "snap-1", tenantId: TENANT, disposition: "accepted",
      owner: "IAM", expiresAt: "2026-12-01T00:00:00.000Z", assumption: "Compensating control holds",
      updatedAt: "2026-08-26T10:00:00.000Z",
    };
    pool.responder = respondTo("FROM threat_reviews", {
      rows: [encryptedRow(review, `threat-review:${TENANT}:snap-1:finding-1`, {
        tenant_id: TENANT, id: "snap-1", finding_id: "finding-1", updated_at: new Date(review.updatedAt),
      })],
    });
    expect(await backend.getThreatReview(TENANT, "snap-1", "finding-1")).toEqual(review);
    expect(pool.only("FROM threat_reviews").params).toEqual([TENANT, "snap-1", "finding-1"]);
  });

  it("refuses to decrypt a review resealed under another finding", async () => {
    const { backend, pool } = backendUnderTest();
    const review: ThreatReview = {
      findingId: "finding-2", snapshotId: "snap-1", tenantId: TENANT, disposition: "accepted",
      owner: "IAM", expiresAt: null, assumption: "", updatedAt: "2026-08-26T10:00:00.000Z",
    };
    pool.responder = respondTo("FROM threat_reviews", {
      rows: [encryptedRow(review, `threat-review:${TENANT}:snap-1:finding-2`, { tenant_id: TENANT, id: "snap-1", finding_id: "finding-1" })],
    });
    await expect(backend.getThreatReview(TENANT, "snap-1", "finding-1")).rejects.toThrow();
  });

  it("returns nothing for a finding with no recorded review", async () => {
    const { backend } = backendUnderTest();
    expect(await backend.getThreatReview(TENANT, "snap-1", "finding-1")).toBeNull();
  });
});

describe("job ownership guards", () => {
  it("rejects a progress update that did not affect exactly one owned row", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.updateJobProgress("job-1", "worker-1", "owners", 1, "detail")).rejects.toThrow(/not owned by this worker/);
    expect(pool.only("UPDATE scan_jobs SET stage").sql).toContain("worker_id=$2");
    expect(pool.only("UPDATE scan_jobs SET stage").sql).toContain("status='running'");
  });

  it("accepts a progress update that matched its owned running row", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 1 });
    await expect(backend.updateJobProgress("job-1", "worker-1", "owners", 5, "detail")).resolves.toBeUndefined();
  });

  it("truncates an over-long progress detail before it reaches the database", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 1 });
    await backend.updateJobProgress("job-1", "worker-1", "owners", 1, "x".repeat(900));
    expect(String(pool.only("UPDATE scan_jobs SET stage").params[4])).toHaveLength(500);
  });

  it("truncates an over-long failure message", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 1 });
    await backend.failJob("job-1", "worker-1", "y".repeat(900));
    expect(String(pool.only("status='failed'").params[2])).toHaveLength(500);
    expect(pool.only("DELETE FROM scan_checkpoints WHERE job_id=$1").params).toEqual(["job-1"]);
  });

  it("rolls back a failed-job transition the worker does not own", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.failJob("job-1", "worker-1", "failure")).rejects.toThrow(/not owned/);
    expect(pool.matching("DELETE FROM scan_checkpoints")).toHaveLength(0);
    expect(pool.matching("ROLLBACK")).toHaveLength(1);
  });

  it("rejects a session update that matched no row in this tenant", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.updateSession(session())).rejects.toThrow(/not found in this tenant/);
    pool.responder = () => ({ rows: [], rowCount: 1 });
    await expect(backend.updateSession(session())).resolves.toBeUndefined();
  });

  it("rejects a checkpoint save that the worker does not own", async () => {
    const checkpoint: ScanCheckpoint = { jobId: "job-1", tenantId: TENANT, payload: {}, updatedAt: "" };
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.saveScanCheckpoint(checkpoint, "worker-1")).rejects.toThrow(/not owned by this worker/);
    expect(pool.only("INSERT INTO scan_checkpoints").sql).toContain("status='running'");
    pool.responder = () => ({ rows: [], rowCount: 1 });
    await expect(backend.saveScanCheckpoint(checkpoint, "worker-1")).resolves.toBeUndefined();
  });

  it("rejects a cancellation the worker cannot complete and deletes the checkpoint when it can", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.cancelJob("job-1", "worker-1")).rejects.toThrow(/not cancellable by this worker/);
    expect(pool.matching("DELETE FROM scan_checkpoints")).toHaveLength(0);

    const second = backendUnderTest();
    second.pool.responder = () => ({ rows: [], rowCount: 1 });
    await second.backend.cancelJob("job-1", "worker-1");
    expect(second.pool.only("DELETE FROM scan_checkpoints WHERE job_id=$1").params).toEqual(["job-1"]);
  });

  it("reports a pending cancellation only for the owning worker's running job", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    expect(await backend.isScanCancellationRequested("job-1", "worker-1")).toBe(false);
    pool.responder = () => rows({ "?column?": 1 });
    expect(await backend.isScanCancellationRequested("job-1", "worker-1")).toBe(true);
    expect(pool.queries.at(-1)!.sql).toContain("status='cancel_requested'");
  });

  it("cleans a queued job's checkpoint in the same cancellation transaction", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => sql.includes("cancel_requested' END")
      ? rows(jobRow({ status: "cancelled" }))
      : { rows: [], rowCount: 1 };
    expect(await backend.requestScanCancellation("job-1", TENANT)).toMatchObject({ status: "cancelled" });
    expect(pool.only("DELETE FROM scan_checkpoints WHERE job_id=$1 AND tenant_id=$2").params).toEqual(["job-1", TENANT]);
    expect(pool.matching("COMMIT")).toHaveLength(1);
  });

  it("keeps the checkpoint while a running job is only asked to stop", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => sql.includes("cancel_requested' END")
      ? rows(jobRow({ status: "cancel_requested" }))
      : { rows: [], rowCount: 1 };
    expect(await backend.requestScanCancellation("job-1", TENANT)).toMatchObject({ status: "cancel_requested" });
    expect(pool.matching("DELETE FROM scan_checkpoints")).toHaveLength(0);
  });
});

describe("queueing and claiming", () => {
  it("requires a live session row for the insert and falls back to the active job", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("SELECT * FROM scan_jobs WHERE tenant_id=$1 AND status IN") ? rows(jobRow({ status: "running" })) : { rows: [], rowCount: 0 });
    const job = await backend.enqueueScan(TENANT, "session-1");
    expect(job.status).toBe("running");
    expect(pool.only("INSERT INTO scan_jobs").sql).toContain("FROM sessions WHERE id=$3 AND tenant_id=$2 AND expires_at>now()");
  });

  it("refuses to queue a scan when neither an insert nor an active job is available", async () => {
    const { backend } = backendUnderTest();
    await expect(backend.enqueueScan(TENANT, "session-1")).rejects.toThrow(/valid tenant session/);
  });

  it("records an audit event naming the queued job", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("INSERT INTO scan_jobs") ? rows(jobRow()) : { rows: [], rowCount: 0 });
    await backend.enqueueScan(TENANT, "session-1");
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, "session-1", "enqueue", "scan_job", "job-1"]);
  });

  it("claims one queued job at a time and skips rows another worker locked", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => rows(jobRow({ status: "running", worker_id: "worker-1", attempt: 1 }));
    const claimed = await backend.claimNextJob("worker-1", TENANT);
    expect(claimed).toMatchObject({ status: "running", workerId: "worker-1", attempt: 1 });
    const sql = pool.queries.at(-1)!.sql;
    expect(sql).toContain("FOR UPDATE SKIP LOCKED");
    expect(sql).toContain("LIMIT 1");
    expect(sql).toContain("available_at<=now()");
    expect(sql).toContain("tenant_id=$2");
  });

  it("returns nothing when the queue is empty", async () => {
    const { backend } = backendUnderTest();
    expect(await backend.claimNextJob("worker-1", TENANT)).toBeNull();
    expect(await backend.getJob("job-1", TENANT)).toBeNull();
    expect(await backend.getLatestJob(TENANT)).toBeNull();
    expect(await backend.requestScanCancellation("job-1", TENANT)).toBeNull();
  });

  it("maps a fully populated job row onto the domain shape", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => rows(jobRow({
      status: "complete", stage: "complete", collected: "42", finished_at: new Date("2026-08-26T11:00:00.000Z"),
      snapshot_id: "snap-1", completion: "partial", error: "partial read", attempt: "3", worker_id: "worker-9",
    }));
    expect(await backend.getJob("job-1", TENANT)).toEqual({
      id: "job-1", tenantId: TENANT, sessionId: "session-1", status: "complete", stage: "complete",
      collected: 42, detail: "Waiting to begin the read-only scan",
      createdAt: "2026-08-26T10:00:00.000Z", updatedAt: "2026-08-26T10:00:00.000Z",
      finishedAt: "2026-08-26T11:00:00.000Z", snapshotId: "snap-1", completion: "partial",
      error: "partial read", attempt: 3, workerId: "worker-9",
    });
  });

  it("maps absent optional job columns to null", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => rows(jobRow({ session_id: null, worker_id: null, error: null, snapshot_id: null }));
    expect(await backend.getJob("job-1", TENANT)).toMatchObject({ sessionId: null, workerId: null, error: null, snapshotId: null, finishedAt: null });
  });
});

describe("stale job recovery", () => {
  it("sums requeued and cancelled jobs and clears checkpoints for the cancelled ones", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => ({ rows: [], rowCount: sql.includes("status='cancel_requested'") ? 2 : 3 });
    expect(await backend.recoverStaleJobs(TENANT, new Date("2026-08-26T09:00:00.000Z"))).toBe(5);
    expect(pool.only("DELETE FROM scan_checkpoints c USING scan_jobs j").params).toEqual([TENANT]);
  });

  it("skips the checkpoint sweep when no cancellation was completed", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => ({ rows: [], rowCount: sql.includes("status='cancel_requested'") ? 0 : 1 });
    expect(await backend.recoverStaleJobs(TENANT, new Date())).toBe(1);
    expect(pool.matching("DELETE FROM scan_checkpoints c USING scan_jobs j")).toHaveLength(0);
  });

  it("treats an unreported row count as zero recovered jobs", async () => {
    const { backend } = backendUnderTest();
    expect(await backend.recoverStaleJobs(TENANT, new Date())).toBe(0);
  });

  it("counts a driver that reports no row count as no recovered jobs", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: null });
    expect(await backend.recoverStaleJobs(TENANT, new Date("2026-08-26T09:00:00.000Z"))).toBe(0);
    // A null count must not be read as "rows were cancelled", which would orphan checkpoints.
    expect(pool.matching("DELETE FROM scan_checkpoints c USING scan_jobs j")).toHaveLength(0);
  });

  it("compares staleness against the supplied cutoff", async () => {
    const { backend, pool } = backendUnderTest();
    const cutoff = new Date("2026-08-26T09:00:00.000Z");
    await backend.recoverStaleJobs(TENANT, cutoff);
    const recoveryQueries = pool.matching("updated_at<$2");
    expect(recoveryQueries).toHaveLength(2);
    for (const query of recoveryQueries) expect(query.params).toEqual([TENANT, cutoff]);
  });
});

describe("completion transaction", () => {
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId: TENANT }, scannedAt: "2026-08-26T10:00:00.000Z" };

  it("writes the snapshot, job, checkpoint sweep, retention, and audit inside one transaction", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("FOR UPDATE") ? rows(jobRow({ tenant_id: TENANT })) : { rows: [], rowCount: 1 });
    await backend.completeJob("job-1", "worker-1", snapshot, new Date("2026-01-01T00:00:00.000Z"));
    expect(pool.sql[0]).toBe("BEGIN");
    expect(pool.sql.at(-1)).toBe("COMMIT");
    expect(pool.matching("INSERT INTO snapshots")).toHaveLength(1);
    expect(pool.matching("DELETE FROM scan_checkpoints WHERE job_id=$1")).toHaveLength(1);
    expect(pool.matching("DELETE FROM snapshots WHERE tenant_id=$1 AND scanned_at<$2")).toHaveLength(1);
    expect(pool.matching("INSERT INTO access_events")).toHaveLength(1);
    expect(pool.released).toBe(1);
  });

  it("rolls back and releases the client when the job is not owned by this worker", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 0 });
    await expect(backend.completeJob("job-1", "worker-1", snapshot, new Date(0))).rejects.toThrow(/not owned by this worker/);
    expect(pool.sql).toContain("ROLLBACK");
    expect(pool.sql).not.toContain("COMMIT");
    expect(pool.released).toBe(1);
  });

  it("rolls back rather than storing a snapshot from another tenant", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("FOR UPDATE") ? rows(jobRow({ tenant_id: OTHER_TENANT })) : { rows: [], rowCount: 1 });
    await expect(backend.completeJob("job-1", "worker-1", snapshot, new Date(0))).rejects.toThrow(/tenant boundaries do not match/);
    expect(pool.sql).toContain("ROLLBACK");
    expect(pool.matching("INSERT INTO snapshots")).toHaveLength(0);
  });

  it("never binds snapshot plaintext as a query parameter", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("FOR UPDATE") ? rows(jobRow({ tenant_id: TENANT })) : { rows: [], rowCount: 1 });
    await backend.completeJob("job-1", "worker-1", snapshot, new Date(0));
    const insert = pool.only("INSERT INTO snapshots");
    const label = snapshot.nodes[0]?.label;
    expect(label).toBeTruthy();
    expect(JSON.stringify(insert.params)).not.toContain(label);
    expect(insert.params[3]).toBe(snapshot.completion.status);
  });
});

describe("result page bounds", () => {
  it("clamps the snapshot and access-event page sizes into a sane range", async () => {
    const { backend, pool } = backendUnderTest();
    for (const limit of [0, -1, 1_000, 20]) {
      await backend.recentSnapshots(TENANT, limit);
      await backend.recentAccessEvents(TENANT, limit);
    }
    for (const query of [...pool.matching("FROM snapshots WHERE tenant_id=$1 ORDER BY"), ...pool.matching("FROM access_events")]) {
      const bound = Number(query.params[1]);
      expect(bound).toBeGreaterThanOrEqual(1);
      expect(bound).toBeLessThanOrEqual(100);
    }
  });

  it("defaults to 20 snapshots and 100 access events", async () => {
    const { backend, pool } = backendUnderTest();
    await backend.recentSnapshots(TENANT);
    await backend.recentAccessEvents(TENANT);
    expect(pool.only("FROM snapshots WHERE tenant_id=$1 ORDER BY").params[1]).toBe(20);
    expect(pool.only("FROM access_events").params[1]).toBe(100);
  });

  it("maps access-event rows, normalizing absent optional columns to null", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = respondTo("FROM access_events", {
      rows: [
        { id: 7, tenant_id: TENANT, session_id: null, action: "read", resource_type: "snapshot", resource_id: null, created_at: new Date("2026-08-26T10:00:00.000Z") },
        { id: 8, tenant_id: TENANT, session_id: "s-1", action: "export", resource_type: "snapshot", resource_id: "snap-1", created_at: "2026-08-26T11:00:00.000Z" },
      ],
    });
    expect(await backend.recentAccessEvents(TENANT)).toEqual([
      { id: "7", tenantId: TENANT, sessionId: null, action: "read", resourceType: "snapshot", resourceId: null, createdAt: "2026-08-26T10:00:00.000Z" },
      { id: "8", tenantId: TENANT, sessionId: "s-1", action: "export", resourceType: "snapshot", resourceId: "snap-1", createdAt: "2026-08-26T11:00:00.000Z" },
    ]);
  });

  it("stores an absent resource id as null when recording access", async () => {
    const { backend, pool } = backendUnderTest();
    await backend.recordAccess(TENANT, null, "list", "scan_job");
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, null, "list", "scan_job", null]);
  });
});

describe("statement parameters", () => {
  const SNAPSHOT_ID = "22222222-2222-4222-8222-222222222222";
  const ANY_PAYLOAD = [expect.anything(), expect.anything(), expect.anything()];

  /** Answers every statement with one affected row, which every guarded write requires. */
  function acceptingBackend() {
    const { backend, pool } = backendUnderTest();
    pool.responder = () => ({ rows: [], rowCount: 1 });
    return { backend, pool };
  }

  it("binds the auth flow id, tenant, and expiry, and nothing else", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.createAuthFlow({ id: "flow-1", tenantId: TENANT, state: "state", verifier: "verifier", expiresAt: Date.parse("2026-08-26T10:05:00.000Z") });
    expect(pool.only("INSERT INTO auth_flows").params).toEqual(["flow-1", TENANT, new Date("2026-08-26T10:05:00.000Z"), ...ANY_PAYLOAD]);
    // The state and verifier are only ever stored inside the sealed payload.
    expect(JSON.stringify(pool.only("INSERT INTO auth_flows").params.slice(0, 3))).not.toContain("verifier");
  });

  it("binds the id and tenant when consuming a flow, so another tenant cannot claim it", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.consumeAuthFlow("flow-1", TENANT, "state");
    expect(pool.only("SELECT * FROM auth_flows WHERE id=$1").params).toEqual(["flow-1", TENANT]);
  });

  it("binds session identity and expiry on create, update, read, and delete", async () => {
    const { backend, pool } = acceptingBackend();
    const stored = session();
    await backend.createSession(stored);
    expect(pool.only("INSERT INTO sessions").params).toEqual([stored.id, TENANT, new Date(stored.sessionExpiresAt), ...ANY_PAYLOAD]);
    await backend.updateSession(stored);
    expect(pool.only("UPDATE sessions SET expires_at").params).toEqual([stored.id, TENANT, new Date(stored.sessionExpiresAt), ...ANY_PAYLOAD]);
    await backend.getSession(stored.id, TENANT);
    expect(pool.only("SELECT * FROM sessions").params).toEqual([stored.id, TENANT]);
    await backend.deleteSession(stored.id, TENANT);
    expect(pool.only("DELETE FROM sessions WHERE id=$1").params).toEqual([stored.id, TENANT]);
  });

  it("issues a fresh job id and binds the requesting session and tenant", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("INSERT INTO scan_jobs") ? rows(jobRow()) : { rows: [], rowCount: 1 });
    await backend.enqueueScan(TENANT, "session-1");
    const insert = pool.only("INSERT INTO scan_jobs").params;
    expect(insert[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(insert.slice(1)).toEqual([TENANT, "session-1"]);
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, "session-1", "enqueue", "scan_job", "job-1"]);
  });

  it("falls back to the tenant's own active job when the insert matched no session", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("SELECT * FROM scan_jobs WHERE tenant_id=$1 AND status IN") ? rows(jobRow({ status: "running" })) : { rows: [], rowCount: 0 });
    await backend.enqueueScan(TENANT, "session-1");
    expect(pool.only("SELECT * FROM scan_jobs WHERE tenant_id=$1 AND status IN").params).toEqual([TENANT]);
  });

  it("scopes every job read to the tenant or the owning worker", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.getJob("job-1", TENANT);
    expect(pool.only("SELECT * FROM scan_jobs WHERE id=$1 AND tenant_id=$2").params).toEqual(["job-1", TENANT]);
    await backend.getLatestJob(TENANT);
    expect(pool.only("SELECT * FROM scan_jobs WHERE tenant_id=$1 ORDER BY").params).toEqual([TENANT]);
    await backend.claimNextJob("worker-1", TENANT);
    expect(pool.only("FOR UPDATE SKIP LOCKED").params).toEqual(["worker-1", TENANT]);
    await backend.isScanCancellationRequested("job-1", "worker-1");
    expect(pool.only("SELECT 1 FROM scan_jobs").params).toEqual(["job-1", "worker-1"]);
  });

  it("binds the stage, count, and bounded detail of a progress update", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.updateJobProgress("job-1", "worker-1", "owners", 42, "collecting owners");
    expect(pool.only("UPDATE scan_jobs SET stage").params).toEqual(["job-1", "worker-1", "owners", 42, "collecting owners"]);
  });

  it("binds the recovery cutoff to both recovery statements", async () => {
    const { backend, pool } = acceptingBackend();
    const cutoff = new Date("2026-08-26T09:00:00.000Z");
    await backend.recoverStaleJobs(TENANT, cutoff);
    expect(pool.only("status='cancel_requested' AND updated_at<$2").params).toEqual([TENANT, cutoff]);
    expect(pool.only("status='running' AND updated_at<$2").params).toEqual([TENANT, cutoff]);
  });

  it("binds the failure reason to the failing job and its worker", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.failJob("job-1", "worker-1", "Graph refused the read");
    expect(pool.only("status='failed'").params).toEqual(["job-1", "worker-1", "Graph refused the read"]);
  });

  it("binds cancellation to the tenant that asked and the worker that acts", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("cancel_requested' END") ? rows(jobRow({ status: "cancel_requested" })) : { rows: [], rowCount: 1 });
    await backend.requestScanCancellation("job-1", TENANT);
    expect(pool.only("cancel_requested' END").params).toEqual(["job-1", TENANT]);
    await backend.cancelJob("job-1", "worker-1");
    expect(pool.only("Scan cancelled safely").params).toEqual(["job-1", "worker-1"]);
  });

  it("binds the checkpoint job, tenant, and owning worker, stamping its own update time", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.saveScanCheckpoint({ jobId: "job-1", tenantId: TENANT, payload: { completedStages: ["applications"] }, updatedAt: "1970-01-01T00:00:00.000Z" }, "worker-1");
    const params = pool.only("INSERT INTO scan_checkpoints").params;
    expect(params[0]).toBe("job-1");
    expect(params[1]).toBe(TENANT);
    expect(params[5]).toBe("worker-1");
    await backend.getScanCheckpoint("job-1", TENANT);
    expect(pool.only("FROM scan_checkpoints WHERE job_id=$1").params).toEqual(["job-1", TENANT]);
  });

  it("binds every statement of a completed scan to the job's own tenant", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("FOR UPDATE") ? rows(jobRow({ tenant_id: TENANT, session_id: "session-1" })) : { rows: [], rowCount: 1 });
    const snapshot = {
      ...cleanProjectFixture, id: SNAPSHOT_ID, scannedAt: "2026-08-26T10:00:00.000Z",
      tenant: { ...cleanProjectFixture.tenant, tenantId: TENANT },
    };
    const retainAfter = new Date("2026-01-01T00:00:00.000Z");
    await backend.completeJob("job-1", "worker-1", snapshot, retainAfter);
    expect(pool.only("SELECT * FROM scan_jobs WHERE id=$1 AND worker_id=$2 AND status='running' FOR UPDATE").params).toEqual(["job-1", "worker-1"]);
    expect(pool.only("INSERT INTO snapshots").params).toEqual([SNAPSHOT_ID, TENANT, snapshot.scannedAt, snapshot.completion.status, ...ANY_PAYLOAD]);
    expect(pool.only("UPDATE scan_jobs SET status='complete'").params).toEqual([
      "job-1", "worker-1",
      snapshot.nodes.length + snapshot.edges.length,
      `${snapshot.nodes.length} objects and ${snapshot.edges.length} relationships normalized`,
      SNAPSHOT_ID, snapshot.completion.status,
    ]);
    expect(pool.only("DELETE FROM scan_checkpoints WHERE job_id=$1").params).toEqual(["job-1"]);
    expect(pool.only("DELETE FROM snapshots WHERE tenant_id=$1 AND scanned_at<$2").params).toEqual([TENANT, retainAfter]);
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, "session-1", SNAPSHOT_ID]);
  });

  it("counts objects and relationships together rather than against each other", async () => {
    const { backend, pool } = backendUnderTest();
    pool.responder = (sql) => (sql.includes("FOR UPDATE") ? rows(jobRow({ tenant_id: TENANT })) : { rows: [], rowCount: 1 });
    // Trimmed so the counts differ, which makes a subtraction visible in the bound value.
    const snapshot = {
      ...cleanProjectFixture, id: SNAPSHOT_ID, edges: cleanProjectFixture.edges.slice(0, 2),
      tenant: { ...cleanProjectFixture.tenant, tenantId: TENANT },
    };
    expect(snapshot.nodes.length).not.toBe(snapshot.edges.length);
    await backend.completeJob("job-1", "worker-1", snapshot, new Date(0));
    expect(pool.only("UPDATE scan_jobs SET status='complete'").params[2]).toBe(snapshot.nodes.length + snapshot.edges.length);
  });

  it("binds the tenant and the clamped page size to every listing", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.recentSnapshots(TENANT, 5);
    expect(pool.only("FROM snapshots WHERE tenant_id=$1").params).toEqual([TENANT, 5]);
    await backend.recentAccessEvents(TENANT, 7);
    expect(pool.only("FROM access_events WHERE tenant_id=$1").params).toEqual([TENANT, 7]);
  });

  it("binds every field of an access event, storing an absent resource as null", async () => {
    const { backend, pool } = acceptingBackend();
    await backend.recordAccess(TENANT, "session-1", "read", "snapshot", "snap-1");
    expect(pool.only("INSERT INTO access_events").params).toEqual([TENANT, "session-1", "read", "snapshot", "snap-1"]);
    const second = acceptingBackend();
    await second.backend.recordAccess(TENANT, null, "list", "scan_job");
    expect(second.pool.only("INSERT INTO access_events").params).toEqual([TENANT, null, "list", "scan_job", null]);
  });

  it("binds the tenant, snapshot, and finding of a stored review", async () => {
    const { backend, pool } = acceptingBackend();
    const review: ThreatReview = {
      findingId: "finding-1", snapshotId: "snap-1", tenantId: TENANT, disposition: "accepted",
      owner: "IAM", expiresAt: null, assumption: "", updatedAt: "1970-01-01T00:00:00.000Z",
    };
    await backend.upsertThreatReview(review, "session-1");
    expect(pool.only("INSERT INTO threat_reviews").params).toEqual([TENANT, "snap-1", "finding-1", ...ANY_PAYLOAD]);
  });
});
