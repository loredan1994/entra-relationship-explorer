import { randomUUID, timingSafeEqual } from "node:crypto";
import type { TenantSnapshot } from "@entra-explorer/domain";
import { Pool, type PoolClient, type QueryResultRow } from "pg";
import { decryptJson, encryptJson, type EncryptedValue } from "./crypto";
import { DATABASE_SCHEMA } from "./schema";
import type { AccessEvent, Backend, BackendHealth, DurableAuthFlow, DurableSession, ScanCheckpoint, ScanJob, ScanJobStage, ThreatReview } from "./types";

interface PostgresBackendOptions { connectionString: string; encryptionKey: Uint8Array; }
interface EncryptedRow extends QueryResultRow { id: string; tenant_id: string; expires_at?: Date; scanned_at?: Date; iv: Buffer; ciphertext: Buffer; auth_tag: Buffer; }

export class PostgresBackend implements Backend {
  private readonly pool: Pool;
  private readonly key: Uint8Array;

  constructor(options: PostgresBackendOptions) {
    if (!options.connectionString) throw new Error("DATABASE_URL is required.");
    if (options.encryptionKey.byteLength !== 32) throw new Error("Backend encryption requires a 32-byte key.");
    this.pool = new Pool({ connectionString: options.connectionString, max: 10, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000 });
    this.key = options.encryptionKey;
  }

  async migrate(): Promise<void> {
    await this.pool.query(DATABASE_SCHEMA);
    await this.pool.query("DELETE FROM auth_flows WHERE expires_at <= now()");
    await this.pool.query("DELETE FROM sessions WHERE expires_at <= now()");
  }

  async health(): Promise<BackendHealth> { await this.pool.query("SELECT 1"); return { ok: true, database: "postgres" }; }

  async createAuthFlow(flow: DurableAuthFlow): Promise<void> {
    const encrypted = encryptJson(flow, this.key, flowContext(flow.id, flow.tenantId));
    await this.pool.query("INSERT INTO auth_flows (id, tenant_id, expires_at, iv, ciphertext, auth_tag) VALUES ($1,$2,$3,$4,$5,$6)", [flow.id, flow.tenantId, new Date(flow.expiresAt), encrypted.iv, encrypted.ciphertext, encrypted.authTag]);
  }

  async consumeAuthFlow(id: string, tenantId: string, state: string): Promise<DurableAuthFlow | null> {
    const result = await this.pool.query<EncryptedRow>("DELETE FROM auth_flows WHERE id=$1 AND tenant_id=$2 AND expires_at>now() RETURNING *", [id, tenantId]);
    const row = result.rows[0];
    if (!row) return null;
    const flow = decryptJson<DurableAuthFlow>(encrypted(row), this.key, flowContext(id, tenantId));
    const a = Buffer.from(flow.state); const b = Buffer.from(state);
    return a.length === b.length && timingSafeEqual(a, b) ? flow : null;
  }

  async createSession(session: DurableSession): Promise<void> {
    const value = encryptJson(session, this.key, sessionContext(session.id, session.tenantId));
    await this.pool.query("INSERT INTO sessions (id,tenant_id,expires_at,iv,ciphertext,auth_tag) VALUES ($1,$2,$3,$4,$5,$6)", [session.id, session.tenantId, new Date(session.sessionExpiresAt), value.iv, value.ciphertext, value.authTag]);
  }

  async getSession(id: string, tenantId: string): Promise<DurableSession | null> {
    const result = await this.pool.query<EncryptedRow>("SELECT * FROM sessions WHERE id=$1 AND tenant_id=$2 AND expires_at>now()", [id, tenantId]);
    const row = result.rows[0];
    return row ? decryptJson<DurableSession>(encrypted(row), this.key, sessionContext(id, tenantId)) : null;
  }

  async updateSession(session: DurableSession): Promise<void> {
    const value = encryptJson(session, this.key, sessionContext(session.id, session.tenantId));
    const result = await this.pool.query("UPDATE sessions SET expires_at=$3,iv=$4,ciphertext=$5,auth_tag=$6,updated_at=now() WHERE id=$1 AND tenant_id=$2", [session.id, session.tenantId, new Date(session.sessionExpiresAt), value.iv, value.ciphertext, value.authTag]);
    if (result.rowCount !== 1) throw new Error("Session was not found in this tenant.");
  }

  async deleteSession(id: string, tenantId: string): Promise<void> { await this.pool.query("DELETE FROM sessions WHERE id=$1 AND tenant_id=$2", [id, tenantId]); }

  async enqueueScan(tenantId: string, sessionId: string): Promise<ScanJob> {
    const id = randomUUID();
    const result = await this.pool.query("INSERT INTO scan_jobs (id,tenant_id,session_id,status,stage,detail) SELECT $1,$2,$3,'queued','applications','Waiting to begin the read-only scan' FROM sessions WHERE id=$3 AND tenant_id=$2 AND expires_at>now() ON CONFLICT DO NOTHING RETURNING *", [id, tenantId, sessionId]);
    const row = result.rows[0] ?? (await this.pool.query("SELECT * FROM scan_jobs WHERE tenant_id=$1 AND status IN ('queued','running','cancel_requested') ORDER BY created_at DESC LIMIT 1", [tenantId])).rows[0];
    if (!row) throw new Error("A valid tenant session is required.");
    await this.recordAccess(tenantId, sessionId, "enqueue", "scan_job", row.id);
    return mapJob(row);
  }

  async getJob(id: string, tenantId: string): Promise<ScanJob | null> { const row = (await this.pool.query("SELECT * FROM scan_jobs WHERE id=$1 AND tenant_id=$2", [id, tenantId])).rows[0]; return row ? mapJob(row) : null; }
  async getLatestJob(tenantId: string): Promise<ScanJob | null> { const row = (await this.pool.query("SELECT * FROM scan_jobs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1", [tenantId])).rows[0]; return row ? mapJob(row) : null; }

  async recoverStaleJobs(staleBefore: Date): Promise<number> {
    const cancelled = await this.pool.query("UPDATE scan_jobs SET status='cancelled',worker_id=NULL,locked_at=NULL,detail='Cancellation completed after the previous worker stopped',finished_at=now(),updated_at=now() WHERE status='cancel_requested' AND updated_at<$1", [staleBefore]);
    if ((cancelled.rowCount ?? 0) > 0) await this.pool.query("DELETE FROM scan_checkpoints c USING scan_jobs j WHERE c.job_id=j.id AND j.status='cancelled'");
    const result = await this.pool.query("UPDATE scan_jobs SET status='queued',worker_id=NULL,locked_at=NULL,available_at=now(),detail='Recovered after the previous worker stopped',updated_at=now() WHERE status='running' AND updated_at<$1", [staleBefore]);
    return (result.rowCount ?? 0) + (cancelled.rowCount ?? 0);
  }

  async claimNextJob(workerId: string): Promise<ScanJob | null> {
    const row = (await this.pool.query("WITH candidate AS (SELECT id FROM scan_jobs WHERE status='queued' AND available_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE scan_jobs j SET status='running',worker_id=$1,locked_at=now(),attempt=attempt+1,detail='Starting Microsoft Graph reads',updated_at=now() FROM candidate WHERE j.id=candidate.id RETURNING j.*", [workerId])).rows[0];
    return row ? mapJob(row) : null;
  }

  async updateJobProgress(id: string, workerId: string, stage: ScanJobStage, collected: number, detail: string): Promise<void> {
    const result = await this.pool.query("UPDATE scan_jobs SET stage=$3,collected=$4,detail=$5,updated_at=now() WHERE id=$1 AND worker_id=$2 AND status='running'", [id, workerId, stage, collected, detail.slice(0, 500)]);
    if (result.rowCount !== 1) throw new Error("The scan job is not owned by this worker.");
  }

  async completeJob(id: string, workerId: string, snapshot: TenantSnapshot, retainAfter: Date): Promise<void> {
    await this.transaction(async (client) => {
      const job = (await client.query("SELECT * FROM scan_jobs WHERE id=$1 AND worker_id=$2 AND status='running' FOR UPDATE", [id, workerId])).rows[0];
      if (!job) throw new Error("The scan job is not owned by this worker.");
      if (snapshot.tenant.tenantId !== job.tenant_id) throw new Error("Snapshot and job tenant boundaries do not match.");
      const value = encryptJson(snapshot, this.key, snapshotContext(snapshot.id, job.tenant_id, snapshot.scannedAt));
      await client.query("INSERT INTO snapshots (id,tenant_id,scanned_at,completion_status,iv,ciphertext,auth_tag) VALUES ($1,$2,$3,$4,$5,$6,$7)", [snapshot.id, job.tenant_id, snapshot.scannedAt, snapshot.completion.status, value.iv, value.ciphertext, value.authTag]);
      await client.query("UPDATE scan_jobs SET status='complete',stage='complete',collected=$3,detail=$4,snapshot_id=$5,completion=$6,finished_at=now(),updated_at=now(),worker_id=NULL,locked_at=NULL WHERE id=$1 AND worker_id=$2", [id, workerId, snapshot.nodes.length + snapshot.edges.length, `${snapshot.nodes.length} objects and ${snapshot.edges.length} relationships normalized`, snapshot.id, snapshot.completion.status]);
      await client.query("DELETE FROM scan_checkpoints WHERE job_id=$1", [id]);
      await client.query("DELETE FROM snapshots WHERE tenant_id=$1 AND scanned_at<$2", [job.tenant_id, retainAfter]);
      await client.query("INSERT INTO access_events (tenant_id,session_id,action,resource_type,resource_id) VALUES ($1,$2,'create','snapshot',$3)", [job.tenant_id, job.session_id, snapshot.id]);
    });
  }

  async failJob(id: string, workerId: string, error: string): Promise<void> {
    await this.pool.query("UPDATE scan_jobs SET status='failed',detail='The read-only scan stopped before a snapshot could be saved',error=$3,finished_at=now(),updated_at=now(),worker_id=NULL,locked_at=NULL WHERE id=$1 AND worker_id=$2 AND status='running'", [id, workerId, error.slice(0, 500)]);
  }

  async requestScanCancellation(id: string, tenantId: string): Promise<ScanJob | null> {
    const row = (await this.pool.query("UPDATE scan_jobs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancel_requested' END,detail=CASE WHEN status='queued' THEN 'Cancelled before Microsoft Graph collection began' ELSE 'Cancellation requested; finishing the current read safely' END,finished_at=CASE WHEN status='queued' THEN now() ELSE finished_at END,updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status IN ('queued','running','cancel_requested') RETURNING *", [id, tenantId])).rows[0];
    return row ? mapJob(row) : null;
  }

  async isScanCancellationRequested(id: string, workerId: string): Promise<boolean> { const row = (await this.pool.query("SELECT 1 FROM scan_jobs WHERE id=$1 AND worker_id=$2 AND status='cancel_requested'", [id, workerId])).rows[0]; return Boolean(row); }
  async cancelJob(id: string, workerId: string): Promise<void> { const result = await this.pool.query("UPDATE scan_jobs SET status='cancelled',detail='Scan cancelled safely; no partial snapshot was published',finished_at=now(),updated_at=now(),worker_id=NULL,locked_at=NULL WHERE id=$1 AND worker_id=$2 AND status='cancel_requested'", [id, workerId]); if (result.rowCount !== 1) throw new Error("The scan job is not cancellable by this worker."); await this.pool.query("DELETE FROM scan_checkpoints WHERE job_id=$1", [id]); }

  async getScanCheckpoint(id: string, tenantId: string): Promise<ScanCheckpoint | null> {
    const row = (await this.pool.query<EncryptedRow>("SELECT job_id AS id,tenant_id,iv,ciphertext,auth_tag,updated_at FROM scan_checkpoints WHERE job_id=$1 AND tenant_id=$2", [id, tenantId])).rows[0];
    return row ? decryptJson<ScanCheckpoint>(encrypted(row), this.key, checkpointContext(id, tenantId)) : null;
  }

  async saveScanCheckpoint(checkpoint: ScanCheckpoint, workerId: string): Promise<void> {
    const value = { ...checkpoint, updatedAt: new Date().toISOString() };
    const payload = encryptJson(value, this.key, checkpointContext(value.jobId, value.tenantId));
    const result = await this.pool.query("INSERT INTO scan_checkpoints (job_id,tenant_id,iv,ciphertext,auth_tag,updated_at) SELECT id,tenant_id,$3,$4,$5,now() FROM scan_jobs WHERE id=$1 AND tenant_id=$2 AND worker_id=$6 AND status='running' ON CONFLICT (job_id) DO UPDATE SET iv=EXCLUDED.iv,ciphertext=EXCLUDED.ciphertext,auth_tag=EXCLUDED.auth_tag,updated_at=now()", [value.jobId, value.tenantId, payload.iv, payload.ciphertext, payload.authTag, workerId]);
    if (result.rowCount !== 1) throw new Error("The scan checkpoint is not owned by this worker.");
  }

  async recentSnapshots(tenantId: string, limit = 20): Promise<TenantSnapshot[]> {
    const bounded = Math.max(1, Math.min(limit, 100));
    const result = await this.pool.query<EncryptedRow>("SELECT * FROM snapshots WHERE tenant_id=$1 ORDER BY scanned_at DESC LIMIT $2", [tenantId, bounded]);
    return result.rows.map((row) => decryptJson<TenantSnapshot>(encrypted(row), this.key, snapshotContext(row.id, row.tenant_id, row.scanned_at!.toISOString())));
  }

  async recordAccess(tenantId: string, sessionId: string | null, action: string, resourceType: string, resourceId?: string): Promise<void> {
    await this.pool.query("INSERT INTO access_events (tenant_id,session_id,action,resource_type,resource_id) VALUES ($1,$2,$3,$4,$5)", [tenantId, sessionId, action, resourceType, resourceId ?? null]);
  }

  async recentAccessEvents(tenantId: string, limit = 100): Promise<AccessEvent[]> {
    const bounded = Math.max(1, Math.min(limit, 100));
    const result = await this.pool.query("SELECT id,tenant_id,session_id,action,resource_type,resource_id,created_at FROM access_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2", [tenantId, bounded]);
    return result.rows.map((row) => ({ id: String(row.id), tenantId: String(row.tenant_id), sessionId: row.session_id ? String(row.session_id) : null, action: String(row.action), resourceType: String(row.resource_type), resourceId: row.resource_id ? String(row.resource_id) : null, createdAt: iso(row.created_at as Date)! }));
  }

  async getThreatReview(tenantId: string, snapshotId: string, findingId: string): Promise<ThreatReview | null> {
    const row = (await this.pool.query<EncryptedRow>("SELECT tenant_id,snapshot_id AS id,finding_id,iv,ciphertext,auth_tag,updated_at FROM threat_reviews WHERE tenant_id=$1 AND snapshot_id=$2 AND finding_id=$3", [tenantId, snapshotId, findingId])).rows[0] as (EncryptedRow & { finding_id?: string; updated_at?: Date }) | undefined;
    return row ? decryptJson<ThreatReview>(encrypted(row), this.key, reviewContext(tenantId, snapshotId, findingId)) : null;
  }

  async upsertThreatReview(review: ThreatReview, sessionId: string | null): Promise<ThreatReview> {
    const value = { ...review, updatedAt: new Date().toISOString() };
    const payload = encryptJson(value, this.key, reviewContext(value.tenantId, value.snapshotId, value.findingId));
    await this.pool.query("INSERT INTO threat_reviews (tenant_id,snapshot_id,finding_id,iv,ciphertext,auth_tag,updated_at) SELECT $1,$2,$3,$4,$5,$6,now() FROM snapshots WHERE tenant_id=$1 AND id=$2 ON CONFLICT (tenant_id,snapshot_id,finding_id) DO UPDATE SET iv=EXCLUDED.iv,ciphertext=EXCLUDED.ciphertext,auth_tag=EXCLUDED.auth_tag,updated_at=now()", [value.tenantId, value.snapshotId, value.findingId, payload.iv, payload.ciphertext, payload.authTag]);
    await this.recordAccess(value.tenantId, sessionId, "update", "threat_review", value.findingId);
    return value;
  }

  async close(): Promise<void> { await this.pool.end(); }

  private async transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try { await client.query("BEGIN"); const result = await operation(client); await client.query("COMMIT"); return result; }
    // The rethrow below is covered; v8 additionally counts the catch block's own normal
    // completion, which an unconditional throw makes unreachable, hence the ignore.
    catch (error) { await client.query("ROLLBACK"); /* c8 ignore next */ throw error; }
    finally { client.release(); }
  }
}

function encrypted(row: EncryptedRow): EncryptedValue { return { iv: row.iv, ciphertext: row.ciphertext, authTag: row.auth_tag }; }
function flowContext(id: string, tenantId: string) { return `auth-flow:${id}:${tenantId}`; }
function sessionContext(id: string, tenantId: string) { return `session:${id}:${tenantId}`; }
function snapshotContext(id: string, tenantId: string, scannedAt: string) { return `snapshot:${id}:${tenantId}:${scannedAt}`; }
function reviewContext(tenantId: string, snapshotId: string, findingId: string) { return `threat-review:${tenantId}:${snapshotId}:${findingId}`; }
function checkpointContext(id: string, tenantId: string) { return `scan-checkpoint:${id}:${tenantId}`; }
function iso(value: Date | string | null): string | null { return value ? new Date(value).toISOString() : null; }
function mapJob(row: Record<string, unknown>): ScanJob {
  return { id: String(row.id), tenantId: String(row.tenant_id), sessionId: row.session_id ? String(row.session_id) : null, status: row.status as ScanJob["status"], stage: row.stage as ScanJobStage, collected: Number(row.collected), detail: String(row.detail), createdAt: iso(row.created_at as Date)!, updatedAt: iso(row.updated_at as Date)!, finishedAt: iso(row.finished_at as Date | null), snapshotId: row.snapshot_id ? String(row.snapshot_id) : null, completion: row.completion as ScanJob["completion"], error: row.error ? String(row.error) : null, attempt: Number(row.attempt), workerId: row.worker_id ? String(row.worker_id) : null };
}
