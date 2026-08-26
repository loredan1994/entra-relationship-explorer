import { randomUUID, timingSafeEqual } from "node:crypto";
import type { TenantSnapshot } from "@entra-explorer/domain";
import { Pool, type PoolClient, type QueryResultRow } from "pg";
import { decryptJson, encryptJson, type EncryptedValue } from "./crypto";
import { DATABASE_SCHEMA } from "./schema";
import type { AccessEvent, Backend, BackendHealth, DurableAuthFlow, DurableSession, ScanJob, ScanJobStage } from "./types";

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
    const row = result.rows[0] ?? (await this.pool.query("SELECT * FROM scan_jobs WHERE tenant_id=$1 AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1", [tenantId])).rows[0];
    if (!row) throw new Error("A valid tenant session is required.");
    await this.recordAccess(tenantId, sessionId, "enqueue", "scan_job", row.id);
    return mapJob(row);
  }

  async getJob(id: string, tenantId: string): Promise<ScanJob | null> { const row = (await this.pool.query("SELECT * FROM scan_jobs WHERE id=$1 AND tenant_id=$2", [id, tenantId])).rows[0]; return row ? mapJob(row) : null; }
  async getLatestJob(tenantId: string): Promise<ScanJob | null> { const row = (await this.pool.query("SELECT * FROM scan_jobs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1", [tenantId])).rows[0]; return row ? mapJob(row) : null; }

  async recoverStaleJobs(staleBefore: Date): Promise<number> {
    const result = await this.pool.query("UPDATE scan_jobs SET status='queued',worker_id=NULL,locked_at=NULL,available_at=now(),detail='Recovered after the previous worker stopped',updated_at=now() WHERE status='running' AND updated_at<$1", [staleBefore]);
    return result.rowCount ?? 0;
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
      await client.query("DELETE FROM snapshots WHERE tenant_id=$1 AND scanned_at<$2", [job.tenant_id, retainAfter]);
      await client.query("INSERT INTO access_events (tenant_id,session_id,action,resource_type,resource_id) VALUES ($1,$2,'create','snapshot',$3)", [job.tenant_id, job.session_id, snapshot.id]);
    });
  }

  async failJob(id: string, workerId: string, error: string): Promise<void> {
    await this.pool.query("UPDATE scan_jobs SET status='failed',detail='The read-only scan stopped before a snapshot could be saved',error=$3,finished_at=now(),updated_at=now(),worker_id=NULL,locked_at=NULL WHERE id=$1 AND worker_id=$2 AND status='running'", [id, workerId, error.slice(0, 500)]);
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

  async close(): Promise<void> { await this.pool.end(); }

  private async transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try { await client.query("BEGIN"); const result = await operation(client); await client.query("COMMIT"); return result; }
    catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }
}

function encrypted(row: EncryptedRow): EncryptedValue { return { iv: row.iv, ciphertext: row.ciphertext, authTag: row.auth_tag }; }
function flowContext(id: string, tenantId: string) { return `auth-flow:${id}:${tenantId}`; }
function sessionContext(id: string, tenantId: string) { return `session:${id}:${tenantId}`; }
function snapshotContext(id: string, tenantId: string, scannedAt: string) { return `snapshot:${id}:${tenantId}:${scannedAt}`; }
function iso(value: Date | string | null): string | null { return value ? new Date(value).toISOString() : null; }
function mapJob(row: Record<string, unknown>): ScanJob {
  return { id: String(row.id), tenantId: String(row.tenant_id), sessionId: row.session_id ? String(row.session_id) : null, status: row.status as ScanJob["status"], stage: row.stage as ScanJobStage, collected: Number(row.collected), detail: String(row.detail), createdAt: iso(row.created_at as Date)!, updatedAt: iso(row.updated_at as Date)!, finishedAt: iso(row.finished_at as Date | null), snapshotId: row.snapshot_id ? String(row.snapshot_id) : null, completion: row.completion as ScanJob["completion"], error: row.error ? String(row.error) : null, attempt: Number(row.attempt), workerId: row.worker_id ? String(row.worker_id) : null };
}
