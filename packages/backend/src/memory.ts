import { randomUUID, timingSafeEqual } from "node:crypto";
import type { TenantSnapshot } from "@entra-explorer/domain";
import type { AccessEvent, Backend, BackendHealth, DurableAuthFlow, DurableSession, ScanCheckpoint, ScanJob, ScanJobStage, ThreatReview } from "./types";

function copy<T>(value: T): T {
  return structuredClone(value);
}

function secretsEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class MemoryBackend implements Backend {
  private readonly flows = new Map<string, DurableAuthFlow>();
  private readonly sessions = new Map<string, DurableSession>();
  private readonly jobs = new Map<string, ScanJob>();
  private readonly snapshots = new Map<string, TenantSnapshot[]>();
  // Stryker disable next-line ArrayDeclaration: every read filters by tenant, so a seeded entry is unreachable.
  private readonly accessEvents: AccessEvent[] = [];
  private readonly threatReviews = new Map<string, ThreatReview>();
  private readonly scanCheckpoints = new Map<string, ScanCheckpoint>();

  async migrate(): Promise<void> {}
  async health(): Promise<BackendHealth> { return { ok: true, database: "memory" }; }

  async createAuthFlow(flow: DurableAuthFlow): Promise<void> { this.flows.set(flow.id, copy(flow)); }

  async consumeAuthFlow(id: string, tenantId: string, state: string): Promise<DurableAuthFlow | null> {
    const flow = this.flows.get(id);
    if (!flow || flow.tenantId !== tenantId || !secretsEqual(flow.state, state)) return null;
    this.flows.delete(id);
    if (flow.expiresAt <= Date.now()) return null;
    return copy(flow);
  }

  async createSession(session: DurableSession): Promise<void> { this.sessions.set(session.id, copy(session)); }

  async getSession(id: string, tenantId: string): Promise<DurableSession | null> {
    const session = this.sessions.get(id);
    if (!session || session.tenantId !== tenantId || session.sessionExpiresAt <= Date.now()) return null;
    return copy(session);
  }

  async updateSession(session: DurableSession): Promise<void> {
    const existing = this.sessions.get(session.id);
    if (!existing || existing.tenantId !== session.tenantId) throw new Error("Session was not found in this tenant.");
    this.sessions.set(session.id, copy(session));
  }

  async deleteSession(id: string, tenantId: string): Promise<void> {
    const session = this.sessions.get(id);
    if (session?.tenantId === tenantId) this.sessions.delete(id);
  }

  async enqueueScan(tenantId: string, sessionId: string): Promise<ScanJob> {
    const session = await this.getSession(sessionId, tenantId);
    if (!session) throw new Error("A valid tenant session is required.");
    const active = [...this.jobs.values()].find((job) => job.tenantId === tenantId && (job.status === "queued" || job.status === "running" || job.status === "cancel_requested"));
    if (active) return copy(active);
    const now = new Date().toISOString();
    const job: ScanJob = { id: randomUUID(), tenantId, sessionId, status: "queued", stage: "applications", collected: 0, detail: "Waiting to begin the read-only scan", createdAt: now, updatedAt: now, finishedAt: null, snapshotId: null, completion: null, error: null, attempt: 0, workerId: null };
    this.jobs.set(job.id, job);
    return copy(job);
  }

  async getJob(id: string, tenantId: string): Promise<ScanJob | null> {
    const job = this.jobs.get(id);
    return job?.tenantId === tenantId ? copy(job) : null;
  }

  async getLatestJob(tenantId: string): Promise<ScanJob | null> {
    const job = [...this.jobs.values()].filter((candidate) => candidate.tenantId === tenantId).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
    return job ? copy(job) : null;
  }

  async recoverStaleJobs(tenantId: string, staleBefore: Date): Promise<number> {
    let recovered = 0;
    for (const job of this.jobs.values()) {
      if (job.tenantId !== tenantId) continue;
      if (job.status === "cancel_requested" && new Date(job.updatedAt) < staleBefore) {
        job.status = "cancelled";
        job.workerId = null;
        job.finishedAt = new Date().toISOString();
        job.detail = "Cancellation completed after the previous worker stopped";
        job.updatedAt = job.finishedAt;
        this.scanCheckpoints.delete(job.id);
        recovered += 1;
      } else if (job.status === "running" && new Date(job.updatedAt) < staleBefore) {
        job.status = "queued";
        job.workerId = null;
        job.detail = "Recovered after the previous worker stopped";
        job.updatedAt = new Date().toISOString();
        recovered += 1;
      }
    }
    return recovered;
  }

  async claimNextJob(workerId: string, tenantId: string): Promise<ScanJob | null> {
    // Stryker disable next-line MethodExpression,ArrowFunction: Map iteration is insertion order, which is already createdAt order; the sort states the intent.
    const job = [...this.jobs.values()].filter((candidate) => candidate.tenantId === tenantId && candidate.status === "queued").sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (!job) return null;
    job.status = "running";
    job.workerId = workerId;
    job.attempt += 1;
    job.detail = "Starting Microsoft Graph reads";
    job.updatedAt = new Date().toISOString();
    return copy(job);
  }

  async updateJobProgress(id: string, workerId: string, stage: ScanJobStage, collected: number, detail: string): Promise<void> {
    const job = this.ownedRunningJob(id, workerId);
    job.stage = stage;
    job.collected = collected;
    job.detail = detail;
    job.updatedAt = new Date().toISOString();
  }

  async completeJob(id: string, workerId: string, snapshot: TenantSnapshot, retainAfter: Date): Promise<void> {
    const job = this.ownedRunningJob(id, workerId);
    if (snapshot.tenant.tenantId !== job.tenantId) throw new Error("Snapshot and job tenant boundaries do not match.");
    // Stryker disable next-line ArrayDeclaration: the retention filter below drops any seeded entry, which has no scannedAt.
    const items = this.snapshots.get(job.tenantId) ?? [];
    items.push(copy(snapshot));
    this.snapshots.set(job.tenantId, items.filter((item) => new Date(item.scannedAt) >= retainAfter).sort((a, b) => b.scannedAt.localeCompare(a.scannedAt)));
    job.status = "complete";
    job.stage = "complete";
    job.snapshotId = snapshot.id;
    job.completion = snapshot.completion.status;
    job.collected = snapshot.nodes.length + snapshot.edges.length;
    job.detail = `${snapshot.nodes.length} objects and ${snapshot.edges.length} relationships normalized`;
    job.finishedAt = new Date().toISOString();
    job.updatedAt = job.finishedAt;
    job.workerId = null;
    this.scanCheckpoints.delete(id);
  }

  async failJob(id: string, workerId: string, error: string): Promise<void> {
    const job = this.ownedRunningJob(id, workerId);
    job.status = "failed";
    job.detail = "The read-only scan stopped before a snapshot could be saved";
    job.error = error;
    job.finishedAt = new Date().toISOString();
    job.updatedAt = job.finishedAt;
    job.workerId = null;
    this.scanCheckpoints.delete(id);
  }

  async requestScanCancellation(id: string, tenantId: string): Promise<ScanJob | null> {
    const job = this.jobs.get(id);
    if (!job || job.tenantId !== tenantId || !["queued", "running", "cancel_requested"].includes(job.status)) return null;
    if (job.status === "queued") { job.status = "cancelled"; job.finishedAt = new Date().toISOString(); job.detail = "Cancelled before Microsoft Graph collection began"; this.scanCheckpoints.delete(id); }
    else { job.status = "cancel_requested"; job.detail = "Cancellation requested; finishing the current read safely"; }
    job.updatedAt = new Date().toISOString();
    return copy(job);
  }

  async isScanCancellationRequested(id: string, workerId: string): Promise<boolean> { const job = this.jobs.get(id); return job?.workerId === workerId && job.status === "cancel_requested"; }
  async cancelJob(id: string, workerId: string): Promise<void> { const job = this.jobs.get(id); if (!job || job.workerId !== workerId || job.status !== "cancel_requested") throw new Error("The scan job is not cancellable by this worker."); job.status = "cancelled"; job.detail = "Scan cancelled safely; no partial snapshot was published"; job.finishedAt = new Date().toISOString(); job.updatedAt = job.finishedAt; job.workerId = null; this.scanCheckpoints.delete(id); }
  async getScanCheckpoint(id: string, tenantId: string): Promise<ScanCheckpoint | null> { const value = this.scanCheckpoints.get(id); return value?.tenantId === tenantId ? copy(value) : null; }
  async saveScanCheckpoint(checkpoint: ScanCheckpoint, workerId: string): Promise<void> { this.ownedRunningJob(checkpoint.jobId, workerId); this.scanCheckpoints.set(checkpoint.jobId, { ...copy(checkpoint), updatedAt: new Date().toISOString() }); }

  async recentSnapshots(tenantId: string, limit = 20): Promise<TenantSnapshot[]> {
    return copy((this.snapshots.get(tenantId) ?? []).slice(0, Math.max(1, Math.min(limit, 100))));
  }

  async recordAccess(tenantId: string, sessionId: string | null, action: string, resourceType: string, resourceId?: string): Promise<void> {
    this.accessEvents.push({ id: randomUUID(), tenantId, sessionId, action, resourceType, resourceId: resourceId ?? null, createdAt: new Date().toISOString() });
  }

  async recentAccessEvents(tenantId: string, limit = 100): Promise<AccessEvent[]> {
    const bounded = Math.max(1, Math.min(limit, 100));
    return copy(this.accessEvents.filter((event) => event.tenantId === tenantId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, bounded));
  }
  async getThreatReview(tenantId: string, snapshotId: string, findingId: string): Promise<ThreatReview | null> { const value = this.threatReviews.get(`${tenantId}:${snapshotId}:${findingId}`); return value ? copy(value) : null; }
  async upsertThreatReview(review: ThreatReview, sessionId: string | null): Promise<ThreatReview> { const value = { ...copy(review), updatedAt: new Date().toISOString() }; this.threatReviews.set(`${value.tenantId}:${value.snapshotId}:${value.findingId}`, value); await this.recordAccess(value.tenantId, sessionId, "update", "threat_review", value.findingId); return copy(value); }
  async close(): Promise<void> {}

  private ownedRunningJob(id: string, workerId: string): ScanJob {
    const job = this.jobs.get(id);
    if (!job || job.status !== "running" || job.workerId !== workerId) throw new Error("The scan job is not owned by this worker.");
    return job;
  }
}
