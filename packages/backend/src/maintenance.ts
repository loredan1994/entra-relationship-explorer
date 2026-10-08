import type { Backend, ScanJob } from "./types";

export const RETENTION_MS = 30 * 86_400_000;
export const LEASE_MS = 10 * 60_000;

/** Called repeatedly while idle, so a quick restart can recover after lease expiry. */
export class WorkerPoller {
  private maintainedAt = Number.NEGATIVE_INFINITY;
  constructor(private readonly backend: Backend, private readonly tenantId: string, private readonly workerId: string) {}

  async poll(now = Date.now()): Promise<ScanJob | null> {
    if (now - this.maintainedAt >= 60_000) {
      await this.backend.recoverStaleJobs(this.tenantId, new Date(now - LEASE_MS));
      await this.backend.pruneExpiredData(this.tenantId, new Date(now - RETENTION_MS));
      this.maintainedAt = now;
    }
    return this.backend.claimNextJob(this.workerId, this.tenantId);
  }
}
