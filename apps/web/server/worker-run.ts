import type { Backend, DurableSession, ScanJob, ScanJobStage } from "@entra-explorer/backend";
import { normalizeTenantScan, ReadOnlyGraphClient, scanTenant, ScanCancelledError, type RawTenantScan } from "@entra-explorer/graph";
import type { AccountInfo } from "@azure/msal-node";
import type { LiveEntraConfig } from "./config-core";
import { acquireSilent } from "./auth/msal";

export async function runScanJob(backend: Backend, job: ScanJob, workerId: string, liveConfig: LiveEntraConfig): Promise<void> {
  let leaseLost = false;
  let refreshFailed = false;
  const heartbeat = setInterval(() => { void backend.heartbeatJob(job.id, workerId).then(owned => { if (!owned) leaseLost = true; }).catch(() => { leaseLost = true; }); }, 30_000);
  const shouldCancel = async () => {
    if (leaseLost) throw new Error("Worker lease lost.");
    const state = await backend.getScanAccessState(job.id, workerId, job.tenantId);
    if (state === "lease_lost") { leaseLost = true; throw new Error("Worker lease lost."); }
    if (state === "session_unavailable") throw new ScanSessionUnavailableError();
    if (state !== "cancel_requested" && refreshFailed) throw new Error("Microsoft token refresh failed.");
    return state === "cancel_requested";
  };
  const assertActive = async () => { if (await shouldCancel()) throw new ScanCancelledError(); };
  try {
    await assertActive();
    if (!job.sessionId) throw new ScanSessionUnavailableError();
    const initialSession = await backend.getSession(job.sessionId, job.tenantId);
    if (!initialSession) throw new ScanSessionUnavailableError();
    let session = initialSession;
    let refreshing: Promise<DurableSession> | null = null;
    let currentStage: ScanJobStage = "applications";
    let currentCollected = 0;
    let progressWrites = Promise.resolve();
    const accessToken = async () => {
      if (session.sessionExpiresAt <= Date.now()) throw new ScanSessionUnavailableError();
      if (session.accessTokenExpiresAt - Date.now() > 5 * 60 * 1_000) return session.accessToken;
      // Fan-out reads share one refresh rather than racing writes to the MSAL cache.
      refreshing ??= refreshSession(backend, liveConfig, session)
        .catch(error => { refreshFailed = true; throw error; })
        .finally(() => { refreshing = null; });
      session = await refreshing;
      return session.accessToken;
    };
    const progress = (stage: ScanJobStage, collected: number, detail: string) => {
      currentStage = stage;
      currentCollected = collected;
      progressWrites = progressWrites.then(() => backend.updateJobProgress(job.id, workerId, stage, collected, detail)).catch(() => undefined);
    };
    const client = new ReadOnlyGraphClient(accessToken, {
      maxRetries: 8,
      onRetry: ({ status, attempt, delayMs }) => progress(currentStage, currentCollected, `${status === 429 ? "Microsoft Graph throttled the scan" : "A transient read failed"}; retry ${attempt} in ${Math.ceil(delayMs / 1_000)} seconds`),
    });
    await progressWrites;
    const checkpoint = await backend.getScanCheckpoint(job.id, job.tenantId);
    if (checkpoint) progress(currentStage, currentCollected, `Resuming encrypted checkpoint from attempt ${Math.max(1, job.attempt - 1)}`);
    const raw = await scanTenant(client, job.tenantId, {
      concurrency: 4,
      onProgress: (event) => progress(event.stage, event.collected, event.detail),
      shouldCancel,
      enabledScopes: liveConfig.graphScopes,
      collectDirectoryAudits: liveConfig.collectDirectoryAudits,
      resumeFrom: checkpoint?.payload as RawTenantScan | undefined,
      onCheckpoint: (payload) => backend.saveScanCheckpoint({ jobId: job.id, tenantId: job.tenantId, payload, updatedAt: new Date().toISOString() }, workerId),
    });
    await progressWrites;
    await assertActive();
    await backend.updateJobProgress(job.id, workerId, "normalizing", currentCollected, "Normalizing source records into explainable relationships");
    const snapshot = normalizeTenantScan(raw);
    await assertActive();
    await backend.completeJob(job.id, workerId, snapshot, new Date(Date.now() - 30 * 24 * 60 * 60 * 1_000));
  } catch (error) {
    if (leaseLost) return;
    await finishStoppedJob(backend, job, workerId, error instanceof ScanSessionUnavailableError
      ? "The scan session expired or was signed out. Sign in and start a new read-only scan."
      : "Scan failed. Review worker diagnostics; tokens and response bodies are not included.");
  } finally {
    clearInterval(heartbeat);
  }
}

class ScanSessionUnavailableError extends Error {}

async function finishStoppedJob(backend: Backend, job: ScanJob, workerId: string, detail: string): Promise<void> {
  const state = await backend.getScanAccessState(job.id, workerId, job.tenantId);
  if (state === "lease_lost") return;
  try {
    if (state === "cancel_requested") await backend.cancelJob(job.id, workerId);
    else await backend.failJob(job.id, workerId, detail);
  } catch (error) {
    // Recovery or cancellation may win between the state read and terminal write.
    // Never fail the worker process merely because it no longer owns this job.
    const latest = await backend.getScanAccessState(job.id, workerId, job.tenantId);
    if (latest === "lease_lost") return;
    if (state !== "cancel_requested" && latest === "cancel_requested") { await backend.cancelJob(job.id, workerId); return; }
    throw error;
  }
}

async function refreshSession(backend: Backend, liveConfig: LiveEntraConfig, session: DurableSession): Promise<DurableSession> {
  const refreshed = await acquireSilent(liveConfig, session.account as AccountInfo, session.tokenCache);
  if (!refreshed?.result.accessToken) throw new Error("Microsoft token refresh failed.");
  const updated = { ...session, accessToken: refreshed.result.accessToken, accessTokenExpiresAt: refreshed.result.expiresOn?.getTime() ?? Date.now() + 55 * 60 * 1_000, tokenCache: refreshed.tokenCache };
  await backend.updateSession(updated);
  return updated;
}
