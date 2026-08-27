import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { PostgresBackend, type DurableSession, type ScanJob, type ScanJobStage } from "@entra-explorer/backend";
import { normalizeTenantScan, ReadOnlyGraphClient, scanTenant, ScanCancelledError } from "@entra-explorer/graph";
import type { RawTenantScan } from "@entra-explorer/graph";
import type { AccountInfo } from "@azure/msal-node";
import { parseEntraConfig } from "./server/config-core";
import { acquireSilent } from "./server/auth/msal";

const parsedConfig = parseEntraConfig(process.env);
if (!parsedConfig.enabled) throw new Error("The scan worker requires ENTRA_ENABLE_LIVE=true.");
const liveConfig = parsedConfig;
const workerId = `${hostname()}:${process.pid}:${randomUUID()}`;
const backend = new PostgresBackend({ connectionString: liveConfig.databaseUrl, encryptionKey: liveConfig.dataEncryptionKey });
let stopping = false;
process.on("SIGTERM", () => { stopping = true; });
process.on("SIGINT", () => { stopping = true; });

async function main() {
  await backend.migrate();
  await backend.recoverStaleJobs(liveConfig.tenantId, new Date(Date.now() - 10 * 60 * 1_000));
  while (!stopping) {
    const job = await backend.claimNextJob(workerId, liveConfig.tenantId);
    if (job && job.tenantId !== liveConfig.tenantId) throw new Error("The claimed scan job crossed the configured tenant boundary.");
    if (!job) { await delay(1_000); continue; }
    await run(job);
  }
  await backend.close();
}

async function run(job: ScanJob): Promise<void> {
  try {
    if (!job.sessionId) throw new Error("The scan no longer has an authenticated session.");
    let session = await backend.getSession(job.sessionId, job.tenantId);
    if (!session) throw new Error("The Microsoft session expired before the scan began.");
    let currentStage: ScanJobStage = "applications";
    let currentCollected = 0;
    let progressWrites = Promise.resolve();
    const accessToken = async () => {
      if (session!.accessTokenExpiresAt - Date.now() > 5 * 60 * 1_000) return session!.accessToken;
      session = await refreshSession(session!);
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
      shouldCancel: () => backend.isScanCancellationRequested(job.id, workerId),
      enabledScopes: liveConfig.graphScopes,
      resumeFrom: checkpoint?.payload as RawTenantScan | undefined,
      onCheckpoint: (payload) => backend.saveScanCheckpoint({ jobId: job.id, tenantId: job.tenantId, payload, updatedAt: new Date().toISOString() }, workerId),
    });
    await backend.updateJobProgress(job.id, workerId, "normalizing", job.collected, "Normalizing source records into explainable relationships");
    const snapshot = normalizeTenantScan(raw);
    await backend.completeJob(job.id, workerId, snapshot, new Date(Date.now() - 30 * 24 * 60 * 60 * 1_000));
  } catch (error) {
    if (error instanceof ScanCancelledError || await backend.isScanCancellationRequested(job.id, workerId)) { await backend.cancelJob(job.id, workerId); return; }
    await backend.failJob(job.id, workerId, "Scan failed. Review worker diagnostics; tokens and response bodies are not included.");
  }
}

async function refreshSession(session: DurableSession): Promise<DurableSession> {
  const refreshed = await acquireSilent(liveConfig, session.account as AccountInfo, session.tokenCache);
  if (!refreshed?.result.accessToken) throw new Error("Microsoft token refresh failed.");
  const updated = { ...session, accessToken: refreshed.result.accessToken, accessTokenExpiresAt: refreshed.result.expiresOn?.getTime() ?? Date.now() + 55 * 60 * 1_000, tokenCache: refreshed.tokenCache };
  await backend.updateSession(updated);
  return updated;
}

function delay(milliseconds: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

void main().catch(() => {
  console.error("Worker stopped unexpectedly. Sensitive diagnostics are suppressed.");
  process.exitCode = 1;
});
