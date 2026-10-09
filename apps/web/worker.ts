import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { PostgresBackend, WorkerPoller } from "@entra-explorer/backend";
import { parseEntraConfig } from "./server/config-core";
import { runScanJob } from "./server/worker-run";

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
  const poller = new WorkerPoller(backend, liveConfig.tenantId, workerId);
  while (!stopping) {
    const job = await poller.poll();
    if (job && job.tenantId !== liveConfig.tenantId) throw new Error("The claimed scan job crossed the configured tenant boundary.");
    if (!job) { await delay(1_000); continue; }
    await runScanJob(backend, job, workerId, liveConfig);
  }
  await backend.close();
}

function delay(milliseconds: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

void main().catch(() => {
  console.error("Worker stopped unexpectedly. Sensitive diagnostics are suppressed.");
  process.exitCode = 1;
});
