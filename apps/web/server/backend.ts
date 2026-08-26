import "server-only";
import { PostgresBackend } from "@entra-explorer/backend";
import type { LiveEntraConfig } from "./config-core";

let singleton: { databaseUrl: string; backend: PostgresBackend; ready: Promise<void> } | undefined;

export async function getBackend(config: LiveEntraConfig): Promise<PostgresBackend> {
  if (!singleton || singleton.databaseUrl !== config.databaseUrl) {
    const backend = new PostgresBackend({ connectionString: config.databaseUrl, encryptionKey: config.dataEncryptionKey });
    singleton = { databaseUrl: config.databaseUrl, backend, ready: backend.migrate() };
  }
  await singleton.ready;
  return singleton.backend;
}
