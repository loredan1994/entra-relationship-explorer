import "server-only";
import { PostgresBackend } from "@entra-explorer/backend";
import type { LiveEntraConfig } from "./config-core";

let singleton: { databaseUrl: string; backend: PostgresBackend; ready: Promise<void> } | undefined;

export async function getBackend(config: LiveEntraConfig): Promise<PostgresBackend> {
  if (!singleton || singleton.databaseUrl !== config.databaseUrl) {
    const backend = new PostgresBackend({ connectionString: config.databaseUrl, encryptionKey: config.dataEncryptionKey });
    const connection = { databaseUrl: config.databaseUrl, backend, ready: backend.migrate() };
    connection.ready = connection.ready.catch(async error => {
      // All callers share this cleanup. A later request can retry after the
      // database recovers, without replacing a newer connection's initialization.
      if (singleton === connection) singleton = undefined;
      try { await backend.close(); } catch { /* Preserve the initialization error. */ }
      throw error;
    });
    singleton = connection;
  }
  const connection = singleton;
  await connection.ready;
  return connection.backend;
}
