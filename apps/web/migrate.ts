import { PostgresBackend } from "@entra-explorer/backend";
import { parseBackendConfig } from "./server/config-core";

async function main() {
  const config = parseBackendConfig(process.env);
  const backend = new PostgresBackend({ connectionString: config.databaseUrl, encryptionKey: config.dataEncryptionKey });
  await backend.migrate();
  await backend.close();
}

void main().catch(() => {
  console.error("Migration failed. Sensitive diagnostics are suppressed.");
  process.exitCode = 1;
});
