import { PostgresBackend } from "@entra-explorer/backend";
import { parseEntraConfig } from "./server/config-core";

async function main() {
  const config = parseEntraConfig(process.env);
  if (!config.enabled) throw new Error("Migrations require ENTRA_ENABLE_LIVE=true.");
  const backend = new PostgresBackend({ connectionString: config.databaseUrl, encryptionKey: config.dataEncryptionKey });
  await backend.migrate();
  await backend.close();
}

void main().catch(() => {
  console.error("Migration failed. Sensitive diagnostics are suppressed.");
  process.exitCode = 1;
});
