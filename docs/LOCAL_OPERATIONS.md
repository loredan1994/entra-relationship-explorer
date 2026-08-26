# Local container operations

## Start

1. Start Docker Desktop.
2. Run `pnpm dev:live` from the repository root.
3. Open `http://127.0.0.1:3200/settings` and connect the configured tenant.

Startup retrieves three values directly from Azure Key Vault `your-key-vault`: the local app-registration credential, the 32-byte data-encryption key, and the PostgreSQL password. Values remain in process and container environment memory and are never written to Git.

## Services

- `postgres`: persistent local database on `127.0.0.1:54320`.
- `migrate`: one-shot idempotent schema migration.
- `web`: production Next.js standalone server on `127.0.0.1:3200` in the non-root distroless application image.
- `worker`: durable queue consumer and the only service that executes tenant scans, using the same production-only image.

`GET /api/v1/health` reports the web/database state and the `read-only` Graph boundary.

## Stop and recover

- `docker compose down` stops services while preserving the named PostgreSQL volume.
- Starting again applies migrations before web and worker become available.
- A stopped web service does not lose sessions or jobs.
- A worker interrupted during a scan leaves its job durable. On startup, jobs whose worker lease has been stale for ten minutes return to the queue.

Removing the named volume is intentionally not part of the normal runbook because that permanently deletes encrypted sessions, snapshots, job history, and access events.

## Throttling and partial data

The Graph client honors `Retry-After` and `x-ms-retry-after-ms`, uses jittered exponential fallback, retries bounded transient failures, refreshes tokens between pages when necessary, and exposes retry state through the durable job progress. If an endpoint exhausts retries, its evidence is retained as skipped and the snapshot is marked partial rather than presented as complete.
