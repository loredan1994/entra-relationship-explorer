# Local container operations

## Start

1. Start Docker Desktop.
2. Run `pnpm dev:live` from the repository root.
3. Open `http://127.0.0.1:3200/settings` and connect the tenant you configured in `ENTRA_TENANT_ID`.

Startup reads three values from outside the repository: the app-registration credential, the 32-byte data-encryption key, and the PostgreSQL password. Set `ENTRA_KEY_VAULT_NAME` to read them from an Azure Key Vault you control, or place them in a git-ignored `.env.local`. Values remain in process and container environment memory and are never written to Git.

## Services

- `postgres`: persistent local database on `127.0.0.1:54320`.
- `migrate`: one-shot idempotent schema migration.
- `web`: production Next.js standalone server on `127.0.0.1:3200` in the non-root distroless application image.
- `worker`: durable queue consumer and the only service that executes tenant scans, using the same production-only image.

`GET /api/v1/health` reports the web/database state and the `read-only` Graph boundary.

Container builds cache the frozen dependency install independently of source edits. Changes to a workspace manifest, lockfile, workspace configuration or pnpm patch invalidate that layer. Local package stores and nested environment files are excluded from the build context.

Review decisions use a revision check and are serialized with snapshot publication within the tenant. If a newer scan completes before a decision is saved, the API returns 409 and the reviewer must reload the evidence. Review JSON is limited to 128 KiB of actual streamed bytes; oversized requests return 413. These writes affect the local database only.

## Stop and recover

- `docker compose down` stops services while preserving the named PostgreSQL volume.
- Starting again applies migrations before web and worker become available.
- Concurrent startup migrations acquire a database-wide transaction lock before schema changes and expired-auth cleanup. Other instances wait for the migration to commit; failures roll back and release the lock.
- A stopped web service does not lose sessions or jobs. Checkpoint writes lock the owning job row so a recovered worker’s progress cannot be overwritten by its predecessor.
- Cancellation and lost worker ownership are checked between pages and before request dispatch. Retry backoff sleeps are split into intervals of at most one second, with an ownership check after each interval; database latency can delay those checks. An already-running HTTP request retains its bounded timeout.
- A worker interrupted during a scan leaves its job durable. On startup, jobs whose worker lease has been stale for ten minutes return to the queue.

Removing the named volume is intentionally not part of the normal runbook because that permanently deletes encrypted sessions, snapshots, job history, and access events.

## Throttling and partial data

The Graph client honors `Retry-After` and `x-ms-retry-after-ms`, uses jittered exponential fallback, retries bounded transient failures, refreshes tokens between pages when necessary, and exposes retry state through the durable job progress. If an endpoint exhausts retries, its evidence is retained as skipped and the snapshot is marked partial rather than presented as complete.
