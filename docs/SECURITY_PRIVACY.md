# Security and privacy

## Boundary

Version 1 is read-only. Its application registration must not contain Microsoft Graph write permissions. The UI must not offer actions that imply a change can be made.

## Least-privilege permission stages

| Stage | Microsoft Graph delegated permission | Why |
|---|---|---|
| Core inventory | `Application.Read.All` | Read registrations, service principals, and app-role assignments |
| Delegated consent inventory | `Directory.Read.All` | Read OAuth2 delegated permission grants and directory relationships |
| Optional roles and PIM | `RoleManagement.Read.Directory` | Read role definitions, active assignments, and eligible schedules |
| Optional access policy | `Policy.Read.All` | Read Conditional Access and partner-specific cross-tenant settings |
| Optional activity overlay | `AuditLog.Read.All` | Read a time-filtered 30-day sign-in activity window |

The default implementation uses the two core delegated permissions above. Optional scopes must be explicitly configured and are rejected unless present in the fixed read-only allowlist. Exact requirements must still be revalidated before real-tenant consent.

## Authentication choices

- Local/admin MVP: delegated administrator login; encrypt the serialized MSAL cache and current access token with AES-256-GCM in the tenant-scoped PostgreSQL session row. Tokens never reach browser JavaScript or snapshot records.
- Shared/scheduled deployment: managed identity where supported, otherwise certificate credentials in Azure Key Vault.
- Never use long-lived client secrets for production.

## Data handling

- Store object IDs, names, metadata, relationships, permission values, scan timestamps, encrypted stage checkpoints, and encrypted tenant-scoped review decisions.
- Never store access tokens, refresh tokens, private keys, secret values, or certificate private material in the graph store.
- Encrypt storage and transport; isolate tenants with a mandatory tenant key in every query.
- Snapshot retention is currently fixed at 30 days. Exports are explicitly initiated and clearly labeled sensitive.
- Redact user email/UPN in shared screenshots and diagnostics by default.

## Trust rules

- A configured permission means “can access,” not “did access.”
- Activity is time-bounded and can be incomplete because of licensing, retention, or throttling.
- Every scan displays completion, errors, skipped endpoints, and collection time.
- Risk labels explain the exact rule and are advisory, not proof of compromise.

## Threat controls

- CSRF protection, PKCE, strict redirect allow-list, secure cookies, and short sessions.
- Server-side Microsoft Graph calls; tokens never reach browser JavaScript.
- Input validation on filters and exports; parameterized database access.
- Rate limits and bounded traversal for graph queries. Completed collection stages are saved as encrypted checkpoints and resumed after a stale worker is recovered; cancellation deletes unpublished checkpoint data.
- Keep tenant-scoped access controls around stored snapshots and explicit exports. Durable metadata-only access events currently record enqueue, snapshot creation, and export. Complete denied-authorization and snapshot-read coverage is still required before claiming a full authorization audit.
- Local PostgreSQL and web ports bind only to loopback; worker and migration remain private to the Compose network. Containers run without added privileges and with `no-new-privileges`; the application image uses a pinned non-root distroless runtime and production-only dependency manifests.
- Dependency scanning, secret scanning, and no tenant exports in Git or build artifacts.

## Privacy findings and residual risk

Tenant snapshots and permissions may identify people and reveal organizational relationships. Repeated snapshots and access records are linkable. Exports cross into an operator-controlled environment, and directory subjects may not be aware of the local administrative scan. The product minimizes fields, excludes raw Graph bodies and secrets, uses tenant-bound encryption, keeps activity collection optional, prunes snapshots after 30 days, and requires explicit export. Owner-approved retention, deletion/rights, backup, incident-response, and export-handling policies are still required before broader organizational use.

Customer-facing threat decisions are intentionally separate from developer assurance. A finding may be accepted only with an owner, rationale, and expiry. In tenant mode, decisions and analyst-edited attack-flow copies use authenticated tenant-scoped encryption in PostgreSQL; fixture mode uses clearly labeled browser storage. Neither path modifies Microsoft Entra.
