# Security and privacy

## Boundary

Version 1 is read-only. Its application registration must not contain Microsoft Graph write permissions. The UI must not offer actions that imply a change can be made.

## Least-privilege permission stages

| Stage | Microsoft Graph application permission | Why |
|---|---|---|
| Core inventory | `Application.Read.All` | Read registrations, service principals, and app-role assignments |
| Delegated consent inventory | `Directory.Read.All` | Read OAuth2 delegated permission grants and directory relationships |
| Optional activity overlay | `AuditLog.Read.All` | Read sign-in activity; deploy separately if not required |

Exact requirements must be revalidated against current Microsoft documentation during implementation. Separate optional permissions so customers do not have to consent to features they will not use.

## Authentication choices

- Local/admin MVP: delegated administrator login; cache tokens only in the protected server session.
- Shared/scheduled deployment: managed identity where supported, otherwise certificate credentials in Azure Key Vault.
- Never use long-lived client secrets for production.

## Data handling

- Store object IDs, names, metadata, relationships, permission values, and scan timestamps.
- Never store access tokens, refresh tokens, private keys, secret values, or certificate private material in the graph store.
- Encrypt storage and transport; isolate tenants with a mandatory tenant key in every query.
- Default snapshot retention: 30 days, configurable. Exports are explicitly initiated and clearly labeled sensitive.
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
- Rate limits and bounded traversal for graph queries.
- Audit access to stored tenant snapshots and exports.
- Dependency scanning, secret scanning, and no tenant exports in Git or build artifacts.

