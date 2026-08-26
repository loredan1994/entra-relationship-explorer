# Security and privacy

## Boundary

Version 1 is read-only. Its application registration must not contain Microsoft Graph write permissions. The UI must not offer actions that imply a change can be made.

## Least-privilege permission stages

| Stage | Microsoft Graph delegated permission | Why |
|---|---|---|
| Core inventory | `Application.Read.All` | Read registrations, service principals, and app-role assignments |
| Delegated consent inventory | `Directory.Read.All` | Read OAuth2 delegated permission grants and directory relationships |
| Optional activity overlay | `AuditLog.Read.All` | Read sign-in activity; deploy separately if not required |

The Phase 1 implementation uses the two core delegated permissions above and rejects any scope outside its fixed allowlist. Exact requirements must still be revalidated before real-tenant consent. Separate optional permissions so administrators do not have to consent to features they will not use.

## Authentication choices

- Local/admin MVP: delegated administrator login; encrypt the serialized MSAL cache and current access token with AES-256-GCM in the tenant-scoped PostgreSQL session row. Tokens never reach browser JavaScript or snapshot records.
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
- Keep tenant-scoped access controls around stored snapshots and explicit exports. Durable metadata-only access events currently record enqueue, snapshot creation, and export. Complete denied-authorization and snapshot-read coverage is still required before claiming a full authorization audit.
- Local PostgreSQL and web ports bind only to loopback; worker and migration remain private to the Compose network. Containers run without added privileges and with `no-new-privileges`; the application image uses a pinned non-root distroless runtime and production-only dependency manifests.
- Dependency scanning, secret scanning, and no tenant exports in Git or build artifacts.

## Layered security-model artifacts

- The OWASP Threat Dragon visual model is `security/threat-dragon/entra-relationship-explorer.json`.
- The canonical Threagile representation is `security/threagile/threagile.yaml`.
- The LINDDUN privacy pass is `security/privacy/linddun.yaml`.
- The selected ASVS 5.0.0 traceability subset is `security/asvs/controls.yaml`. It records evidence and gaps; it is not an ASVS compliance claim.
- Current dispositions are in `security/risk-register.yaml`. No risk is accepted without a named approver and expiry date.
- Automated evidence for the twelve product invariants is in `security/invariants/evidence.yaml`.

## Privacy findings and residual risk

Tenant snapshots and permissions may identify people and reveal organizational relationships. Repeated snapshots and access records are linkable. Exports cross into an operator-controlled environment, and directory subjects may not be aware of the local administrative scan. The product minimizes fields, excludes raw Graph bodies and secrets, uses tenant-bound encryption, keeps activity collection disabled, prunes snapshots after 30 days, and requires explicit export. Owner-approved retention, deletion/rights, backup, incident-response, and export-handling policies are still required before broader organizational use.

Generated Threagile, Gitleaks, Trivy, ZAP, and SBOM output is ignored by default because reports can contain source paths, snippets, and response metadata. Scanners receive no application credentials, tokens, raw Graph responses, tenant snapshots, or exports.

The current official distroless digest has one time-bounded, upstream-blocked OpenSSL HIGH disposition (`risk-006`, review due 2026-09-02). It is open, not accepted. Eleven MEDIUM and thirteen LOW current-runtime findings are grouped for the same digest review as `risk-008`; they are reported, not silently ignored. Trivy findings attributed to absent package paths or Debian 12 metadata in the detected Debian 13 runtime are recorded as evidenced false positives; all unmatched or expired HIGH/CRITICAL findings fail the gate. Trivy reports the Dockerfile `HEALTHCHECK` rule as LOW (`risk-009`, false positive) because health is intentionally defined in Compose, where the application environment and loopback endpoint exist.

Threagile's two HIGH injection paths into PostgreSQL are consolidated as `risk-007` and marked mitigated by parameterized SQL plus tenant/worker ownership tests. New database queries must preserve that control; the disposition does not establish blanket immunity to injection.
