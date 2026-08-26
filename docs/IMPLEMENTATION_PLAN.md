# Implementation plan

## Phase 0 — foundation

Status: complete.

- Create TypeScript monorepo and CI checks.
- Encode the design tokens and accessible application shell.
- Add synthetic fixtures modeling API, orchestrator, users, groups, and permissions.
- Build the relationship canvas and evidence inspector against fixtures.

Exit: the complete UX works without connecting to a real tenant.

## Phase 1 — read-only tenant scan

Status: complete for the approved local single-tenant boundary. Admin consent is limited to the two core delegated read permissions.

- Implement Microsoft sign-in and tenant boundary.
- Add paginated readers for applications, service principals, app-role assignments, delegated grants, owners, and credentials metadata.
- Normalize records into nodes, edges, and evidence.
- Add scan status, retry/backoff, completeness report, and table export.

Exit: a consenting administrator can scan and explain configured relationships; no write permission exists.

## Phase 2 — investigation quality

Status: implemented for local use. The project scanner passed a representative GET-only live-tenant read. PostgreSQL persistence, a durable queue, and a separate scan worker now protect active work from web-process restarts.

- Application detail, saved filters, one-hop expansion, unresolved-edge warnings.
- Snapshot comparison and change feed.
- Accessibility audit, large-tenant performance test, and privacy review.

Exit: production pilot with representative tenant scale.

## Local backend hardening — complete

- PostgreSQL schema and idempotent migration job.
- AES-256-GCM encrypted auth flows, MSAL session cache, access tokens, and tenant snapshots.
- Durable tenant-scoped queue with one active scan per tenant, safe worker claims, progress, stale-job recovery, and atomic completion.
- Versioned `/api/v1` health, session, scan, and export endpoints.
- Docker Compose stack with loopback exposure, health checks, persistent volume, and Key Vault-sourced secrets.

## IAM intelligence and threat workspace — implemented for the current relationship scope

- Bounded transitive path discovery over evidence-bearing configured relationships.
- Prioritized findings for powerful privilege paths, delegated OAuth consent, missing ownership, and missing scan evidence.
- Multi-stage flows with prerequisites, per-step provenance, MITRE ATT&CK® mappings, confidence, mitigation, and uncertainty.
- Browser-local decision records for status, owner, expiry, and assumptions, plus sanitized CSV finding exports.
- Strict configured / observed / inferred / missing evidence separation, including an optional 30-day observed sign-in overlay.

## Next product modules

- Sign-in activity overlay behind separate `AuditLog.Read.All` consent.
- Live collection for directory roles, group membership, PIM eligibility, Conditional Access, managed identities, and cross-tenant policy where least-privilege permissions permit it.
- PostgreSQL-synchronized finding decisions and collaborative report generation.
- Scheduled scans using managed identity or certificate authentication.

## Decisions requiring explicit approval later

- Tenant hosting model: local-only, single-tenant Azure deployment, or multi-tenant service.
- Which deployments should enable optional role, policy, cross-tenant, or sign-in evidence scopes.
- Retention duration and whether user-identifying fields may be stored.
- Any future write/remediation capability; this must be a separate security design.
