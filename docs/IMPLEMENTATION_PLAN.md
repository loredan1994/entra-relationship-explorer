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
- Encrypted tenant-scoped decision records for status, owner, expiry, assumptions, and editable review-flow copies; fixture mode remains clearly labeled browser-local sample state.
- Finding lifecycle across retained scans: new, ongoing, returned, no longer detected, and unconfirmed when current evidence is incomplete.
- Explicit review revalidation, acceptance-expiry warnings, and reopening of resolved findings that remain or return.
- Sanitized CSV findings, relationship CSV, standalone client report, and MITRE Attack Flow exports.
- Strict configured / observed / inferred / missing evidence separation, including an optional 30-day observed sign-in overlay.

## High-leverage Graph collector expansion — complete

- Devices and administrative units, including member relationships and name-resolved role scopes while retaining the raw Graph scope path.
- Application and managed-identity federated credentials with stable evidence nodes and focused findings only when a powerful path is reachable.
- Authorization policy and permission-grant policies, including include/exclude conditions when `Policy.Read.PermissionGrant` is explicitly enabled.
- Policy subtype-aware UI labels, exact endpoint evidence, partial-collection warnings, comparison fingerprints, and export coverage.

## Next product modules

- Scheduled scans using managed identity or certificate authentication, with an explicit deployment and secret-handling design.
- Notifications and hosted multi-tenancy only after the local recurring-review workflow is proven.
- A contributor-friendly finding catalog and fixture template without runtime third-party plugin loading.
- Focused Markdown and versioned JSON evidence packets for one finding or attack path.
- Deeper condition evaluation for custom permission-grant policies before generalized risk findings are emitted.

## Decisions requiring explicit approval later

- Tenant hosting model: local-only, single-tenant Azure deployment, or multi-tenant service.
- Which deployments should enable optional role, policy, cross-tenant, or sign-in evidence scopes.
- Retention duration and whether user-identifying fields may be stored.
- Any future write/remediation capability; this must be a separate security design.
