# Implementation plan

## Phase 0 — foundation

- Create TypeScript monorepo and CI checks.
- Encode the design tokens and accessible application shell.
- Add synthetic fixtures modeling API, orchestrator, users, groups, and permissions.
- Build the relationship canvas and evidence inspector against fixtures.

Exit: the complete UX works without connecting to a real tenant.

## Phase 1 — read-only tenant scan

- Implement Microsoft sign-in and tenant boundary.
- Add paginated readers for applications, service principals, app-role assignments, delegated grants, owners, and credentials metadata.
- Normalize records into nodes, edges, and evidence.
- Add scan status, retry/backoff, completeness report, and table export.

Exit: a consenting administrator can scan and explain configured relationships; no write permission exists.

## Phase 2 — investigation quality

- Application detail, saved filters, one-hop expansion, unresolved-edge warnings.
- Snapshot comparison and change feed.
- Accessibility audit, large-tenant performance test, privacy review, threat model.

Exit: production pilot with representative tenant scale.

## Phase 3 — optional modules

- Sign-in activity overlay behind separate `AuditLog.Read.All` consent.
- Rule-based review findings with transparent explanations.
- Scheduled scans using managed identity or certificate authentication.

## Initial backlog

1. Scaffold Next.js/TypeScript workspace and tests.
2. Convert `DESIGN.md` tokens into CSS variables.
3. Define `ApplicationNode`, `ServicePrincipalNode`, and `RelationshipEdge` schemas.
4. Load synthetic fixtures for the Clean Project example.
5. Build map, search, filter, inspector, and table fallback.
6. Add Microsoft login and Graph permission display.
7. Implement scanner endpoint by endpoint with fixture-driven contract tests.

## Decisions requiring explicit approval later

- Tenant hosting model: local-only, single-tenant Azure deployment, or multi-tenant service.
- Whether optional sign-in logs are worth the extra permission.
- Retention duration and whether user-identifying fields may be stored.
- Any future write/remediation capability; this must be a separate security design.

