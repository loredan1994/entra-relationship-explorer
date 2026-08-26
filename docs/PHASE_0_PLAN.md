# Phase 0 implementation plan

## Outcome

Phase 0 delivers the complete investigative experience against synthetic data. It does not authenticate to Microsoft, call Microsoft Graph, store tenant exports, request permissions, or deploy infrastructure.

## Technical shape

- `apps/web`: Next.js application shell and the product routes described in the product specification.
- `packages/domain`: framework-independent normalized node, relationship, evidence, and snapshot contracts plus synthetic fixtures and query helpers.
- A lightweight SVG/HTML relationship map for the first interaction pass. The normalized domain contract stays independent so Cytoscape.js or React Flow can be evaluated later with large synthetic datasets.
- Static fixture loading only. There is no network client, authentication package, database, token cache, or write action in Phase 0.

## Work sequence

### P0.1 — contracts and fixtures

1. Define tenant-scoped nodes for app registrations, enterprise applications, people, and groups.
2. Define normalized relationships with exact source and target object IDs, relationship type, source endpoint, scan timestamp, and configured-versus-observed evidence.
3. Model the Clean Project caller/resource example, ownership, group assignment, and delegated access with synthetic identifiers.
4. Add contract tests for tenant isolation, evidence completeness, and configured-access language.

### P0.2 — design foundation

1. Encode the `DESIGN.md` colors, type scale, spacing, radii, and motion as CSS variables.
2. Build the 72 px product bar, 280 px filter rail, responsive relationship canvas, and evidence inspector.
3. Provide visible focus states, reduced-motion handling, text labels for color-coded states, and a skip link.

### P0.3 — fixture-driven product routes

1. Overview: inventory and transparent review findings.
2. Relationship map: search, object-type filters, relationship selection, evidence inspector, and an equivalent table.
3. Application detail: blueprint and tenant identity shown side by side.
4. Permissions: sortable configured-access inventory.
5. Changes: an explicit empty state until multiple fixture snapshots exist.
6. Settings: fixture-mode status and a clear statement that no Graph permission is requested.

### P0.4 — verification gates

1. Type-check the workspace and run domain contract tests.
2. Build the production web bundle and verify every documented route is generated.
3. Keyboard-test filters, nodes, connections, tabs, and inspector focus order.
4. Validate responsive behavior and contrast before Phase 0 is called complete.

## Phase 0 exit criteria

- The Clean Project story is understandable and traceable to evidence without a tenant connection.
- Every visible connection exposes object IDs, relationship type, source endpoint, and scan time.
- Configured access is never presented as observed activity.
- Graph and table representations expose the same filtered relationships.
- All documented routes have an intentional fixture-mode experience.
- Type checks, contract tests, production build, keyboard review, and responsive review pass.

## Explicitly deferred

- Microsoft sign-in, consent, Graph readers, and permission verification belong to Phase 1 and require a separate implementation review.
- Persistence and hosting depend on the approved tenant hosting model.
- Sign-in activity remains a separate optional module with separate consent.
- No write or remediation capability is designed or implied.
