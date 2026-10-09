# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until `1.0.0` the public surface — the HTTP API in [docs/openapi.yaml](docs/openapi.yaml),
the export formats, and the database schema — may change in a minor release.
Breaking changes are always called out under **Changed** with a migration note.

## [Unreleased]

### Added

- Original tenant-bound evidence engine with reproducible proofs, typed access evaluation, temporal path reconstruction, weighted change planning, policy counterexamples, federation overlap analysis, credential continuity simulation, evidence-gap planning, access contracts, and portable offline replay.
- Evidence engine UI with ten workflows, visible support limits, sensitive export acknowledgment, and a standalone offline CLI.
- Independent exhaustive planning oracles, semantic decision tables, package-tamper tests, desktop/mobile engine workflows, and reproducible generated benchmarks.

- Real MSAL integration contracts for PKCE, authorization-code exchange, cache restoration, refresh-token rotation and revoked refresh credentials using a synthetic network transport.
- Question-based overview shortcuts and an in-app Guide covering investigation workflows, evidence meaning, local data handling and contributor tools; reorganized README and a dedicated operator user guide.

- Investigation workspace with collector coverage, permission reconciliation, credential and federation review, local access scenarios, and a synthetic rule laboratory.
- Application access review showing sign-in controls, publisher context, assignments, consent audiences, accountable owners, and separately labelled observed activity.
- Local scenario export/import bound to the tenant and snapshot, with recomputed results and bounded candidate ranking.
- Individual credential and federation history, field-level snapshot differences, and opt-in directory audit correlation that does not claim causation.
- Behavioral and mutation contracts for sparse data, failed reads, exact time and size limits, tenancy, stale worker leases, physical retention, and concurrent review decisions.
- Isolated PostgreSQL integration and browser persistence checks, plus continuous mutation and maintainability verification.
- GET-only collectors for directory devices, administrative units and scoped roles, application and managed-identity federated credentials, tenant authorization policy, and optional consent-policy conditions.
- Explainable administrative-unit, workload-federation, and consent-policy relationships, with focused inferred federation paths and a configured broad-consent finding.
- Finding lifecycle across retained scans: newly detected, ongoing, returned, no-longer-detected, and unconfirmed when collection coverage cannot establish absence.
- Explicit snapshot-scoped review revalidation with prior-decision context, expired-acceptance warnings, and reopening for findings previously marked resolved.
- Apache-2.0 license, contribution guide, security policy, and code of conduct.
- CodeQL analysis, dependency review, and Dependabot in CI.
- An explicit save state in the threat workspace decision record, so a rejected
  or failed review write can no longer look like a saved decision.

### Changed

- Review input limits are enforced explicitly: invalid or oversized fields return HTTP 400 without saving, instead of silently truncating a successful write. Existing documented limits and stored reviews remain compatible.
- CSV export is available for the synthetic demo. Live exports still require an authenticated tenant and retained snapshot; unavailable exports offer connection/scan guidance.
- Version the corrected interpretation as engine `1.0.2` / authorization rules `entra-configured/3`. Re-export older portable investigations from their source snapshots; incompatible replay versions are explicitly rejected. Stored snapshots remain readable.
- Cache container dependency installation separately from product sources; exclude package stores and nested environment files from the build context.
- Load engine history only for workflows that use it, and skip graph layout in table view.
- Refresh the pinned Node 24 Alpine build image to the reviewed digest from dependency PR #46.
- Resolve delegated consent scopes to exact resource-specific permission IDs; missing and ambiguous mappings remain unknown.
- Preserve structured federation audiences and supported Conditional Access inputs. Read session-control metadata through the existing optional policy permission; unsupported conditions remain unknown. Historical snapshots remain compatible and require a fresh read-only scan for missing structured fields.

- Upgrade MSAL Node to 6.0.0; align Vitest and its coverage provider at 5.0.3; update Playwright, lint tooling and Node 24 declarations. Update Cytoscape, tsx and PostgreSQL client patches, with matching dependency notices.
- Update dependency review and pnpm setup actions; pin CodeQL initialization and analysis to the same 4.38.2 revision. Group future Vitest updates and keep Node runtime/type major updates coordinated.
- **Review API migration:** review GET/PUT/POST requests require the displayed `snapshot` query parameter. PUT/POST require `expectedRevision` (`null` for a new decision, the loaded revision for an existing one). Stale snapshots and competing writes return HTTP 409. Update external API clients with the application.
- The database adds a review `revision` column automatically during the existing startup migration. Existing encrypted records remain readable; legacy revisions use the empty-string value until the next save. Restart the web and worker services together after upgrading.
- New snapshot metadata remains optional. Older scans display unknown coverage and unconfirmed differences until a fresh read-only scan supplies evidence.
- Test discovery excludes mutation sandboxes, keeping normal runs and reported counts independent of failed mutation runs.
- Permission reconciliation and collector coverage are split into smaller functions with explicit responsibilities.
- Tenant and client identifiers are now supplied through the environment rather
  than committed as defaults in `compose.yaml`.
- `pnpm dev:live` reads secrets from a Key Vault named by `ENTRA_KEY_VAULT_NAME`,
  or from a git-ignored `.env.local`, instead of a hard-coded vault.

### Fixed

- Make Inspect reveal and focus the selected evidence, including incoming evidence links, with a return action to the matching relationship. Keep the inspector inside desktop/tablet bounds and preserve readable table columns with a reachable Inspect action on narrow screens.
- Recenter the map on Fit/Home, restore canvas controls after an empty search, reset stale URL filters, and show all filtered relationships when leaving a bounded map for the table.
- Keep mobile Filters disabled until its interaction handler has loaded, preventing a lost first click during slow navigation.
- Report browser-storage failures when saving filters. Link overview review items to their actual findings, and pair application objects only through an unambiguous nonempty application ID within the tenant.
- Recover expired scan sessions with a sign-in action; display authentication failures and accurately describe permission sorting and export availability.
- Bind comparison selectors and lifecycle results to the selected historical snapshots; explain an earliest-snapshot selection without falsely claiming that only one scan exists.
- Reveal selected application/finding detail, explain empty credential filters, and disable all review-flow edits while loading or saving. Keep generated editable summaries within limits while preserving full source explanations.
- Keep independent contract and package-import tools available without a valid access query. Preserve cleared rotation editors, explain missing federation evidence, and prevent obsolete imports or exports from replacing newer user actions.

- Stop paginated Graph reads and retry backoff promptly after cancellation or worker lease loss.
- Lock checkpoint writes to the current job owner so stale workers cannot overwrite newer progress or recreate cancelled checkpoints.
- Load saved review decisions for the entire finding queue, including acceptance-due counts before a finding is selected.
- Reject malformed imported evidence and mismatched relationship identity bindings; keep blank provenance and conflicting contract targets uncertain.

- Serialize concurrent startup migrations to prevent PostgreSQL DDL deadlocks. Index identity lookups while normalizing observed sign-ins, preserving first-match behavior.
- Preserve uncertainty for missing or conflicting intermediate identities, conflicting policy variants, and partially known validity windows. Apply explicit work limits to change planning.
- Build large relationship indexes without repeatedly copying adjacency arrays; aggregate large Graph collections without exceeding JavaScript's argument limit.
- Bind engine state to the displayed snapshot, distinguish observed evidence in the map and table, and recover cleanly from scan-control network failures.
- Serialize snapshot publication with local review saves, so a completed newer scan cannot race a decision into older evidence. Reject review bodies over 128 KiB before parsing or storage.
- Pseudonymize exact identifiers inside quoted and encoded source endpoint filters as well as URL path segments.
- Bound offline CLI reads through a single open file handle and validate evidence-gap scopes and token-like export content without repeated backtracking; cover growing inputs, size boundaries and crafted scope/token inputs.

- Backport Stryker's Vitest 5 nested-test selection fix through a pinned pnpm patch. An end-to-end runner check rejects missing tests and incorrect prefix matches before the production mutation suite runs.
- Browser verification always starts the current build on a dedicated port instead of silently reusing an older local preview server.
- Keep future CodeQL action updates together to avoid incompatible `init`/`analyze` versions, and prevent repeated mutation-test summaries from exceeding GitHub's upload limit.

- Prevent group membership and API access from being mistaken for control of application credentials; disclose bounded or incomplete path analysis.
- Preserve missing inventory as uncertainty when comparing permissions, owners, credentials, consent and application controls; missing authorization-policy assignments no longer imply disabled user consent.
- Scope pending and unsaved review state to each finding; reject invalid expiry dates, stale snapshot decisions and competing revisions.
- Refresh worker leases during long scans, recover abandoned scans during idle polling, and physically prune expired evidence and authentication records.
- Reject cross-tenant memory checkpoints and reviews for missing or expired snapshots; align finding-limit deduplication with PostgreSQL.
- Report failed reads without authorization evidence as unavailable, and ignore malformed audit targets without discarding valid event context.
- Identify default application access only when the resource's collected role inventory is explicitly empty.

### Security

- Disable the unused image-optimization endpoint and remove optional `sharp`/`libvips` binaries from the lockfile and runtime, preserving the existing dependency license gate.
- All Microsoft Graph operations remain GET-only. New application fields use existing permissions; directory audits require an explicit opt-in under an existing read scope.
- Updated dependency overrides and the lockfile to resolve the advisories found during verification. Tenant data, secret values and certificate material remain excluded from Git and evidence exports.

## Prior work

Before this changelog began, the project reached a code-complete read-only
product: fixture-driven exploration, single-tenant Microsoft sign-in, GET-only
paginated Graph reads, PostgreSQL-backed encrypted sessions and snapshots, a
durable resumable scan queue, throttling-aware progress and cancellation,
snapshot comparison, attack-path discovery, editable review copies of attack
flows, and CSV, HTML report, and MITRE Attack Flow exports.

[Unreleased]: https://github.com/loredan1994/entra-relationship-explorer/commits/main
