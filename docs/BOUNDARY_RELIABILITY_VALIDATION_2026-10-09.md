# Boundary reliability review — 2026-10-09

This pass follows the [deep workflow review](DEEP_WORKFLOW_VALIDATION_2026-10-09.md). It concentrates on invalid inputs, concurrent user intent, session termination, database races and evidence provenance. Regressions reproduce incorrect outcomes before the source corrections; passing page loads alone are not the acceptance criterion.

## Reproduced failures

| Boundary | Reproduced failure | Corrected behavior and regression |
|---|---|---|
| Authentication cookies | Non-UUID cookies caused PostgreSQL cast failures, including on sign-out; uppercase UUIDs found rows but failed authenticated decryption | Validate and canonicalize external identifiers before storage; signed-out pages and cookie clearing remain usable. Unit routes and isolated PostgreSQL browser checks cover both forms |
| Sign-in configuration | Uppercase tenant IDs passed validation but failed exact identity-provider comparisons | Normalize validated tenant/client IDs; preserve exact tenant isolation |
| Concurrent sign-in | Clearing every rejected callback's cookie destroyed a newer pending login when an older tab returned | Preserve syntactically valid pending flow cookies on state mismatch; a two-login regression completes the newer flow after rejecting the older callback |
| Scan endpoints | Authenticated malformed job IDs caused HTTP 500 | Both API aliases return uncached 404; authentication and origin checks still precede job lookup |
| Database startup | A rejected initialization promise remained cached until process restart | Close the failed pool once, let later requests retry, and keep concurrent initialization scoped to its own connection |
| Startup during active work | Schema initialization and snapshot publication acquired table locks in opposite orders and deadlocked | Acquire an exclusive migration gate before schema changes and a shared gate before runtime transactions; controlled PostgreSQL interleavings cover publication, checkpoints and session deletion |
| Concurrent database tests | One suite's startup cleanup deleted another suite's deliberately expired session, invalidating exact rollback and lock-state assertions | Give each suite its own schema, retain real within-suite concurrency and reproduce both failures with controlled unrelated migrations; reject driver host overrides and non-Postgres URLs before constructing test pools |
| Scan enqueue | Failed audit writes left a runnable job despite an API error; concurrent reuse produced duplicate creation events | Commit new enqueue and its audit event together; injected audit failures roll back the job, and concurrent valid callers reuse one audited creation |
| Page source labels | A new scan or session transition between page and shell reads produced conflicting content and source labels | Pass one authorized context through every page; historical comparisons label their selected later scan; no cross-request tenant cache |
| What-if imports | A delayed file could undo Reset, replace a newer file or overwrite manual/candidate choices | Newer intent invalidates pending work; obsolete success/error feedback cannot describe a changed plan |
| Application bookmarks | Missing or search-hidden identities silently selected an unrelated application | Explain the missing/filtered selection and offer recovery while preserving the requested identity |
| Session refresh | A refresh completing after expiry or deletion could return/persist a token | Enforce the stored session lifetime at update and before returning credentials; refresh does not extend application-session lifetime |
| Worker lifecycle | Cached sessions allowed further Graph reads after sign-out/expiry; a replaced worker could fail while trying to terminate its old job | Check session existence, expiry and ownership during collection and retry; stop unpublished work and yield safely after ownership changes |
| Snapshot publication | Session termination between the final worker check and publication could still save a snapshot | Recheck the session within publication after lock acquisition, using current database time |
| Retention | A concurrent review could survive deletion of its snapshot as orphaned ciphertext; inconsistent lock order could deadlock cleanup and publication | Serialize review/publication/cleanup with the tenant lock and consistent lock order; real PostgreSQL tests coordinate both transaction interleavings |
| Contract witnesses | A shortest incomplete path could be presented as a violation while another path actually proved it; derivation references could point to the wrong path | Select a complete shortest witness and renumber/filter derivation references consistently |
| Contract work | Repeated per-caller graph scans grew quadratically while traversal counters understated the work | Share direct-grant indexes, reuse evaluation during comparisons and account for preprocessing separately; bounded work cannot establish a pass after exhaustion |
| Evidence gaps | A conflicting proof with no ordinary missing facts looked like a successful empty collection plan | Include conflicting fact IDs as unresolved prerequisites; proposed collector reads include role definitions and managed-identity federation |

## Reproduce

Use an isolated loopback PostgreSQL database named `entra_review_test`, never the live tenant database:

```sh
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
```

New browser suites are `scenario-import-lifecycle`, `application-selection-recovery` and PostgreSQL-backed `auth-boundaries`. Server render tests cover all ten pages and historical comparisons. Worker tests exercise the real scanner and backend with a synthetic GET-only transport. PostgreSQL race tests use explicit locks and transaction coordination rather than probabilistic sleeps.

Hosted mutation checks run independently for domain, backend, engine, Graph and web, each with isolated PostgreSQL. The final quality gate requires coverage and every package to succeed. The fresh-run requirement, 95% thresholds and tested scopes are unchanged; local commands remain sequential to avoid shared-resource contention. After two hosted jobs hit Docker Hub anonymous pull limits before tests started, CI switched to Docker Official Images on ECR Public; the PostgreSQL image digest is unchanged and was verified as available on ECR Public.

The repository now also requires `quality` in GitHub's `main` branch protection, alongside the existing `verify`, `Analyze TypeScript` and `review` checks. Previously, a failed quality run did not itself prevent a normal protected merge. Existing strictness and other protection settings are preserved; fork maintainers must configure required checks separately from the workflow file.

## Compatibility and limits

- Interpretation is engine `1.0.4` / authorization rules `entra-configured/4`. Older portable packages require re-export; stored snapshots remain readable.
- No schema migration or Microsoft Graph permission increase is required. On the first upgrade to coordinated runtime transactions, stop the old web and worker before starting the new image; preserve PostgreSQL and its volume. Older processes do not participate in the new lock protocol.
- Tenant checks remain read-only. Synthetic tests cover sign-out, review writes, failures and transaction races; live validation must not revoke sessions, start scans or modify tenant data.
- Session termination prevents subsequent guarded reads and unauthorized publication. An already in-flight Graph GET cannot be withdrawn.
- Work bounds report incomplete evaluation; they are not proof of absence. Synthetic tests and sampled live comparisons do not establish correctness for every tenant or deployment.

## Final verification

- **2,705 unit/integration tests passed:** domain 552, engine 886, Graph 486, backend 294 and web 487. The opt-in Graph live test remains separate from the synthetic suite. Mutation-survivor review added eight worker lifecycle cases and 29 engine cases covering contract evidence, bounded reads and independent continuity timelines. Six test-fixture safety checks verify that unsafe database targets cannot construct a pool.
- **195 browser checks passed:** 165 desktop/mobile behaviors and 30 isolated PostgreSQL scenarios. The full browser run plus a focused rerun verify the final selectors; three project-specific duplicate cases are intentionally skipped. The entire PostgreSQL browser suite passed again after the migration coordination fix.
- Production build, lint, TypeScript, 18 offline CLI checks and Compose security validation passed. Coverage/maintainability assessed 1,134 functions with none above CRAP 30. Measured line coverage is 99.88% for the engine and 100% for domain, Graph, backend and web-server code; other coverage dimensions and browser assertions are reported separately rather than inferred from those numbers.
- The first fresh hosted engine mutation run correctly stopped the release at **94.38%**, below the unchanged 95% minimum. The 29 added engine regressions target observable missed behavior; independent review found no weakened expectations or tests encoding a known product defect. Hosted CI repeats all five packages from scratch before merge. [PR #52](https://github.com/loredan1994/entra-relationship-explorer/pull/52) records the final fresh scores and check results.
- The current dependency audit reported no known vulnerabilities. The pre-publication scan found no known deployment credentials or private tenant identifiers in candidate files, including the added regression suites.
- Read-only Azure CLI validation made **19 Microsoft Graph GET requests** and matched **5,136 comparisons**, with zero mismatches. Optional policy/activity collectors were not enabled, directory-audit reads were denied and group-membership evidence remained partial; those gaps are not claims of absence.
- The deployed image passed **40 live UI interaction checks and all ten engine workflows**, including 49 displayed-source comparisons. There were zero browser errors, attempted writes, authentication/export requests or downloads. Accessibility checks found no violations across the ten engine workflows. Five live actions were deliberately skipped because they require writes/downloads or evidence absent from this snapshot; synthetic suites cover those behaviors.
- In-memory engine checks matched 20 relationship-provenance fields across five supported application queries, verified pseudonymized replay and correctly failed a forbidden-grant contract. Unavailable policy evidence remained unknown.
- The final non-root container matched all 123 checked runtime source files, loaded production worker/backend/engine modules and reported healthy PostgreSQL storage with the read-only Graph boundary. The upgrade stopped only the old Entra web/worker first and preserved the tenant database and sessions; unrelated Docker services were unchanged.
