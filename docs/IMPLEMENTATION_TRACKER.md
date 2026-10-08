# Review implementation

Source: `REPOSITORY_REVIEW_2026-10-08.md`. Scope approved by the owner on 8 October 2026: review fixes and all six proposed additions, with outcome-based verification. Entra remains GET-only, single-tenant and local. No public deployment or tenant consent change is part of this work.

## Work sequence

- [x] Correct control-path traversal, analysis completeness and coverage-aware comparisons (R1, R2, R10).
- [x] Preserve permission audience, credential metadata and truthful collector coverage (R5–R8).
- [x] Fix periodic recovery, idle retention and snapshot-bound review persistence (R3, R4, R9).
- [x] Ship readiness/coverage and permission reconciliation views.
- [x] Ship retained-snapshot timeline with opt-in directory audit correlation.
- [x] Ship local what-if planner and credential/federation workbench.
- [x] Ship synthetic rule laboratory and contributor workflow.
- [x] Run regression, contract, browser, build and isolated database checks; document evidence and remaining external validation limits.

## Verification principles

Tests must state observable behavior, include nearby cases that must not alert, and distinguish unknown evidence from a negative result. Preserve the reproduced failures as regression cases. Use synthetic identities in repository tests and fixtures; explicitly authorized live acceptance keeps tenant material outside Git. Do not weaken assertions merely to retain old incorrect behavior. Test worker/database and review concurrency boundaries independently of line coverage.

New snapshot fields are optional for compatibility with retained encrypted snapshots; missing legacy fields mean unknown, not empty or complete. New activity collection is explicitly opted into and stays behind existing authorized read scopes. Scenario changes affect only an in-memory copy. Rule replay accepts validated synthetic data and never executes imported code.

## Verification completed

- Full `pnpm verify` with an isolated PostgreSQL 17 database: **1,408 unit/contract/database tests passed** in the final coverage run, **48 browser checks passed** (46 desktop/mobile product checks plus two real PostgreSQL persistence flows). Full `pnpm verify` also passed; the final coverage run includes two additional rule guards.
- The synthetic suite skips one optional real-Entra test; a separate owner-authorized live acceptance run passed. Two desktop-only skips cover behavior tested on the mobile project. Live tenant material remains outside Git.
- Lint, TypeScript, production build, Compose isolation and `git diff --check` passed.
- Rule-lab scaffold and replay were executed successfully without a tenant connection.
- Current scoped coverage and mutation measurements are recorded in `RELEASE_VERIFICATION_2026-10-08.md`. All packages meet the unchanged 95% mutation gate. No measured function exceeds CRAP 30. Coverage does not include every UI/worker line.
- The disposable test database was used only for synthetic data. CI now provisions the same isolated database category and runs the integration and persistence flows automatically.

The second review pass adds local scenario import, individual credential/trust history, and interactive synthetic replay; see `REVIEW_FOLLOWUP_2026-10-08.md` for reproduced issues and fixes.

The six initial additions are documented in `INVESTIGATIONS.md`; the lab's initial import surface is deliberately limited to a compiled synthetic fixture plus validated exclusions. Broader custom graphs remain repository-reviewed TypeScript tests. Workload sign-in completeness, full group membership, and effective Conditional Access evaluation remain explicit evidence limitations, not claimed capabilities.

The subsequent application access enrichment and Docker recovery are recorded in [Application access review](APPLICATION_ACCESS_REVIEW_2026-10-08.md). The subsequent quality corrections and independent read-only Azure CLI comparison are recorded in [Release verification](RELEASE_VERIFICATION_2026-10-08.md).
