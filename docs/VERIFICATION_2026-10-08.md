# Implementation verification — 8 October 2026

**Historical checkpoint.** The counts, machine limitations and open quality gaps below describe this earlier pass. The current contribution is verified in [Release verification](RELEASE_VERIFICATION_2026-10-08.md).

**Later follow-up:** Docker recovery, the current application access feature, refreshed full verification and database-inclusive quality results are documented in [Application access review](APPLICATION_ACCESS_REVIEW_2026-10-08.md). The machine limitation below describes the earlier failed run and is now resolved.

- **Functional verification passed on the final dependency set:** `TEST_DATABASE_URL=… pnpm verify` passed Compose isolation, ESLint, TypeScript, the production Next.js build, 1,064 unit/contract/database tests and 46 browser checks. The database was a disposable loopback PostgreSQL 17 instance containing synthetic data.
- **Test breakdown:** domain 323; Graph 329; backend 194 (including four real PostgreSQL tests); web-server contracts 218; desktop/mobile Chromium 44; real UI + PostgreSQL persistence two. Two desktop cases are intentionally skipped because their mobile equivalents cover the behavior. The optional live test is excluded from this synthetic run and was executed separately.
- **Meaningful outcomes:** tests exercise competing review writes, stale snapshot/revision rejection, retention before physical cleanup, worker lease ownership, delayed saves across finding selection, tenant isolation, partial-evidence uncertainty, alternative control paths, consent audience, credential rotation, audit correlation bounds, import rejection, and synthetic rule pass/fail behavior. Browser checks include accessibility and no-write assertions for local scenarios.
- **Live acceptance passed before the final test-tooling migration:** Microsoft sign-in, two worker scans, independently fetched Graph samples, encrypted persistence, five authenticated export formats, unauthenticated export rejection, review persistence/conflicts, cross-origin rejection, local scenario round-trip, and retained-snapshot comparison were exercised against an owner-authorized tenant. The standalone Graph acceptance test also passed. Tenant-specific results and probe output remain outside Git.
- **Live limitations remain explicit:** group membership is partial because Graph v1.0 can omit service principals. An opted-in directory-audit read returned `Authentication_MSGraphPermissionMissing`. Roles, policy, partner-trust and sign-in collectors were not enabled with the existing core consent, so their live behavior is not verified. No scopes, tenant roles, grants or credentials were changed. Successful empty device/administrative-unit reads do not test populated records in that tenant.
- **Live test corrected:** the previous unconditional `completion.status === "complete"` expectation contradicted the deliberate membership limitation. The test now checks every collector state, requires no read errors or skipped endpoints, allows only the known membership limitation when groups exist, and checks tenant boundaries, unobserved evidence and relationship provenance. It does not accept arbitrary partial scans.
- **Runtime security patches applied:** Next.js 16.3.8, sharp 0.35.5 and source-map-js 1.2.2 replace affected locked versions. The initial production audit reported ten advisories, including one critical. The critical advisory concerns a specific `next/og` image-generation path; no use of that API was found in product source. An installed-version advisory is not proof that this application was exploitable. See the [Next.js maintainer advisory](https://github.com/vercel/next.js/security/advisories/GHSA-vcvr-r3jv-pc5j).
- **Development tooling patched:** Vitest and its V8 coverage provider are now 4.1.11; qs is 6.16.0; compatible fast-uri and brace-expansion dependencies were refreshed. Node type dependencies are explicit in domain/Graph packages. Coverage scripts use explicit production-source globs. No behavioral assertion or mutation threshold was removed to make the migration pass.
- **Dependency audit passed:** the final `pnpm audit --json` reported zero advisories across runtime and development dependencies. `pnpm security:dependencies` exposes the check and CI runs it. This is a registry dependency audit, not a container OS vulnerability scan or CodeQL run.
- **Documentation fixed:** OpenAPI export URLs now resolve to the implemented `/api/export/*` routes, while versioned API paths remain `/api/v1/*`. Direct dependency inventories and notices reflect installed versions.
- **Secret hygiene:** an in-memory exact-value check found none of the three vault secrets used for validation in 235 tracked or non-ignored candidate files. The five tested live export bodies also excluded the client secret, encryption key and session token. This is a targeted check, not a comprehensive Git-history secret scan. Live exports were not saved in the repository.

## Current scoped coverage

Measured with Vitest 4.1.11 after mutation sandboxes finished. Coverage targets are domain/Graph/backend `src` and web `server`; React components and the worker are not included in these percentages. The final backend coverage run omitted the four Docker-dependent tests after the machine's storage failure; those tests had already passed in the final full verification run. Vitest 3 percentages from earlier reports are superseded and are not directly comparable to the new instrumentation.

| Target | Statements | Branches | Functions |
|---|---:|---:|---:|
| Domain | 96.78% | 94.28% | 94.82% |
| Graph | 99.46% | 96.71% | 99.19% |
| Backend, unit coverage | 96.50% | 95.04% | 96.07% |
| Web server | 100% | 100% | 100% |

## Mutation and maintainability gaps

Every mutant was rerun with `--force` under the patched test runner; prior cached results were not reused. The required score remains 95%.

| Target | Score | Result |
|---|---:|---|
| Domain | 82.12% | Failed |
| Graph | 86.18% | Failed |
| Backend, unit run | 86.80% | Failed |
| Web server | 98.71% | Passed |

An earlier backend run including PostgreSQL integration tests reached 88.90%, also below the gate. Docker's subsequent storage failure prevented repeating that database-inclusive mutation run with the final tooling. Surviving mutants require stronger behavioral assertions, especially in collector coverage, permission reconciliation, credentials, scenarios, timeline and review retention. Scores were not increased by excluding mutants or lowering thresholds.

The refreshed CRAP report identifies three functions over 30: `permissionLedger` (63.0), `recordStageCoverage` (53.0), and `parseRuleLabCase` (30.4). These are maintainability/testing gaps; passing functional tests does not clear them. Ignored local reports are in `quality-reports/` and each package's `reports/mutation/`.

## Machine limitation and remaining validation

- The original production image and the runtime-security-patched image built and started successfully. After the final development-tooling migration, application compilation passed, but Docker failed while exporting the image with an I/O error.
- At that point the host disk was full and PostgreSQL returned a read-only-filesystem error. Task-generated Next.js cache was removed; disk space later became available, but Docker remained unresponsive. A targeted cleanup of one identified task build-cache entry timed out. Unrelated containers, images and volumes were not removed, and Docker was not forcibly restarted because other projects were running.
- Final image export/restart, post-restart live acceptance, and database-inclusive coverage/mutation reruns require Docker recovery. The existing live validation database and temporary synthetic test container remain pending that recovery.
- No public deployment, release or Git commit was made. The functional checks pass, but the mutation quality gates do not; this report is not an all-green release sign-off.
