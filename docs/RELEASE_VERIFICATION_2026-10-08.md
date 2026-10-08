# Release verification — 8 October 2026

This report supersedes the earlier verification checkpoints from the same day. It covers the investigation features, application access enrichment, review concurrency and retention fixes, and the subsequent mutation-driven corrections. Microsoft Graph remains GET-only with the existing scope allowlist.

## Read-only live validation

Azure CLI account metadata was compared with the running application's configured tenant in memory before making requests. Independent `az rest --method GET` calls were paginated and compared with the decrypted local snapshot; no tenant data, tokens or credential values were written to repository files. Browser checks block all methods except GET and HEAD.

The comparisons include registration and enterprise-application inventories, object/client identity, labels, sign-in audience, verified publisher metadata, account state, assignment requirement, home tenant, SSO mode, credential identifiers/validity dates, manifest requests, permission definitions, sampled owners and incoming app-role assignments, and collected delegated grants with their scopes and consent audience. Empty and missing values are compared separately.

The tenant cannot exercise every optional feature: group membership remains partial under the Graph v1.0 contract; the opted-in directory-audit read is denied; optional role, policy, cross-tenant and sign-in collectors remain disabled. No permission, role, grant, app registration or tenant credential was changed. Populated optional datasets are covered by synthetic regression tests, not claimed as live acceptance.

## Executed verification

- Full `pnpm verify` passed: Compose security, ESLint, TypeScript, production build, 1,406 unit/contract/database tests, 46 desktop/mobile browser checks and two real PostgreSQL browser persistence flows. Two desktop cases are intentionally covered by the mobile project; the opt-in Graph live test is not part of the synthetic run.
- The final coverage run passed **1,408 tests**: domain 552, Graph 419, backend 208 (including eight real PostgreSQL tests), web server 229. The two additional domain cases exercise standalone rule evaluation without prior evidence and policy-type validation.
- Maintainability: **734 functions measured; zero above CRAP 30**. Permission reconciliation, collector coverage and rule-lab validation now pass without lowering the threshold.
- Fresh release image built and restarted the existing local stack successfully, preserving encrypted history. A fresh GET-only worker scan completed with **1,522 objects, 1,100 relationships and 451 enterprise-application profiles**.
- Independent Azure CLI verification: **19 GET requests, 5,136 comparisons, zero mismatches and zero unavailable reads**. All 17 registrations and 451 enterprise applications were compared; owner checks covered four of each kind, assignment checks covered four resources, and all 14 collected delegated grants were checked.
- Read-only browser validation on the rebuilt image: **100 displayed field comparisons across 50 rendered identities**, HTTP 200, zero page errors, zero write requests, zero accessibility violations.
- Current dependency audit: **zero known vulnerabilities** across runtime and development packages.

## Scoped coverage

| Target | Statements | Branches | Functions |
|---|---:|---:|---:|
| Domain | 100% | 99.88% | 100% |
| Graph | 99.86% | 99.85% | 100% |
| Backend | 99.73% | 100% | 99.01% |
| Web server | 100% | 100% | 100% |

## Mutation verification

Every package completed a fresh `--force` run against the current production sources. No surviving or uncovered mutants remain.

| Target | Score | Killed by assertions | Detected by timeout | Survived / uncovered | Documented exclusions |
|---|---:|---:|---:|---:|---:|
| Domain | 100% | 3,285 | 6 | 0 / 0 | 10 |
| Graph | 100% | 2,131 | 4 | 0 / 0 | 65 |
| Backend | 100% | 702 | 0 | 0 / 0 | 14 |
| Web server | 100% | 619 | 0 | 0 / 0 | 12 |

Stryker counts non-terminating mutations detected by timeout separately from assertion failures. Exclusions are visible in source comments; the score applies to the mutations enabled by the published configuration. The new tests also exposed loose assertions that selected an unrelated permission row or accidentally accepted a wrong sort; those assertions now select the exact grant and check ordering from both input directions.

The targeted final scan checked **261 tracked/non-ignored candidate files**, with zero matches for the runtime client secret, encryption key, database password or real tenant/client identifiers. It reports aggregates only; live data and tokens remain outside Git.

## Reproduction and scope

- `TEST_DATABASE_URL=… pnpm verify`: Compose isolation, lint, type-checks, unit/contract tests, production build, desktop/mobile browser checks, and real PostgreSQL persistence flows. The test database must be an isolated loopback `entra_review_test` database containing synthetic data.
- `TEST_DATABASE_URL=… pnpm quality:crap`: measured coverage and complexity/coverage risk. Functions above CRAP 30 fail the command.
- `TEST_DATABASE_URL=… pnpm test:mutation --force --concurrency 2`: fresh Stryker runs; the existing 95% per-package floor is unchanged. Static mutants remain enabled.
- `pnpm security:dependencies`: current runtime and development dependency advisories.

Coverage and mutation scope is domain, Graph and backend production sources plus web server modules. These percentages do not claim coverage of every React component or worker line. Browser tests and database tests verify those boundaries separately. Optional live tests and intentional desktop-only skips are reported separately from passing tests.

Equivalent mutations are handled by simplifying redundant logic or narrowly documented source annotations. No whole new feature is excluded. Standalone catalog import tests catch module-initialization failures as failed tests; test discovery excludes leftover mutation sandboxes. Exact-value secret/tenant-ID checks supplement, but do not replace, a full Git-history secret audit or a container OS vulnerability scan.

## Upgrade notes

Review APIs require the displayed snapshot and an expected revision; stale or competing writes return HTTP 409. Startup applies the additive revision-column migration. Existing encrypted data remains readable. Restart web and worker together. Older snapshots display unknown for newly introduced metadata until a fresh scan supplies it. See [CHANGELOG](../CHANGELOG.md) and [OpenAPI](openapi.yaml).
