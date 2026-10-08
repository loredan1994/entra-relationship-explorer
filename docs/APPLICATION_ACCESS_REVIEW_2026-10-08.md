# Application access review — 8 October 2026

**Historical checkpoint.** The counts, machine limitations and open quality gaps below describe this earlier pass. The current contribution is verified in [Release verification](RELEASE_VERIFICATION_2026-10-08.md).

This follow-up adds a resource-centered view under **Investigations → Application access**. It answers which identities have direct recorded assignments or consent to an application, alongside its sign-in controls and publisher context. Each relationship opens its original map evidence. Existing views, retained snapshots and Graph permissions remain compatible.

## Changes

- Collect sign-in audience, account enabled state, assignment requirement, home tenant, preferred SSO mode and verified-publisher ID/name through existing v1.0 GET inventory reads. Allowlist the retained fields and discard unrelated response properties.
- Match local registrations by application ID; never match display names or missing IDs. Sort duplicate names by object ID. Search identities, IDs, home tenants and publishers.
- Keep application grants, user/group assignments, delegated-consent audiences, owners and successful sign-ins distinct. Do not count mirrored app-role edges twice or infer effective group membership. Bound displayed records and disclose truncation.
- Explain assignment/owner/consent completeness using the successful and failed source endpoints. Preserve unknown historical fields and mark newly collected metadata differences unconfirmed in the timeline.
- Correct the map inspector's fixed “configured relationship” and missing-activity labels when the selected edge is an observed sign-in. Display its timestamp and requested window without claiming permission use.
- Recognize Microsoft's zero-GUID default assignment when the collected resource declares no app roles. Keep missing resources and other unresolved roles uncertain.
- Exclude coverage, test results, mutation sandboxes and local quality reports from the Docker build context and runtime image.

## Verification

- Complete functional suite: **1,086 unit/contract/database tests** and **48 browser checks**, including actual PostgreSQL concurrency/persistence flows and desktop/mobile accessibility checks. Two desktop-only cases and the separately optional Graph live test are explicitly skipped in the synthetic suite.
- Lint, TypeScript, production Next.js build, Compose isolation, dependency audit and whitespace checks pass.
- Production image builds, exports and starts successfully after Docker recovery. Its web process runs as UID 65532; health and database checks pass. Existing encrypted data survives the restart.
- A fresh owner-authorized live worker scan populated the new fields. The authenticated application review passed rendering, no-write and accessibility checks. Independent single-object Graph reads matched the sampled stored fields. Tenant material remains outside Git.
- Regression tests cover false versus unknown, malformed publisher fields, consent principal preservation, direction and duplicate counting, tenant isolation, default assignments, sorting and historical metadata uncertainty. Rendered inspector tests check configured, observed and incomplete states.
- A targeted in-memory check found no known client secret, encryption key or database password in tracked/non-ignored candidate files. This is not a full Git-history secret audit.

## Scoped coverage

Coverage was measured after mutation sandboxes finished, with the isolated PostgreSQL tests enabled. It covers production domain/Graph/backend sources and web server code; it is not whole-UI or worker coverage.

| Target | Statements | Branches | Functions |
|---|---:|---:|---:|
| Domain | 96.90% | 94.52% | 94.93% |
| Graph | 99.46% | 96.87% | 99.20% |
| Backend | 98.65% | 95.49% | 99.01% |
| Web server | 100% | 100% | 100% |

## Remaining limits

The product is still read-only. Optional live role/policy/activity permissions were not enabled. The tenant's opted-in directory-audit read remains denied, and v1.0 group membership remains partial. Publisher verification is not a safety verdict; sign-in settings and direct assignments are not effective-access evaluation.

The new application-access domain module passed all 78 mutants. The required 95% mutation gate remains unmet overall: domain **82.67%**, Graph **86.33%**, backend **88.90%**, web server **98.71%**. Backend mutants were fully rerun with PostgreSQL available; other packages used incremental reruns against the current tests. No threshold was lowered. Three existing functions still exceed the complexity/coverage risk threshold: `permissionLedger`, `recordStageCoverage`, and `parseRuleLabCase`. Functional success does not close those quality gaps.
