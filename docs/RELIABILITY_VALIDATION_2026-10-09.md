# Reliability and performance review — 2026-10-09

Baseline: `5a17b611c99bef5a7cb91a15fe6d599d3e4a390c`. This pass targets reproducible failures and measured work, not a claim that every tenant configuration is supported. Tenant validation uses read-only Microsoft Graph/Azure CLI requests. Synthetic tests use a separate PostgreSQL database.

## Corrections

| Area | Failure or wasted work | Correction and regression evidence |
|---|---|---|
| Authorization | Missing/conflicting intermediate identities could refute a possible path and pass a prohibition contract | Include traversed object dependencies even when type checks fail; distinguish unknown/conflicting from complete absence |
| Policy | A canonical conflicting policy or membership could manufacture a definite decision | Conflicting evidence remains unknown; an independent, known applicable block remains decisive |
| Temporal paths | One-sided validity bounds were discarded; offset timestamps sorted lexically | Intersect every known bound, preserve half-open exclusions, normalize observation instants before ordering/deduplication |
| Search performance | Repeated adjacency-array copies and inventory scans grew quadratically | Append to indexed buckets and prepare policy evidence once per search |
| Planning | Greedy/preprocessing work ran outside the search-state limit | Indexed incidence counts and a separately reported work budget; exhaustion cannot publish a partial plan or claim infeasibility |
| Large scans | Spreading entire Graph collections into `push` exceeded the JavaScript argument limit | Append bounded records without function-argument expansion; paginated 150,000-record regressions |
| Observed activity | Each sign-in searched the complete identity inventory again | First-match indexes preserve application/object ID collisions and explicit-ID precedence |
| Evidence UI | Table view computed hidden graph layout and rendered every relationship | Skip layout, render 50 rows per page, keep deep-linked evidence on the correct page |
| Engine state | New scan headers could retain previous query/result state; most tabs received ten unused snapshots | Bind state to tenant/snapshot; load one snapshot normally, two for contracts and ten for temporal history |
| Scan controls | Overlapping polls and failed actions could leave stale or stuck UI | Serialized polling, bounded request timeout, abort on navigation, stale-response rejection and retryable errors |
| Review storage | A newer scan could publish between route validation and review save | Serialize publication/review transactions per tenant; recheck current snapshot and commit review/audit together |
| Startup | Concurrent schema migrations could deadlock | Serialize schema migration and expired-auth cleanup in one database-wide transaction |
| Request/export boundaries | Review JSON was unbounded; quoted/encoded endpoint IDs could escape pseudonymization | Count actual streamed bytes before parsing; reject above 128 KiB; exact-token endpoint mapping with offline replay tests |
| Container builds | Source edits invalidated dependency installation | Install from manifests/lock/config/patches before copying sources; exclude package stores and nested environment files |

Engine interpretation is now `1.0.1`, authorization rules `entra-configured/2`. Older portable investigations need re-export from source snapshots. Encrypted historical snapshots remain readable; no tenant configuration or permission changes are required.

## Measurement method

Paired local runs compare baseline source with current source on the same generated inputs. Hardware: Apple M3 Max, darwin/arm64, Node 24.19.0. Other verification tasks were running, so these are examples of scaling behavior rather than latency guarantees.

| Synthetic case | Baseline | Corrected | Result check |
|---|---:|---:|---|
| 40,000 outgoing authorization edges, one traversal step | 3,858 ms | 30 ms | Identical complete proof output |
| 20,000 group memberships, one policy scenario | 515 ms | 10 ms | Same bounded scenario count |
| 20,000 unrelated identities, 16 policy scenarios | 55 ms | 3 ms | Same scenario domain |
| 20,000 identities × 20,000 sign-ins | 9,604 ms | 83 ms | Entire normalized snapshots deeply equal |
| 200 independent planning paths, one search state | 855 ms | 1.78 ms | New total-work limit stops at 10,000 units; bounded/unknown with no incomplete plan |

`pnpm engine:benchmark` includes the high-fan-out, group-membership and planner cases with hardware, limits and result states in its JSON output. Timing is not asserted in tests: instrumented inputs count visits, tests verify work limits, and independent subset enumeration checks exact plans. An additional review compared complete plan sets/ranking with exhaustive enumeration across 3,000 seeded problems. A further 2,500 problems with varied search budgets verified plan feasibility, minimality and bounds, including 67 bounded results.

## Reproduce verification

Set `TEST_DATABASE_URL` to an isolated loopback database named `entra_review_test`, then run:

```sh
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
pnpm security:dependencies
pnpm engine:benchmark
```

Browser checks use two local workers and one in CI; ordinary and persistence artifacts use separate directories. No test timeout or mutation threshold was relaxed. Persistence tests exercise revision conflicts, publication/review ordering, migration concurrency, snapshot replacement, evidence pagination and failed/interrupted scan requests.

## Recorded results

- 2,186 unit/integration tests: domain 552, engine 698, Graph 458, backend 215, web server/presentation 263. The separate opt-in live Graph test is skipped in the deterministic suite; live checks below use the authorized local environment.
- 71 browser checks: 62 desktop/mobile and nine isolated PostgreSQL persistence checks. Two desktop entries intentionally skip tests specific to the mobile project. Eighteen offline CLI subprocess checks pass.
- Coverage/maintainability: 1,059 functions, zero above CRAP 30. Engine coverage is 99.91% statements / 99.70% branches / 100% functions; server coverage is 100% across all three. No gate was reduced.
- Initial local incremental mutation results no longer represented the final tests after removing a platform-dependent exact work-count snapshot: the fresh hosted run scored 94.80% and correctly blocked the 95% gate. Nineteen additional behavioral cases address planner, contract and portable-export gaps. The fresh whole-engine rerun retested all 3,290 mutants and passed at 96.05%, with no reused results. The original hosted run passed domain/backend at 100%; local Graph and web results were 99.48% and 100%, respectively. Hosted checks rerun all packages on the final commit. The package threshold is 95%, not a per-file guarantee; fresh whole-package runs are authoritative.
- Independent review found no actionable regression after comparing 3,000 exhaustive planner cases. The public output compatibility tests pass under Node 24 and Node 26; work-counter snapshots allow variation in native sort comparison counts while behavioral tests enforce the work budget.
- Dependency audit: no known vulnerabilities at verification time. Known-secret/tenant-identifier scan passed without printing values.
- Production container built successfully. A second build after source changes reused the frozen dependency install layer. Updated web/database health checks pass; the existing tenant database and sign-in session were preserved.

## Read-only tenant validation

The updated runtime completed a fresh read-only scan and evaluated seven retained snapshots; the latest contains 1,522 objects and 1,100 relationships. The fresh snapshot was encrypted locally and correctly marked partial, including four unresolved delegated grants. Nineteen Azure CLI GET requests matched all 5,136 checked inventory/profile/credential/permission/ownership/consent fields, with zero mismatches and zero unavailable comparison reads. No identifiers or raw responses are included in this report.

Five application-grant proofs and 46 delegated-grant proofs were supported. Twenty relationship provenance checks matched stored source evidence. Pseudonymized replay succeeded, a deliberately forbidden recorded grant failed its local contract, and two retained observations preserved an uncertain intervening interval. The semantic comparison found zero changes under the tested contract.

With a fresh user sign-in, all ten engine workflows returned HTTP 200 with zero detected accessibility violations, zero page errors and zero non-GET/HEAD requests. Sixteen displayed tenant/snapshot/source fields matched the retained evidence. Browser checks blocked write requests and saved neither tenant screenshots nor raw data.

Current optional policy collection is disabled, group-membership evidence is partial, and directory-audit reads are denied. Policy results therefore remain unknown; these checks do not validate real policy enforcement or complete observed activity. Azure and browser checks changed no tenant settings or permissions.

## Interpretation limits

The tool remains a local, single-tenant workspace. Optional source coverage and collection windows can limit conclusions; configured grants do not prove observed use or effective authorization. Policy evaluation is the documented offline subset. Search/work limits establish uncertainty when exhausted. Pseudonymization reduces direct identifiers but does not anonymize topology or timestamps. Synthetic scale tests are not production load certification.

## Subsequent final sweep

The next sweep corrects six additional failure modes, with interpretation version `1.0.2` / rules `entra-configured/3`:

- Cancellation and lease loss now interrupt pagination, retries and long backoff waits; a request also rechecks after asynchronous token acquisition before dispatch. In-flight HTTP requests retain their existing timeout.
- Checkpoint writes hold the owning job row until the upsert finishes, so recovery or cancellation cannot leave a stale worker overwriting newer progress. Real PostgreSQL concurrency tests reproduce both original races.
- The threat queue loads minimal current review summaries in bounded batches. Saved statuses and acceptance-due filters work before an individual finding is opened; full records and revisions still load before editing.
- Imported engine inputs validate interpreted primitive fields before producing proofs. Arbitrary ignored metadata and absent optional historical fields remain compatible; whitespace-only provenance remains unknown.
- Relationship evidence cannot silently contradict its source and target object IDs. Existing inventory size limits are checked before examining records; oversized-array regressions use throwing element getters to verify this boundary.
- Contracts check referenced identity conflicts even when an allowlist generates no queries; before/after comparisons cannot call those results complete.

The regressions use synthetic fixtures and an isolated database. Existing public-format fixtures now keep their recorded source IDs consistent with graph endpoints; expected authorization semantics are unchanged. Versioned format snapshots were reviewed after the interpretation bump. The same unchanged 95% per-package mutation and maintainability gates apply to these changes.

The final-sweep verification passed 2,321 unit/integration tests (domain 552, engine 800, Graph 475, backend 225, web 269), 72 browser checks (62 desktop/mobile plus ten database persistence scenarios), and 18 offline CLI checks. The review-queue browser regression reproduces the original incorrect open status before the fix and passes afterward. All 17 cancellation regressions fail against the original behavior and pass after the correction.

Fresh local mutation runs passed at 95.92% for the engine, 99.28% for Graph, 100% for the backend and 99.85% for the web server. The unchanged domain package had passed at 100%; hosted CI independently reruns every package from scratch before merge. Coverage and maintainability checked 1,089 functions, with zero above CRAP 30. No threshold, exclusion or timeout was relaxed.

The updated production container completed another read-only scan, retaining eight encrypted snapshots. The latest again contains 1,522 objects and 1,100 relationships. Nineteen Azure CLI GET requests matched all 5,136 compared fields, with zero mismatches or unavailable comparison reads. Engine replay and all ten browser workflows passed against the updated runtime. The source-coverage limitations above remain unchanged. The disposable test database was removed; the running application image and its immediate rollback image are retained.
