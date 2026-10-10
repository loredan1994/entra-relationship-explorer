# Recovery and scale validation — 2026-10-10

This pass follows the [boundary reliability review](BOUNDARY_RELIABILITY_VALIDATION_2026-10-09.md). It tests interrupted dependencies, competing browser edits, ambiguous imports and a high-degree ownership graph. Each correction has a regression for the incorrect outcome, rather than an assertion that a page merely renders.

## Reproduced failures and corrections

| Area | Failure reproduced before the fix | Behavior covered after the fix |
|---|---|---|
| Browser-local decisions | Two tabs overwrote unrelated decisions or missed newly saved context; retrying a stale draft overwrote another owner's edit | Origin-wide Web Locks serialize read/merge/write. Authored fields merge independently; competing edits to the same field retain the unsaved draft and offer an explicit reload |
| Save recovery | Initial storage denial prevented later synchronization; a queued save was lost during client navigation, or its result missed a remounted workspace | Subscribe independently of the initial storage read, retain requested saves through client navigation, and notify both other tabs and the same window after persistence |
| Declared planning costs | Clearing a numeric field silently became a zero-cost candidate | Preserve the draft string, reject blank/invalid/out-of-range costs, and require explicit zero for an assumed free change |
| Investigation and contract imports | Native JSON parsing silently discarded earlier duplicate tenant, proof, secret-like or allowlist fields | Reject duplicate decoded field names before parsing, including escaped aliases and duplicates following escaped string values; enforce investigation nesting before parsing |
| Idle database connections | An idle pool error became an uncaught event and could terminate the web or worker process | Retain a permanent error listener, emit a static warning without connection/error contents, and let a later request reconnect |
| Graph pagination | A present but malformed continuation marker was accepted as the end of a complete collection | Only an absent continuation establishes completion. Invalid continuations fail before page progress is committed, preserving unavailable/partial coverage |
| Graph response resources | Retry and lost-ownership paths abandoned streaming response bodies | Cancel abandoned bodies before backoff or propagating the interruption; cleanup errors cannot hide the original failure |
| Ownership analysis | Each additional outgoing connection recopied the complete list of earlier connections | Append to new adjacency lists once, preserving relationship order, provenance, input immutability and traversal bounds |

The browser checks use synthetic fixture records, two actual pages sharing a context, held Web Locks and injected storage failures. Live tenant review endpoints retain their existing authenticated revision checks. Browser environments without Web Locks show explicit unsaved guidance. Full document unload cannot guarantee completion of a queued browser save; wait for the saved state before closing or reloading.

The PostgreSQL integration test uses an isolated loopback `entra_review_test` database and per-suite schema. It terminates only its own idle connection, constrained by PID, database, user and a unique application name. The next request must use a different backend PID and recover the unchanged encrypted synthetic session. It never restarts or terminates the live tenant database.

## Performance evidence

`pnpm intelligence:benchmark` constructs one synthetic owner with 1,000, 10,000 and 30,000 outgoing ownership relationships and no terminal grants. Input construction is outside the timer. Each size runs three sequential analysis calls and reports raw samples, their median, traversal bounds and process RSS.

On an Apple M3 Max, 14 logical CPUs, 38.65 GB memory and Node 24.19.0, the same profiled 30,000-relationship workload fell from **1,233.415 ms to 20.562 ms** after replacing prefix copies. The original CPU profile attributed 933 ms to adjacency construction and 284 ms to garbage collection. The result remained zero reportable paths, 10,000 traversals and an explicitly truncated analysis. A separate post-change three-sample benchmark measured medians of 1.006, 10.432 and 18.441 ms at the three sizes.

These measurements isolate a high-degree indexing case, not representative tenant latency or a service guarantee. RSS is process memory, not per-query allocation. A deterministic work-count regression avoids timing thresholds: the old implementation visited 502,500 relationship references for 1,000 connections and failed the 20,000-reference ceiling. The corrected implementation passes that bound and independently preserves distinct path witnesses and exact source endpoints.

## Reproduce

Use a disposable loopback PostgreSQL database named `entra_review_test` for `TEST_DATABASE_URL`. Do not point failure-injection tests at a tenant database.

```sh
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
pnpm intelligence:benchmark
```

Run coverage and mutation checks sequentially. New regression files include `threat-tab-recovery`, `engine-cost-recovery`, `threat-review-concurrency`, `portable-import-ambiguity`, `contract-import-ambiguity`, `postgres-disconnect`, `client-pagination-resources` and `intelligence-scaling`.

## Compatibility and limits

- Microsoft Graph calls remain GET-only; scopes, tenant boundaries and stored snapshot formats are unchanged.
- Valid investigation and contract files retain the existing engine version and format. Previously accepted ambiguous JSON is intentionally rejected.
- No database schema change is required. An active failed query still reports its error; idle-connection recovery does not promise replay of arbitrary failed transactions.
- Synthetic failure injection verifies the recovery paths. Live checks must remain read-only and cannot establish behavior for every tenant or deployment.
- Hosted CI retains fresh per-package mutation runs, the 95% package floor, coverage and CRAP 30 gates. Focused parser mutations supplement those gates; equivalent boundary iterations are documented rather than excluded to inflate scores.

## Verification results

- **2,766 unit/integration tests passed:** domain 554, engine 914, Graph 511, backend 296 and web 491. The opt-in Graph live test remains separate.
- **211 browser checks passed:** 181 desktop/mobile behaviors and 30 isolated PostgreSQL scenarios. Three duplicate project-specific checks are intentionally skipped. One database-browser navigation assertion initially exceeded its five-second deadline while a concurrent production image build saturated a shared 3.825 GiB Docker VM. The complete 30-test suite passed after stopping that build, with no assertion or timeout changes.
- Lint, TypeScript, production web build, Compose security validation and **18 offline CLI checks** passed.
- Coverage/maintainability assessed **1,137 functions**, with none above CRAP 30. Statement coverage: engine 99.92%, domain 100%, Graph 99.88%, backend 99.54% and web-server 98.95%. Browser behavior is assessed separately from server-code coverage.
- A fresh focused mutation run exercised all 73 mutations in the new JSON scanner: 66 killed, four timed out, three equivalent acceptance-boundary changes survived (**95.89%**). The three survivors add an ignored out-of-range iteration or give an array an unused object-key set; none enables ambiguous valid JSON. No exclusions were added. This focused result is not a substitute for the complete hosted package gates.
- The publishable-file check found no matches for the local deployment's known credentials or private tenant/client identifiers. Raw tenant data and private diagnostic outputs remain outside Git.
