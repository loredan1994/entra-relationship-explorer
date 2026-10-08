# Custom engine validation — 9 October 2026

All ten roadmap workflows are implemented in the original `@entra-explorer/engine` package and the **Evidence engine** workspace. The [implementation reference](CUSTOM_ENGINE.md) specifies supported semantics, input formats, budgets and unresolved cases. Engine interpretation is versioned `1.0.0`, with authorization rules `entra-configured/1`; this does not declare the whole application a 1.0 release.

The engine consumes recorded, tenant-bound facts. It has no Graph transport, authentication client or database connection. Plans, policy scenarios and credential deployment assumptions remain local. No Microsoft Graph permissions were added, no tenant configuration was changed, and no raw tenant records or secrets were committed.

## Implemented and exercised

| Workflow | Verification beyond ordinary examples |
|---|---|
| Reproducible proofs | Canonical input permutations, contradictory source variants, missing evidence, source metadata and dependency invalidation |
| Typed authorization compiler | All eight query kinds, typed relationship matrices, exact resource permission IDs, user-specific consent, scoped roles and cache-versus-fresh evaluation |
| Time-consistent paths | Independent sampled-time interval oracle, half-open boundaries, disjoint snapshots and explicit uncertainty between observations |
| Weighted change planning | Exhaustive subset oracle for small instances, protected alternatives, deterministic equal-cost ordering and bounded-search reporting |
| Policy counterexamples | Hand-authored control/targeting tables, exclusions, AND/OR controls, report-only separation and malformed/unsupported inputs |
| Federation boundaries | Case-sensitive issuer/subject/audience comparisons, exact matching, conflicting sources and unsupported preview forms |
| Credential continuity | Independent interval checks, declared deployment dependencies, skew, gaps, retirement and rollback assumptions |
| Evidence-gap planning | Shared-read deduplication, unresolved non-collection prerequisites, scope guidance and no automatic reads or consent |
| Access contracts | Strict declarative schemas, shortest witnesses, semantic change detection and partial-evidence uncertainty |
| Portable replay | Independent-process CLI replay, missing dependencies, rehashed tampering, tenant isolation, size/depth limits and private mapping separation |

The UI exposes all ten workflows on desktop and mobile. The CLI implements proof evaluation, contracts, semantic comparison, export and independent replay. Eighteen subprocess checks verify actual exit codes, malformed input handling, owner-only export permissions and refusal to overwrite existing files or follow output symlinks.

## Automated results

The complete `pnpm verify` command covers Compose invariants, lint, types, unit/contract/database tests, the CLI, production build and browser flows. An isolated loopback PostgreSQL database contains only synthetic test fixtures.

- **2,004 unit/contract/database tests:** 552 domain, 566 engine, 445 Graph, 208 backend and 233 web-server tests.
- **64 browser checks:** 62 desktop/mobile checks and two separate PostgreSQL persistence flows. Intentional optional-live and desktop-only skips remain explicit; persistence flows were actually run.
- **18 CLI subprocess checks**, including local export and replay.
- **Coverage and maintainability:** 1,054 measured functions; zero above CRAP 30. Engine coverage is 99.89% statements, 99.56% branches and 100% functions.
- **Fresh engine mutation score: 95.69%.** Of 3,064 mutations, 2,910 were killed, 22 timed out, 128 survived and four had no coverage. This passes the existing 95% package gate; it is not a claim that every mutation was detected. Remaining survivors include redundant checks and unasserted formatting/guard variants. No threshold was reduced or production semantic module excluded.
- **Fresh Graph mutation score: 99.48%.** 2,300 killed, four timed out, 12 survived and none without coverage. Other production packages retain their existing mutation gate and are rerun by hosted CI.
- **Dependency audit:** zero known advisories at validation time.
- **Container:** the production image built with the reviewed Node 24 Alpine digest from PR #46 and restarted the existing local web/worker stack while preserving encrypted snapshots and sessions. Unrelated Docker services were left intact.

Coverage metrics apply to configured production modules, not every UI line. Public-format snapshots supplement behavioral assertions; they do not replace the independent planning, interval and policy expectations. Hosted Product verification also reruns coverage and all mutation packages from a fresh checkout, including the actual Stryker/Vitest nested-test-selection canary.

## Read-only tenant comparisons

Live inputs and session material stayed in process memory or the existing encrypted local database. Public results contain aggregate counts only. The active Azure CLI tenant was checked against the application's configured tenant before comparison.

| Check | Result |
|---|---|
| Core inventory and relationship comparison | 19 Azure CLI GET requests; **5,136 comparisons, zero mismatches**, no unavailable core reads |
| Delegated permission normalization and proofs | Seven GET requests; 14 consent records, ten fully resolved scope mappings, four unresolved mappings; **46 supported queries and 42 source checks, zero mismatches** |
| Application-permission proofs and offline replay | Five supported queries, 20 source checks, successful pseudonymized replay and a correctly failing forbidden-grant contract |
| Additional role/policy reads using existing CLI access | Four GET attempts; **three active-role proofs supported, zero mismatches**; eligibility read unavailable |
| Authenticated engine UI | All ten views returned HTTP 200; 16 displayed-source checks matched; zero page errors, axe violations or non-GET/HEAD requests |

Four delegated records had incomplete or ambiguous resource-scope mappings. They remain unknown rather than receiving guessed permission IDs. The optional role checks establish the returned active assignments, not complete role inventory: PIM eligibility was unavailable. The Conditional Access read returned **zero policies**, so live policy-control behavior could not be exercised. A counterexample in that empty policy model does not establish effective tenant access.

The saved application's optional role, policy and activity collectors remained disabled. Group membership was partial, and directory audit access was denied. Historical snapshots lacking structured trust/policy fields remain readable and produce unknown where needed. The authenticated UI correctly preserves these limits. No optional scope was enabled or consented for validation.

## Defects found and corrected during validation

- Hosted CodeQL identified a file-size check/read race and a potentially quadratic scope expression. The CLI now reads at most the permitted bytes plus one through a single open handle; scope parsing uses bounded, separately validated segments. Exact file-size boundaries, a growing input stream and crafted scope inputs have regression checks. The growing-stream test was also run against the original reader and failed as expected; the corrected reader passed.

- Missing single-user consent context and unresolved delegated scope IDs could otherwise turn missing evidence into a false negative. Both now remain unknown.
- Proof-cache dependencies now include source endpoint and collection metadata; canonical path ordering agrees with derivation references.
- Ownership and role facts enforce their supported principal/resource types. Conflicting grant, federation and credential variants cannot silently establish assurance.
- Planning removes redundant exclusions and rejects impossible protection requirements, including empty target sets. Query and contract budgets account for actual evaluation work.
- Malformed policy containers, selectors and session-control data remain unsupported instead of becoming unconstrained conditions.
- Large successful-endpoint inventories no longer exceed portable scalar bounds; minimized exports validate their own structure and replay before download.
- Rotation templates/results reset when the selected identity changes. Query controls have explicit accessible labels, and irrelevant query fields are cleared when the question changes.

## Reproduce

Use Node 24, the pinned pnpm version and an isolated database named `entra_review_test`. Set its loopback URL as `TEST_DATABASE_URL`; never point these tests at a retained tenant database. Run the following sequentially:

```sh
pnpm install --frozen-lockfile
pnpm --filter @entra-explorer/web exec playwright install chromium
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
pnpm security:dependencies
pnpm engine:benchmark
```

[Recorded benchmarks](ENGINE_BENCHMARKS.md) include generated distributions, hardware, memory and query limits. Larger samples deliberately report their 128-path limit. Local timings are observations, not service-level guarantees.

Live acceptance additionally requires an existing authorized tenant session. Compare only necessary GET responses, check tenant identity, and keep raw responses and tokens out of repository files and public logs. Unsupported Entra semantics, credential possession, token validity, service-side authorization and continuity between scans remain outside this engine's proof claims. SHA-256 detects package modification; it does not authenticate Microsoft as the source.
