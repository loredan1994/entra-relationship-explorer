# Custom evidence engine

The **Evidence engine** screen contains ten local investigation workflows backed by `@entra-explorer/engine`. The engine has no Graph client, token access, database connection, or write transport. It consumes a projection of one tenant’s recorded snapshots and operator-supplied intent. Its public entry point is `packages/engine/src/index.ts`.

Engine version: `1.0.0`. Authorization rule version: `entra-configured/1`. These version the interpretation and replay format, independently of the application release.

## Read the result correctly

| Result | Meaning |
|---|---|
| Supported | A witness supports the stated proposition under the recorded model and assumptions. |
| Refuted | Complete relevant evidence, or incompatible explicit constraints, refute the stated proposition. |
| Unknown | Required facts, supported semantics, or search capacity are missing. |
| Conflicting | Relevant source variants disagree. Both variants remain available for inspection. |

These are **logical result states**, separate from **configured**, **observed**, and **inferred** evidence classes. A supported configured grant does not establish successful token issuance, policy satisfaction, successful resource authorization, or observed use. In contract results, supported means the contract passes; in counterexample results, supported means a counterexample was found. Each screen names the proposition being evaluated.

## Ten workflows

1. **Evidence proofs.** Select a principal, resource, question type and, where applicable, a resource-specific permission ID. Inspect source endpoints, source record IDs, dependencies, rule versions and derivations. Identical reordered inputs produce the same proof. The incremental evaluator fingerprints relevant predicate buckets, including negative dependencies, so an added alternative invalidates an old absence.
2. **Access compiler.** Evaluate application grants, delegated consent with a specific user, assignments, ownership, membership, active/eligible administrative roles, or possible control paths. Names never substitute for IDs. Eligibility never substitutes for activation. Scope matching is exact, not an inference about every operation a role might permit.
3. **Time-consistent paths.** Compare up to 100 supplied snapshots (the UI loads up to ten retained scans). A path must occur within one snapshot; edges from separate snapshots cannot manufacture a witness. Explicit source validity uses half-open intersections. Intervening time remains uncertain even when a path appears in repeated scans. A snapshot witness assumes scan consistency, not an atomic Graph transaction. Audit events do not establish continuity or causation.
4. **Change planning.** Supply operational costs for candidate relationship exclusions and protect required integrations. The weighted hitting-set solver finds plans covering all supplied paths. Protected alternatives require at least one surviving path. Exhaustive branch-and-bound establishes optimality only when it finishes. A deterministic greedy plan can seed an upper bound; bounded results expose both limits and the lower bound. The UI offers protected grants; the package interface also accepts protected integrations with several alternatives. Plans never apply changes.
5. **Policy counterexamples.** Declare MFA, compliant-device, or block intent over users and resource application IDs. The checker enumerates policy-literal boundaries, recorded group context, a complement representative, and boolean control combinations. It removes unnecessary scenario fields while preserving a violation. A negative answer applies to this declared finite domain. Up to 100 distinct witnesses are displayed. Exports can be compared manually with Microsoft’s What If tool; no What If POST request is made.
6. **Federation boundaries.** Compare exact v1.0 issuer, subject and single-audience constraints. Matching is case-sensitive; wildcards are literal characters, not matching operators. Overlaps include unsigned synthetic claims. Operator-entered claim values are assumptions. Historical comma-joined audiences, multiple audiences and preview expressions stay unknown. No real token is accepted or produced.
7. **Credential continuity.** Start a rotation template from collected metadata, supply deployment/retirement dates and workload dependencies, and inspect gaps, unknown intervals and rollback overlap. Missing deployment dates start as null. A clock-skew budget shortens both validity and declared deployment windows. `unavailableFrom` omitted means declared availability through the horizon; null means retirement time unknown. Shared dependencies identify affected workloads. Dates do not establish possession or use.
8. **Evidence gap planner.** Tie missing query prerequisites to candidate GET templates, declared read costs, read scopes and role guidance. Shared prerequisites are collected once. Candidate scopes are limited to 256 characters and validated as read-scope segments. The planner never grants consent, performs a read, infers session permissions from historical coverage, or treats a proposed read as guaranteed evidence. Non-collection gaps, such as missing user context, remain unresolved.
9. **Access contracts.** Evaluate tenant-bound declarative intent, return a shortest violating witness and compare semantic paths between retained snapshots. Display names, input order and collection timestamps do not create authorization drift. New alternative derivations do. Partial coverage changes pass to unknown, and missing paths are not confirmed removals. Contracts contain data only, never executable plugins.
10. **Portable verifier.** Export the facts relevant to a query, its proof, dependency manifest and versions. The verifier validates the bounded JSON structure, checks SHA-256 integrity and recomputes the proof. It rejects unsupported schema/version, missing dependencies, tampering and mixed tenants. It does not extract archives or process supplied filenames. Pseudonyms are stable within an export; the optional private mapping is saved separately. Pseudonymization does not anonymize topology, dates or source shapes. Hashes do not authenticate Microsoft as the source.

## Authorization support matrix

| Query | Supported semantics | Deliberately unresolved |
|---|---|---|
| Application permission | Configured client-to-resource application grant, exact permission ID | Token issuance, resource-side checks, policy satisfaction |
| Delegated permission | Exact scope ID, all-user or matching single-user consent, explicit user context | User’s underlying resource rights, requested runtime scope, authentication and policy |
| Application assignment | Direct user assignment or one direct group membership | Nested group inheritance, application-specific authorization |
| Group membership | Bounded transitive membership with cycle prevention | Hidden or incomplete membership absence |
| Ownership | Recorded ownership capability | Credential possession, exercised control, every administrative restriction |
| Active / eligible role | Separate assignment kinds and exact directory scope | Activation, implicit role-action expansion, restricted administrative-unit exceptions |
| Control path | Typed ownership/federation → registration/tenant identity → application grant | Treating API grants, membership, or observations as credential control |

The group-assignment rule follows Microsoft’s documented restriction: group-based enterprise application assignment does not expand nested groups. See [application assignment](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).

## Conditional Access support matrix

Supported inputs are user/group inclusions and exclusions, exact resource application IDs, platforms, client types and named-location IDs with a supplied trusted-location fact. Supported controls are block, MFA, compliant device, and hybrid-joined device, combined with AND/OR. All applicable enforced policies must be satisfied. Disabled policies are excluded; report-only results remain separate.

Uncollected/malformed fields, workload targeting, role/guest selectors, device filters, risk conditions, authentication strengths, session controls, compound resource aliases and service dependencies remain unknown. A definite supported exclusion can establish that a policy does not apply. Policy targeting is not evaluated as if malformed input were an empty allow-list.

These boundaries follow [Microsoft’s policy evaluation model](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies) and the [Graph condition-set schema](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0). Exact federation behavior is based on [Microsoft’s federation restrictions](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations). This implementation is a versioned offline subset, not a replacement for Entra’s authorization service.

## Data and migration

`federationTrust` preserves structured audiences. `conditionalAccess` preserves supported selectors and names of unsupported fields, without arbitrary raw Graph bodies. The policy read adds `sessionControls` to its existing v1.0 `$select`; it requires the same optional `Policy.Read.All` scope. Core permissions and optional-consent behavior are unchanged.

Old encrypted snapshots remain readable. Missing structured fields are unknown; a fresh read-only scan supplies them where current permission and endpoint coverage allow. The engine does not migrate historical data into invented facts. No database migration is needed.

## CLI and contract schema

Use explicitly supplied snapshot files outside Git. All commands are offline:

```sh
pnpm engine proof snapshot.json query.json
pnpm engine contract snapshot.json contract.json
pnpm engine compare before.json after.json contract.json
pnpm engine export snapshot.json query.json new-investigation.json
pnpm engine verify new-investigation.json
```

Proof/contract commands exit 0 for supported/pass, 1 for refuted/fail, and 2 for unknown/conflicting or invalid input. Verification exits 0 only after integrity and replay succeed. Export creates a new file with owner-only permissions and refuses to overwrite it. CLI export uses pseudonyms and does not save the private mapping. Comparison reports whether the evidence supports a complete semantic comparison.

```json
{
  "version": 1,
  "tenantId": "synthetic-tenant",
  "id": "production-only",
  "kind": "only-principals",
  "resourceId": "resource-object-id",
  "permissionId": "resource-permission-id",
  "allowedPrincipalIds": ["production-runner-object-id"]
}
```

Other kinds are `require-grant` (`principalId`, `resourceId`, `permissionId`) and `no-control-path` (`sourceIds`, `resourceIds`). Version, tenant ID and contract ID are required. Unknown fields and duplicate identifiers are rejected. Contract IDs and selectors are bounded; no JavaScript, expressions or plugins execute.

## Resource bounds and verification

| Operation | Bound |
|---|---|
| Compile a snapshot | 100,000 nodes / 500,000 relationships |
| Default authorization query | 50,000 steps / 128 paths / depth 12 |
| Maximum explicit query budget | 1,000,000 steps / 10,000 paths / depth 32 |
| Planning | 1,000 candidates / 10,000 paths / 1,000 protected integrations; 25,000 search steps in UI |
| Policy search | 10,000 scenarios by default, maximum 100,000; group closure stops after 100,000 relationship visits and unresolved groups remain unknown |
| Federation comparison | 20,000 pairs by default |
| Rotation | 1,000 deployment stages / 200 workloads / 1,000,000 evaluation steps |
| Contract | 100 KB / 100 IDs per selector / 250,000 evaluation steps |
| Portable package | 5 MB / depth 24 / 150,000 structural values |

Budgets are visible in results. Reaching a limit does not certify absence or global optimality. Bound completion and source completeness are separate facts.

Tests use exhaustive subset enumeration as an independent planning oracle, hand-authored policy decision tables, independent sampled-time interval checks, cross-tenant and malformed inputs, input permutation invariance, cache-versus-full replay, negative dependency invalidation and tamper checks. Browser checks cover all ten screens, meaningful interactions, accessibility, mobile overflow and absence of write requests.

Run `pnpm engine:benchmark` for generated distributions with machine, Node version, memory, query budget and timing included. See [recorded benchmarks](ENGINE_BENCHMARKS.md). Run `pnpm verify`, `pnpm quality:crap` and `pnpm test:mutation` before shipping. Engine mutation scope includes the production semantics and verifier; the shared mutation canary checks that nested test selection actually runs tests.

Delegated scope IDs are resolved only against the exact resource service principal’s collected scope definitions. Missing or ambiguous name-to-ID joins remain unknown, including older snapshots without resolved IDs. Ownership capabilities follow the user/service-principal owner types described by Microsoft’s [application](https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) and [service principal](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0) schemas.
