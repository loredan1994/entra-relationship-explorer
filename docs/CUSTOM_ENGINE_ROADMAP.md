# Custom engine roadmap

Proposal researched on 8 October 2026. These are ten proposed capabilities, not features available in the current release.

The product opportunity is a local Entra reasoning workspace where an analyst can reproduce each conclusion, see the assumptions that would change it, and compare a proposed change with both security goals and operational constraints. Our intellectual property should be the Entra semantics, evidence model, query evaluator, temporal analysis and planning algorithms. Keep PostgreSQL, MSAL, established cryptography, React and layout libraries for their existing jobs.

## What the market already covers

| Reference | Documented capabilities | Implication for this product |
|---|---|---|
| [BloodHound Enterprise](https://specterops.io/platform/bloodhound-enterprise/) and [OpenGraph](https://specterops.io/opengraph/) | Identity attack paths, remediation prioritization and extensible relationships across systems. | A graph, path search or extensible collector alone is not a differentiator. |
| [Microsoft Entra recommendations](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-recommendations) | Tenant recommendations and Identity Secure Score recommendations. | Another score or checklist has limited distinctive value. |
| [Microsoft Conditional Access What If](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) | Scenario evaluation for users and workload identities, including reasons policies apply or do not apply. | Basic policy simulation already exists. Our opportunity is versioned, offline, bounded counterexample search with explicit unsupported conditions. |
| [Maester](https://maester.dev/docs/intro/) | Custom security tests and automated configuration monitoring. | Custom tests alone are not novel; reusable semantic contracts with minimal graph witnesses offer a deeper direction. |
| [Maester Cloud](https://maester.cloud/docs) | Stored evidence, run comparisons, drift and trends. | History and retained evidence alone are not unique. Recomputable reasoning and time-consistent paths need to provide additional value. |
| [Semperis Purple Knight](https://www.semperis.com/purple-knight/security-indicators/) | Entra and hybrid identity exposure/compromise indicators. | More indicator rules alone will not establish the product's identity. |
| [Obsidian Security](https://www.obsidiansecurity.com/platform/data-that-matters) | Connected identity, entitlement and activity context, including non-human identities. | NHI inventory or an identity knowledge graph alone is insufficient differentiation. |

These are documented overlaps, not an exhaustive evaluation of vendor products. The opportunities below are product hypotheses; validate them with operators and comparable hands-on workflows before claiming exclusivity.

## Ten proposed features

### 1. Reproducible evidence proofs

Select a finding and inspect the complete derivation: source facts, collector coverage, rule version, assumptions, intermediate conclusions and contradicting facts. A small independent verifier should be able to reproduce the result from the exported inputs.

Build a custom provenance DAG with `supported`, `refuted`, `unknown` and `conflicting` states. Keep those states separate from configured, observed and inferred evidence classes. Dependency tracking invalidates only affected conclusions when a fact changes. A proof certifies a conclusion under the model and supplied facts; it does not certify effective access in Entra.

**New beyond today:** evidence packets currently project findings and referenced relationships; they do not execute an independently verifiable derivation.

**Acceptance:** shuffled inputs yield the same canonical proof; removing a required source produces unknown; contradictory sources remain visible; changing a rule version invalidates its prior result; another tenant's fact is rejected. Uses existing snapshots. Priority: foundation.

### 2. Entra authorization compiler

Ask, “Under which recorded conditions could this principal access this resource?” Get a structured explanation of grants, consent audience, applicable role scope, eligible versus active assignments and unresolved conditions. A configured delegated grant must still expose its user-context requirements.

Compile Entra records into a typed intermediate representation and evaluate a documented subset of authorization semantics with a custom fixed-point evaluator. Distinguish app permissions, delegated permissions, assignment controls, ownership capabilities and administrative roles instead of treating all graph edges as interchangeable reachability.

**New beyond today:** the permission ledger reconciles requests and grants; the compiler combines supported conditions into queryable, versioned derivations.

**Acceptance:** differential fixtures for delegated/app-only access, resource-specific permission IDs, nested groups, scoped roles and PIM eligibility; no manufactured “effective access” answer when policy or membership evidence is incomplete. Core data uses existing reads; role and policy facets require their existing optional read scopes. Priority: foundation after 1.

### 3. Time-consistent path reconstruction

Ask, “Did all prerequisites for this possible path overlap at any point we can establish?” Separate a path supported at one collected instant from a path assembled from relationships that never coexisted.

Build a custom temporal graph using observed-at time, source validity intervals and bounded uncertainty between scans. Intersect prerequisite windows during traversal; retain event-time versus collection-time differences. Directory audit events add context without being treated as complete attribution.

**New beyond today:** snapshot timelines compare fields; this engine evaluates the temporal compatibility of entire multi-step paths.

**Acceptance:** disjoint role/credential windows yield no time-supported path; unknown change times yield an uncertainty interval; out-of-order events and retention gaps cannot invent continuity. Uses retained snapshots and optional existing audit/role reads. Priority: second wave.

### 4. Minimal-change planning solver

Ask, “Which smallest set of proposed changes breaks these modeled paths while preserving these required integrations?” Compare several plans, their residual paths, affected applications and analyst-assigned operational costs.

Build a bounded weighted hitting-set solver over proof dependencies, with protected-path constraints and branch-and-bound for small cases. Larger cases use a documented approximation and return the search limit and best known bound. Plans remain local artifacts; no changes are applied to Entra.

**New beyond today:** the what-if planner evaluates manually selected exclusions; this solver proposes and ranks combinations under constraints.

**Acceptance:** match exhaustive solutions on small generated graphs; never label a heuristic result optimal; detect infeasible protection constraints; removing one edge must preserve and report alternate paths. Uses existing graph data plus user-supplied intent. Priority: first distinctive workflow after 1–2.

### 5. Policy counterexample generator

Ask, “Show a supported sign-in scenario that violates our stated policy intent.” Generate a minimal identity/resource/device/location scenario explaining the exception, rather than requiring the analyst to guess every scenario manually.

Build a custom finite-domain model checker for an explicitly supported Conditional Access subset. Generate decision-table boundary cases, evaluate overlapping policies and minimize counterexamples. Unsupported conditions return unknown. Report-only policies remain separate from enforced controls.

**New beyond today:** policy records provide investigation context; this adds bounded, reproducible counterexample search across a policy set.

**Acceptance:** exclusions, missing device facts, report-only controls and conflicting policies have independent fixtures; compare supported synthetic cases with published Microsoft behavior. Export scenarios for an operator to compare with Microsoft's What If tool. Do not call its evaluation API through the GET-only collector. Requires optional `Policy.Read.All` plus necessary existing identity evidence. Priority: later semantic expansion.

### 6. Federation trust boundary analyzer

Ask, “Which external workload identities could satisfy these recorded trust conditions, and where do trust definitions overlap?” Present exact issuer/audience/subject constraints and a synthetic witness for any supported overlap.

Build a custom trust-expression representation, matching evaluator and set-intersection algorithm. Begin with exact v1.0 issuer, audience and subject semantics. Unsupported preview expressions remain unknown; do not silently interpret them as exact subjects or broaden the collector to beta. Optional operator-supplied CI context must be separately labeled as supplied evidence.

**New beyond today:** federation inventory displays credential metadata; this analyzes the meaning and intersection of trust boundaries.

**Acceptance:** case sensitivity, audience mismatch, issuer mismatch and distinct repository/environment subjects cannot collapse into a match. Witnesses contain synthetic claims, never real tokens. [Microsoft's beta resource](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta) documents additional expression semantics; supporting them would require a separate collector/version decision. Priority: second wave.

### 7. Credential continuity simulator

Ask, “Under these declared deployment assumptions, does this rotation plan leave any interval without a usable credential?” Show gaps, overlap, modeled rollback windows and identities affected by a shared credential dependency.

Build a custom interval and dependency simulator that combines metadata validity with operator-declared deployment stages. Distinguish a credential that is valid by metadata from one proven deployed or used. Never infer certificate possession, successful authentication or safe retirement from dates alone.

**New beyond today:** the workbench identifies expiry and rotation overlap; the simulator evaluates an ordered migration plan and its assumptions.

**Acceptance:** validity-boundary equality, clock skew budgets, unknown deployment completion and loss of the fallback credential have explicit cases. Output must identify which assumptions need operator confirmation. Existing metadata suffices for initial planning; workload-use evidence is optional and separately scoped. Priority: second wave, narrowly scoped MVP.

### 8. Evidence gap planner

Ask, “What is the smallest additional set of reads that could resolve this unknown conclusion?” Show the specific unresolved prerequisites, candidate endpoints, existing permission availability, collection cost and any role/license dependency.

Build a custom query-dependency planner that finds shared missing facts and ranks bounded read sets by which unknowns they can resolve. Rank using declared costs and deterministic coverage, not invented probability scores. Never auto-consent or expand scopes. A proposed read can still return partial or denied evidence.

**New beyond today:** evidence coverage describes collector status; this links missing evidence to the particular question and proposes a minimal follow-up plan.

**Acceptance:** shared dependencies are fetched once; failed/partial reads never count as absence; pagination exhaustion and unsupported endpoints remain explicit; proposed scope sets are minimal on small exhaustive fixtures. Uses current coverage and the compiler dependency graph. Priority: foundation after 1–2.

### 9. Access contracts and semantic change review

Define intent such as, “Only the production runner may hold this application permission,” or, “No externally federated workload may reach these protected applications through supported control paths.” Review whether a new snapshot changes the meaning of access, not merely its JSON fields.

Build a small declarative contract language compiled into the same typed evaluator. Each failure returns a minimal witness subgraph and each indeterminate result identifies missing facts. Support a local CI command against synthetic or explicitly supplied snapshots, with versioned schemas, bounded evaluation and no executable plugin code.

**New beyond today:** the rule laboratory checks synthetic rule cases; contracts encode an operator's access intent and assess semantic drift between real retained snapshots.

**Acceptance:** reorderings and display-name changes do not create authorization drift; a new alternate access path does; partial collection changes a pass to unknown rather than a false pass. Contracts and snapshots are always tenant-bound. Priority: first distinctive workflow after 1–2.

### 10. Portable investigation verifier

Export one investigation as an offline package that another analyst can inspect and recompute without connecting to the tenant. Include the minimum required facts, engine/rule versions, proof dependencies, uncertainty, collection windows and integrity manifest.

Build an original projection and deterministic replay format with a small standalone verifier. Offer stable per-export pseudonyms for identities, with a private mapping kept outside the export. Standard cryptographic hashes detect modification; they do not prove Microsoft originated the records. Minimize unneeded topology and explicitly state that pseudonymization is not anonymization.

**New beyond today:** focused evidence packets are readable exports; this adds bounded offline replay and independently checked conclusions with a data-minimized sharing mode.

**Acceptance:** replay yields identical supported conclusions; changing a fact is detected; absent dependencies are rejected; path traversal, oversized inputs and cross-tenant mixes fail safely; no token/credential values can enter the format. Uses existing facts and proof output. Priority: second wave after 1.

## One reusable engine, ten workflows

Start with an original `@entra-explorer/engine` package, implemented as pure TypeScript over immutable tenant-bound facts. Keep the existing domain package as the migration boundary; do not rewrite the UI or collector to launch the first feature.

```text
Existing read-only collectors → versioned facts + coverage + collection windows
                              ↓
                    Entra semantic compiler
                              ↓
                 Bounded incremental evaluator
                 ↙            ↓             ↘
          proof graph    temporal queries    contract evaluator
                 ↘            ↓             ↙
             planning / counterexamples / independent replay
                              ↓
                Existing evidence inspector and accessible tables
```

Own the fact schema, semantic rules, incremental dependency index, proof representation, temporal operators and planning logic. Continue using mature libraries for authentication, encryption, storage and rendering. Contributions extend reviewed declarative semantics and fixtures rather than loading arbitrary runtime JavaScript.

Every query result carries its tenant, snapshot set, rule/engine version, evidence references, assumptions, completeness and resource limits. Absence can establish a negative claim only when the relevant collection boundary is complete. A graph path alone never establishes real service authorization or observed use.

## Delivery and verification

1. **Foundation:** implement 1, then a narrow application-permission slice of 2 and query-specific missing facts from 8. Demonstrate one conclusion that another process can reproduce and invalidate correctly.
2. **First product advantage:** implement 4 and 9 for that same supported slice. Demonstrate a proposed minimal plan that breaks modeled exposure while preserving declared required access, plus a contract that detects its regression.
3. **Depth:** add 3, 6, 7 and 10 using the same provenance machinery. Expand 5 only after publishing the supported policy semantics and comparison fixtures.

Use independent oracles: exhaustive enumeration for tiny planning problems, a deliberately simple full evaluator to check the incremental evaluator, interval algebra fixtures, and published Entra examples for supported semantics. Metamorphic tests cover reordered facts, irrelevant additions, cross-tenant contamination and loss of evidence. Keep mutation tests focused on semantic decisions, not merely line execution.

Publish benchmarks with generated graph distributions, hardware, memory limits and query budgets. Set performance targets after measuring the prototype; return a partial/limited result rather than silently truncating a proof. Publish the feature support matrix and remaining unknowns beside the UI, not only in contributor documentation.

Success criteria for operator trials: time to reproduce a conclusion, incorrect confident conclusions under missing data, fraction of a plan independently verified, and useful minimal counterexamples found. Rule count and the number of drawn edges are secondary metrics.
