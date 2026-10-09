# Deep workflow review — 2026-10-09

This pass follows the [UI interaction review](UI_INTERACTION_VALIDATION_2026-10-09.md). It tests failure recovery, dense relationship inventories and evidence-engine edge cases. A successful page load is not sufficient: tests check the selected evidence, retained drafts, downloaded content, recovery transactions and logical conclusions.

All mutation and persistence scenarios use synthetic data and an isolated PostgreSQL database. Live validation is read-only. No tenant exports, credentials or private screenshots belong in this report or Git.

## Reproductions and corrections

| Area | Reproduced defect | Correction and meaningful regression |
|---|---|---|
| Dense maps | A node limit still allowed thousands of parallel edges into expensive label layout | Bound Map to 15 objects and 50 connections; preserve every relationship in Table and state the omitted count |
| Cyclic maps | Repeated rank propagation created enormous empty horizontal space | Layer strongly connected components as one column; preserve all relationships and verify all 64 directed three-object graphs against an independent reachability oracle |
| Map search | A relationship beyond the first neighborhood limit disappeared even when it matched the search | Filter before bounding, retain the selected connection and re-anchor deliberately when filters change; ordinary Inspect preserves pan/zoom |
| Browser review storage | Quota errors, denied access and malformed stored records could crash the editor or discard usable drafts | Keep working drafts in memory, validate stored records independently, preserve valid neighboring decisions and offer an explicit retry with truthful persistence status |
| Live review reads | A failed load stranded disabled controls; a later success left a stale error | Retry the selected read without losing another finding's unsaved owner or narrative; verify the surviving draft saves exactly |
| Export intent | Viewing or hovering findings generated export requests through route prefetch | Native download destinations with explicit client actions; browsing issues no export requests, and a click issues one download request |
| Export evidence | A new scan could silently replace the displayed finding's evidence in a download | Bind workspace downloads to the displayed snapshot; reject a changed scan with HTTP 409 before recording or producing an export |
| Export recovery | Authentication and upstream errors navigated away from the open investigation | Inline failure feedback, explicit retry, duplicate-request prevention, bounded wait and cancellation when selection changes; preserve owner, flow narrative and notes |
| Delegated consent | A service principal or group could be supplied as the user context | Require a recorded user; missing or contradictory context stays unknown or conflicting |
| Application assignment | Non-user group members could inherit an enterprise application assignment | Expand only direct user membership; group assignment itself remains inspectable and nested groups do not inherit |
| Path conflicts | Unrelated contradictory relationships contaminated independent path proofs and portable exports | Restrict path contradictions to source-reachable candidates, including relevant noncanonical variants |
| Temporal evidence | An incomplete overlapping path borrowed support from a different complete but disjoint path | Require its own complete compatible witness; retain partial-evidence and collection gaps instead of claiming absence |
| Credential continuity | Contradictory duplicate credential IDs produced different answers when array order changed | Report deterministic unknown for the conflicting credential; an independent unambiguous credential can still establish declared continuity |
| Scan session boundary | PostgreSQL scan reuse could return an active job for an invalid requesting session | Reject missing, expired and foreign-tenant sessions without writing an enqueue audit event; a second valid same-tenant session can still reuse a job |
| Cancellation recovery | Marking a job cancelled before deleting its checkpoint could strand ciphertext after deletion failed | Commit both actions in one transaction; inject a real database deletion failure, verify rollback, then retry and verify physical removal |
| Graph body failures | A connection failure after HTTP 200 headers bypassed request retries | Retry bounded body failures with fresh authentication and ownership checks, preserve previously collected pages and sanitize invalid JSON |

Observed local synthetic measurements: a two-object, 5,000-connection layout took approximately 6,380 ms before bounding and 10 ms for its 50-connection visual scope afterward. A 15-object cycle previously produced an 82,612px-wide layout; the corrected layout is 262px wide. These are reproducible scenario measurements on the development host, not service-level guarantees or claims about total page load time.

## Compatibility and boundaries

- Interpretation is now engine `1.0.3` / authorization rules `entra-configured/4`. Re-export older portable packages from their source snapshots; incompatible replay is rejected explicitly. Existing stored snapshots remain readable.
- Workspace CSV, finding, path and Attack Flow downloads supply `snapshot`. Direct API callers can omit this optional binding to request the newest snapshot; callers that need correspondence with a displayed view must supply it.
- No database migration, new Microsoft Graph scope, tenant write feature or external service was added.
- Map bounds affect presentation, not the retained inventory. Missing source evidence and bounded engine searches remain visible limitations.
- A browser draft surviving an error does not mean it is persisted. Copy unsaved edits before deliberately reloading or leaving to authenticate.

## Reproduce

Set `TEST_DATABASE_URL` to an isolated loopback PostgreSQL database named `entra_review_test`, then run:

```sh
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
```

New browser suites cover `export-intent`, `export-recovery` and `threat-recovery`. Database-backed browser suites cover `export-binding`, `map-scale` and `review-recovery`. Unit/integration regressions cover typed authorization context, temporal/continuity evidence, Graph response-body failures and transactional recovery. Previously established workflow tests remain in the full verification run.

## Verification results

- **2,475 unit/integration tests and 18 offline CLI checks passed:** domain 552, engine 834, Graph 486, backend 230 and web 373. The opt-in Graph live test is separate from the synthetic suite.
- **177 browser checks passed:** 151 desktop/mobile checks and 26 isolated PostgreSQL scenarios. Three project-specific duplicate cases are intentionally skipped. The full workflow run and focused reruns verify the final tests; the persistence suite completed in full after Docker compilation, with no relaxed assertions or increased timeouts.
- Production build, lint, TypeScript and Compose security checks passed. Coverage/maintainability assessed 1,092 functions with none above CRAP 30. Web-server coverage is 100%; browser interactions are evaluated separately rather than inferred from that metric.
- A fresh full engine mutation run scored **95.22%** across 3,535 mutants. Three additional behavioral tests then killed ten meaningful survivors in a fresh 171-mutant targeted run. Its combined report is **95.50%**, not a second full fresh run. CI repeats fresh mutation for every package at the unchanged 95% floor before merge.
- Dependency audit found no known vulnerabilities. The pre-publication scan found no known live credentials or private tenant identifiers in candidate files.
- The deployed local app passed **40 live interaction checks and all ten engine workflows**, with 49 displayed-source comparisons, zero browser errors, zero observed export requests/downloads and zero attempted writes. Accessibility checks on all ten engine workflows found no violations. Incoming Inspect, Back and reload were also verified in the user's existing in-app tab.
- A separate Azure CLI validation made **19 Microsoft Graph GET requests** and matched **5,136 comparisons** covering inventories, labels, application profiles, credentials, permission definitions, manifests, sampled owners/assignments and delegated consent. This verifies those collected fields, not unavailable policy or activity evidence.
- The new production container passed offline runtime checks, runs as an unprivileged user, and reports healthy PostgreSQL storage with the read-only Graph boundary. Updating web/worker preserved the tenant database and session; unrelated Docker services were not changed.

Synthetic coverage and read-only tenant comparisons cannot establish correctness for every tenant policy or browser environment. Live checks deliberately avoid analyst writes, downloads and tenant mutations; those failure paths are exercised against synthetic data.
