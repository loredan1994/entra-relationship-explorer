# Investigation tools

Open **Investigations** in the navigation. Every tool uses the current, tenant-scoped snapshot. Old encrypted snapshots remain readable: missing new metadata is displayed as unknown and is populated by a subsequent scan.

## Application access review

**Application access** combines each enterprise application (service principal) or managed identity with its matching local registration, identified by application ID rather than display name. Search by name, object/client ID, home tenant or publisher. The view records sign-in audience, enabled state, assignment requirement, preferred SSO mode, home tenant and the publisher verification ID/name. A publisher record is not a safety assessment. Missing or malformed fields remain unknown, including historical snapshots; a newly collected field is not a confirmed configuration change.

Direct incoming user/group assignments, application permissions and delegated consent preserve principal IDs, consent audience, source record IDs, endpoints and completeness. Mirrored role edges are not counted twice. Assignments are not expanded into effective group members. Owner evidence is specific to the tenant identity; registration ownership remains distinct. Empty results disclose whether the exact assignment, consent and owner endpoints completed. Microsoft’s default zero-GUID assignment is labeled “Default access (no specific app role)” only when the resource inventory declares no app roles; missing resources and unknown role IDs stay unresolved.

Observed successful user sign-ins appear separately with timestamps. They do not prove that a permission was exercised, and absence does not establish workload inactivity. The map inspector preserves this distinction when following an evidence link. Results display at most 50 matching identities, 100 incoming relationships and 20 recent observations; refine the search or use the map for the full recorded relationship inventory.

The collector adds allowlisted fields to its existing v1.0 application/service-principal GET requests under the current `Application.Read.All` scope. It does not collect redirect URLs, notification email addresses, notes, additional publisher fields or new secret material. The contracts follow Microsoft’s [service-principal properties](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0), [application properties](https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) and [app-role assignment semantics](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0).

## Evidence coverage

The matrix records each collector's status, reason, scope, operator-access guidance, collection time, record count, per-endpoint page/item limits, successful/failed endpoints and requested activity window. Scope/role guidance is not a claim that the signed-in operator has that role. Empty successful reads differ from denied, unavailable, disabled and legacy unknown evidence. Parent inventory failures also mark dependent collectors incomplete.

The current v1.0 collector records user sign-ins. It does not establish complete service-principal or non-interactive workload activity, so it does not generate workload-dormancy findings. A successful sign-in does not prove a configured permission was exercised. Group membership remains partial when the documented v1.0 service-principal omission can apply. Conditional Access edges describe inclusion references, not effective enforcement or exclusions. Path analysis is bounded to depth 5, 2,000 paths and 10,000 traversals; truncation prevents a prior finding being declared absent.

## Permission ledger

Application manifests (`requiredResourceAccess`) are reconciled with configured application grants and delegated consent, using resource app IDs and role/scope definitions. The ledger distinguishes requested-and-granted, requested-not-granted, granted-not-requested and unknown. It preserves all-users versus single-user consent and the principal ID. External application manifests are unavailable in the local tenant. No row asserts observed use or recommends automatic removal.

## Snapshot timeline

**Changes** lets an analyst choose a retained earlier/later pair from up to 20 snapshots. Metadata changes include before/after fields, consent audience, individual credentials and federation metadata. An absent record in incomplete or reduced coverage is unconfirmed. Field-level differences also remain unconfirmed when their source failed or an older schema never collected the field; a confirmed rename can coexist with an unconfirmed owner difference. The demo includes two explicitly synthetic snapshots. Findings' lifecycle continues to describe the latest retained history and is separate from the selected comparison.

Directory audit correlation is off by default. Set `ENTRA_COLLECT_DIRECTORY_AUDITS=true` for both web and worker before a new scan to collect a bounded 30-day window using the already-required `Directory.Read.All` permission. No additional Graph scope is requested. Access still depends on the operator role and available retention. Only event ID, time, activity name, result, actor ID/type, target IDs and source endpoint are retained. Modified properties, raw old/new values, UPNs, IP addresses and raw audit bodies are discarded.

Only successful events sharing a target object and the comparison interval are displayed as candidates. Federation changes match the native credential and parent identity IDs as well as the internal graph object. This is correlation, not attribution. Missing evidence says “Actor unknown.” Available events need not cover the full interval.

## Local what-if planner

Exclude up to 100 configured ownership, federation, membership, grant or role relationships in an in-memory copy. Compare baseline paths, paths absent in the scenario, remaining alternatives and reachable targets. Reset restores the baseline. An explicit export contains a versioned review plan tied to the tenant and snapshot, with excluded edge IDs and returned path IDs.

Use **Import review plan** to restore a plan exported for this exact tenant, snapshot ID and scan time. The importer accepts at most 100 KB and 100 eligible exclusions, rejects unsupported fields and stale or foreign plans, and recomputes results from the current evidence. Rejected imports leave the current scenario intact. Files are read locally in the browser; nothing is uploaded.

Candidate ranking evaluates at most 20 relationships from the returned paths and orders them by modeled path reduction. It is not an optimal cut, a business-impact estimate or proof that access would be revoked. Missing evidence, traversal limits, credentials already possessed, sessions and unmodeled conditions remain limitations. The planner makes no Graph or persistence request.

## Credentials and federation

Each password/certificate entry shows ID, kind, label, start, expiry and source endpoint. The scan-time state distinguishes expired, not-yet-valid, expires-soon (30 days), valid and unknown. A valid interval does not prove deployment or use. Rotation overlap and expired credentials with valid replacements are explicit. Federation issuer, subject, audiences, parent identity and evidence remain separate from credentials with expiry dates. The **Credential and trust history** section in Changes shows individual additions, removals and metadata changes, along with the earlier/later values and source endpoints. Unchanged validity dates crossing an expiry boundary are labeled **validity changed**, not a configuration edit. Missing inventories and missing managed-identity federation expansion remain unconfirmed. Secret values and certificate bytes are never retained.

## Decisions, recovery and retention

Live review decisions require an explicit save, the displayed snapshot ID and the loaded revision. A newer snapshot or competing edit produces a conflict instead of applying stale decisions. Loading and saving are tracked per finding; switching the queue preserves unsaved edits and cannot unlock an in-flight save. Accepted-risk dates must be valid calendar dates. Prior decisions require explicit revalidation. Demo decisions stay in browser storage.

Workers refresh their leases during a scan and perform stale recovery and retention maintenance at least once per minute while polling. Snapshot reads and current/prior decision reads exclude evidence older than 30 days even before cleanup. A former worker cannot update a job after another worker claims it.

## Verification

`pnpm verify` runs Compose isolation checks, lint, TypeScript, unit/contract tests, production build and desktop/mobile Playwright tests. CI also runs the PostgreSQL integration tests and real-browser persistence flow using an isolated service database. Locally, set `TEST_DATABASE_URL` to a disposable loopback database named `entra_review_test` and run:

```sh
pnpm --filter @entra-explorer/backend exec vitest run src/postgres.integration.test.ts
```

The integration suite uses synthetic records in unique tenants and cleans up its own rows. It checks migrations, encrypted reads, concurrent saves, tenant isolation, retention, lease recovery and old-worker rejection. With `TEST_DATABASE_URL`, `pnpm verify` also launches a separate synthetic live-mode server for `pnpm test:persistence`: two browser tabs attempt competing saves, then a new scan arrives before an old-screen decision is saved. The test checks the persisted records and rejects Graph/auth network calls from the browser. Without `TEST_DATABASE_URL`, the database integration tests and both persistence flows are explicitly skipped. No real Entra tenant is required for deterministic verification; live permission, operator-role and licensing validation remains a separate environment check.

Contracts were checked against Microsoft documentation for [application declarations](https://learn.microsoft.com/en-us/graph/api/resources/requiredresourceaccess?view=graph-rest-1.0), [consent audiences](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0), [sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [group-member limitations](https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0), and [directory audits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0).
