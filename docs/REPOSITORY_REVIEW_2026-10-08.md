# Repository review and six proposed additions

Reviewed 8 October 2026 against commit `3d28b05be724fa4b5aa262cf190aa19a71ba1f95`.

The product has a substantial foundation for a local, read-only Entra investigation tool. Its strongest qualities are explicit relationship provenance, tenant-bound encryption, a constrained Graph transport, synthetic onboarding, accessible alternatives to the graph, and useful investigation exports. The next priority should be correctness of evidence and review state. Several conclusions currently overstate what the collected data can establish, despite passing tests.

This review proposes work; it does not implement product changes or authorize new Graph scopes, deployments, or Entra writes.

## Scope and verification

Reviewed the product and design specifications; Graph transport, collection and normalization; path discovery, rules, comparisons and finding lifecycle; authentication, API authorization, storage and worker lifecycle; review UI, exports, accessibility tests; container configuration; and open-source contribution and CI materials. Inspected the committed overview preview and ran the current browser suite. This was not a new manual accessibility audit.

| Check | Result |
|---|---|
| Compose security validation, ESLint, TypeScript | Passed |
| Domain tests | 282 passed |
| Graph tests | 325 passed; one live-tenant test skipped |
| Backend tests | 186 passed |
| Web server tests | 211 passed |
| Production build | Passed |
| Desktop/mobile browser suite | 28 passed; two desktop skips for mobile-only assertions |
| Coverage rerun | 100% statements, branches, functions and lines within the configured targets |
| Additional synthetic probes | Reproduced invalid privilege traversal, misleading lifecycle disappearance, immediate-restart queue behavior, lost consent audience, incorrect policy coverage, partial-scan removal classification and insufficient dormancy gating |

`pnpm run verify` completed its code checks and build, then hit a sandbox restriction opening port 3100. The browser suite was rerun successfully with localhost access. `pnpm test:coverage` also passed. There were **1,004 passing unit/contract tests** in total.

Coverage is scoped: the web package instruments `server/`, not the worker or React components. PostgreSQL unit tests use a fake pool; they do not exercise a real database's transactions, locks or recovery. No live tenant was scanned, no credentials were read, and no new PostgreSQL/container integration run or mutation run was performed. The API-related findings below distinguish documentation validation from live reproduction.

The public GitHub repository was also checked: it had no published release, no open issues, and 14 open pull requests, all concerning dependency maintenance. These are observations at review time, not evidence of adoption or a judgment about demand. See [releases](https://github.com/loredan1994/entra-relationship-explorer/releases) and [pull requests](https://github.com/loredan1994/entra-relationship-explorer/pulls).

## Findings to address first

Priorities describe product impact: P1 means address before relying on the affected investigation workflow; P2 means a material correctness, privacy or reliability issue. They are not vulnerability severity ratings.

### R1 — P1: Ordinary application use becomes an inferred privilege-control path

**Location:** [intelligence.ts:125–143](../packages/domain/src/intelligence.ts), particularly the traversal at line 128.

The path engine walks every outgoing relationship except observed activity. It can therefore traverse `person → ASSIGNED_TO → application → CAN_CALL_AS_APP → Microsoft Graph`. Being assigned to use an application does not, by itself, provide control of its credentials or its application permissions. The same underlying problem affects continuing through an API-call relationship into the resource identity's own privileges.

**Reproduction:** A three-node synthetic graph containing an ordinary user's Reader assignment and the application's `RoleManagement.ReadWrite.Directory` grant produced a **critical** path titled “Ordinary application user can reach Microsoft Graph.” No control relationship or application vulnerability was present.

**Fix:** Define explicit traversal semantics for each relationship and for the capability carried between steps. Keep application-use paths distinct from identity-control paths. API access should not automatically transfer control of the target. Add adjacent negative cases for ordinary app users, API callers and nested group app assignments. Microsoft distinguishes [application assignment](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal) from administrative control; it also documents that application assignments do not cascade through nested groups.

### R2 — P1: Analysis truncation can make an unchanged path appear gone

**Location:** [finding-lifecycle.ts:65,96–101](../packages/domain/src/finding-lifecycle.ts), [intelligence.ts:129](../packages/domain/src/intelligence.ts).

Absence is treated as trustworthy when collection is complete and endpoint coverage matches. It does not consider `pathAnalysis.truncated`. Collection completeness and analysis completeness are different properties.

**Reproduction:** Keep an administrator's existing role relationship unchanged, then place 2,000 other role paths ahead of it. The new analysis reports `truncated: true`; the unchanged finding is classified as `no-longer-detected` rather than `unconfirmed`.

**Fix:** Carry analysis completeness into lifecycle evaluation and exports. A prior path that was not evaluated must remain unconfirmed. Prefer reevaluating known paths before discovering new ones. Sorting the paths after a bounded walk also does not guarantee that the walk found the highest-priority paths; adjust the corresponding UI wording or search strategy.

### R3 — P1: A normal worker restart can strand the scan indefinitely

**Location:** [worker.ts:19–26](../apps/web/worker.ts), [postgres.ts:77–90](../packages/backend/src/postgres.ts).

Stale-job recovery runs once at startup, with a ten-minute cutoff. If the worker restarts while its old job is less than ten minutes old, recovery does nothing. The loop then claims only queued jobs and never repeats recovery. The old running job also prevents a new scan for that tenant.

**Reproduction:** Using the memory backend's matching state model, an immediate restart recovered zero jobs, claimed no job, and a new enqueue returned the same `running` job. Source inspection confirms that the worker never performs the later recovery call. This was not a process-kill test against PostgreSQL.

**Fix:** Repeat lease recovery at a bounded interval, with reliable heartbeat/lease ownership. Test crash-and-restart before lease expiry, cancellation during recovery, and stale-worker attempts to publish against an isolated PostgreSQL instance.

### R4 — P2: A review can be saved onto a newer snapshot than the analyst saw

**Location:** [threat review route:18–21,54](../apps/web/app/api/v1/threat-reviews/[id]/route.ts), [threat-workspace.tsx:56](../apps/web/components/threat-workspace.tsx).

The browser sends the finding ID and decision, but not its displayed snapshot ID. The route loads the latest snapshot and stores the decision against that snapshot. If a scan finishes while an analyst reviews an older screen and the finding ID remains stable, their decision can silently apply to unseen evidence. This defeats the intended explicit per-scan revalidation boundary.

**Evidence:** Traced the browser payload and route/store arguments; no live concurrent-session test was run.

**Fix:** Require the expected snapshot ID on reads, writes and revalidation, and reject stale edits with a conflict response. Use a review revision or ETag for concurrent edits. Test a scan completing between opening and saving a review.

### R5 — P2: Delegated consent audience disappears during normalization

**Location:** [normalize.ts:560–593](../packages/graph/src/normalize.ts).

The collector retains `consentType` and `principalId`, but the normalized delegated relationship drops both. Reviewers cannot tell consent for one person from consent for everyone, and comparisons cannot detect an audience change when the grant identity remains the same.

**Reproduction:** Changing a synthetic grant from `Principal` plus a person ID to `AllPrincipals` plus null produced an empty snapshot diff.

**Fix:** Preserve consent audience and principal ID as typed evidence, include them in fingerprints and focused exports, and label them in the inspector. Add cases for audience changes and different people with otherwise identical permissions. These fields have explicit authorization meaning in Microsoft's [delegated grant contract](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0).

### R6 — P2: The activity query does not establish workload-sign-in coverage

**Location:** [scanner.ts:363–369](../packages/graph/src/scanner.ts), [intelligence.ts:232–239](../packages/domain/src/intelligence.ts), [normalize.ts:344](../packages/graph/src/normalize.ts).

The transport allows only v1.0. Its activity query requests `servicePrincipalId` and `resourceServicePrincipalId`, but the current v1.0 sign-in resource documentation does not expose those fields. Workload event types and these identifiers are documented in beta; that API requires explicit event-type filtering to include non-interactive/workload events. The current query has only a lower timestamp bound. Separately, any successful sign-in endpoint collection enables dormancy findings for both application and delegated access, regardless of event-class coverage.

**Evidence:** Checked the current [v1.0 list contract](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [v1.0 resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0), and [beta event filtering](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta). A synthetic successful empty response enabled a finding claiming no matching workload activity. This establishes the unsafe coverage gate; the exact current tenant response to the query was not tested.

**Fix:** Establish an explicitly supported contract before enabling workload dormancy conclusions. Within the existing v1.0 boundary, label unsupported workload evidence unavailable. Do not silently widen the transport to beta. Track collected event classes, actual available window, requested start/end and completeness. A successful sign-in should be labeled as a sign-in to a resource; it does not prove an API call or a particular permission was used.

### R7 — P2: Group collection misses a documented service-principal limitation

**Location:** [scanner.ts:237–244](../packages/graph/src/scanner.ts).

The collector relies on `/groups/{id}/members` in v1.0 and records success as collected coverage. Microsoft currently documents a known issue where this endpoint omits service-principal members. The result can miss workload membership relationships without a collection error.

**Evidence:** Source trace plus Microsoft's current [group members documentation](https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0); not a live-tenant reproduction.

**Fix:** Validate the documented v1.0 expansion workaround, including any nested collection pagination limits, or explicitly mark service-principal membership coverage incomplete. Keep within GET-only v1.0 and existing permissions. Add a contract fixture that models a successful but semantically incomplete response.

### R8 — P2: Failed consent-policy detail is presented as complete

**Location:** [normalize.ts:209–212,333–338](../packages/graph/src/normalize.ts).

Once a permission-grant policy record exists, its metadata hard-codes `coverage: "complete"`, even if its include/exclude endpoints failed. The policy-assignment relationship then treats that target as resolved.

**Reproduction:** Return one custom policy, a 403 for its includes, and an empty excludes collection. The snapshot becomes partial, but the policy itself reports zero conditions, low risk and complete coverage.

**Fix:** Compute completeness from both per-policy detail reads. Distinguish “zero conditions returned successfully” from “conditions unavailable,” and propagate that status to the inspector and export. The Conditional Access collector also discards exclusions and many other conditions while emitting complete `GOVERNED_BY` relationships; label those as inclusion references unless applicability is actually evaluated. Microsoft documents explicit [user/group exclusions](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0).

### R9 — P2: Thirty-day retention depends on another successful scan

**Location:** [postgres.ts:94–105,140–143](../packages/backend/src/postgres.ts).

Expired snapshots and associated reviews are deleted only inside successful job completion. Reads have no age filter, and there is no periodic pruning operation. A tenant that stops scanning can retain and expose old snapshots indefinitely, contrary to the documented fixed retention period.

**Evidence:** Inspected all retention/deletion callers and the read query. This was not a timed database experiment.

**Fix:** Make tenant-scoped retention housekeeping independent of successful scans; also exclude expired results from reads. Document behavior while the application is stopped and cover backups separately. Test an idle tenant with expired snapshots, reviews and job references. Auth-flow/session cleanup likewise currently happens on migration, so maintenance should account for expired encrypted auth rows without redefining retention policy implicitly.

### R10 — P2: Partial collection is rendered as object/permission removal

**Location:** [comparisons.ts:68–69](../packages/domain/src/comparisons.ts), [Changes page](../apps/web/app/changes/page.tsx).

The generic comparison labels every missing relationship `removed`, including when the corresponding newer endpoint failed. The finding lifecycle is more cautious, so the two screens can give conflicting accounts of the same scan.

**Reproduction:** Remove a relationship from the newer synthetic snapshot and mark its assignment endpoint failed. The diff still emits `kind: "removed"` and increments the Removed count.

**Fix:** Add an unconfirmed/unknown comparison state based on source coverage. Show removal only when the relevant evidence supports it. Preserve the useful wording “absent from the latest scan,” but avoid placing it in the same confirmed-removal count.

## Architecture, UX and open-source assessment

**Keep the existing package boundaries.** Domain analysis, Graph ingestion, storage and web concerns are already separated well enough for these changes. A graph database or general plugin system is not required for the proposed features. The GET-only client, fixed origin/version checks, redirect refusal, scope allowlist, tenant-keyed SQL, authenticated encryption and explicit export projection are useful controls to preserve.

**Strengthen integration evidence.** The highest-value tests now are real PostgreSQL worker recovery, browser review persistence during new scans, and source-contract fixtures checked against Microsoft documentation. The current tests demonstrate implementation coverage, but the extra probes show missing behavioral cases. CI runs `verify`; coverage and mutation commands are available separately. Avoid describing the whole product as 100% covered.

**Measure the full large-tenant workflow.** The 10,000-object neighborhood test is useful, but it does not establish browser performance or full history-analysis latency. The map receives the entire snapshot, its relationship table maps all filtered rows, the threat queue renders all visible findings, and lifecycle analysis repeatedly analyzes retained snapshots. Add representative browser and server benchmarks before claiming the 10,000-application product target is met. Pagination/virtualization and analysis reuse are more immediate options than an architectural rewrite.

**Improve review persistence ergonomics.** A single debounced `pendingReview` can be replaced when a reviewer quickly edits another finding. The current acceptance-due filter also uses prior reviews, not the complete current review set. These deserve focused browser regression tests and a per-finding save queue or explicit save behavior. They were observed in source, not included among the reproduced findings above.

**Reduce triage noise.** Guest presence, managed-identity presence and any nonempty delegated grant currently generate findings. Such inventory facts are useful context but can overwhelm concrete control paths in a real tenant. Evaluate default prioritization with representative synthetic tenants and users; reserve prominent alerts for an explainable exposure, and keep inventory discoverable.

**Make an initial tagged release reproducible.** The repository already has licensing, notices, a contribution guide, issue templates, CodeQL, dependency review and pinned CI actions. Add a release checklist with migration notes, compatibility expectations and a maintained feature roadmap. Update the changelog for the shipped rule catalog and focused packets. The contribution guide's reference to a `security/` directory is stale in the tracked tree, and its mutation-score wording differs from the current 95% configured threshold. These are maintenance items, separate from the six product proposals.

## Six new additions

Sizes are relative implementation estimates, including meaningful tests and documentation: **S** is a contained extension, **M** spans a few modules, **L** adds a substantial analysis or workflow. They are not delivery-date commitments. All proposals preserve read-only Entra access and the local single-tenant model.

| Order | Addition | New value beyond the current product | Size |
|---|---|---|---|
| 1 | Scan readiness and evidence coverage | Explains whether a conclusion can be evaluated, and what prevented it | M |
| 2 | Requested-versus-granted permission ledger | Reconciles application intent, actual consent and the people covered | M |
| 3 | Change investigation timeline | Connects snapshot changes to available directory audit evidence | L |
| 4 | What-if access and blast-radius planner | Tests hypothetical relationship removals locally and explains remaining paths | L |
| 5 | Credential and federation lifecycle workbench | Shows individual credential transitions, overlap and affected workloads | M |
| 6 | Contributor rule laboratory | Makes safe, evidence-based rule contributions reproducible without a tenant | M |

### 1. Scan readiness and evidence coverage

**User question:** “Can I trust this result, and why is some evidence missing?”

Add a preflight/readiness view and persistent per-collector coverage matrix. Show requested scope, operator-role requirements, last successful read, collection window, item/page limits, and a reasoned state: not enabled, unavailable, denied, partial, complete or unknown. Each finding should show which prerequisite evidence is present. Analysis limits need their own status, separate from collection coverage.

This extends the existing scan progress and skipped-endpoint lists into a decision aid. Start with the existing core and optional collectors; no new scope is needed. Probe only explicitly enabled evidence, and never request consent automatically. Do not claim a particular licensing cause from a generic 403.

**Implementation seams:** collector result types, snapshot completion metadata, rule coverage predicates, Settings, and the finding inspector.

**Acceptance:** an empty successful result differs from a denied read; workload sign-ins remain unknown when only user events were collected; a truncated path search cannot make a previous finding appear cleared. Addresses R2, R6–R8 and supports R10.

### 2. Requested-versus-granted permission ledger

**User question:** “What does this app ask for, what was actually consented, and for whom?”

Add a side-by-side view of app registration requests, application grants and delegated consent. Highlight requested-but-not-granted permissions, grants no longer present in the manifest, user-specific consent, and all-user consent. Preserve the distinction between desired configuration, granted access and observed authentication.

The current collector does not select `requiredResourceAccess`. Add that application field and the resource's delegated permission definitions, then join permission IDs with values. Microsoft's [required-resource-access contract](https://learn.microsoft.com/en-us/graph/api/resources/requiredresourceaccess?view=graph-rest-1.0) defines the manifest side. Use the existing inventory scopes; verify the final endpoint selections before implementation.

**Implementation seams:** scanner/sanitizers, normalized consent types, application detail, permission table, comparison fingerprints and focused packets.

**Acceptance:** a one-person-to-all-users consent change is visible; missing local registrations are explicit for third-party apps; dynamic/incremental consent is explained rather than automatically treated as unauthorized. Build after R5.

### 3. Change investigation timeline

**User question:** “When did this permission change, and is there evidence of who changed it?”

Allow selection of retained before/after snapshots, show actual field differences, and optionally attach matching directory audit events. Start with permission/role assignments, ownership and federation changes. Include actor, timestamp, target IDs, event/result and correlation confidence only when the audit record supports them.

The current Changes page compares only the latest pair and gives generic descriptions; it has no directory-audit collector. Add time-bounded GET reads of `/auditLogs/directoryAudits`, explicitly opted into because they introduce activity and actor data. Microsoft lists `AuditLog.Read.All` as least privileged and the already-held `Directory.Read.All` as a sufficient higher permission; do not demand an extra scope when the existing authorization suffices. Operator-role requirements still apply. See [directory audit reads](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0).

**Implementation seams:** audit-event model and sanitized collector, retained-snapshot selector, field-level diffs, object timeline and focused evidence packets.

**Acceptance:** missing audit history produces “actor unknown”; ambiguous matches are labeled correlations; scan time is not misrepresented as exact change time. Honor retention and coverage. Build after R5 and R10.

### 4. What-if access and blast-radius planner

**User question:** “If this relationship were removed, which privilege routes would disappear and which would remain?”

Add a local scenario mode where an analyst excludes selected grants, ownership links, group memberships or federation relationships from a copy of a snapshot. Compare reachable identities/resources and known privilege paths with the original. Show alternate paths and a ranked set of candidate relationship removals, with each result traceable to original evidence.

This is new analytical behavior beyond the existing map and editable attack-flow narrative. It needs no Graph calls or new permissions. It must describe changes to modeled configured reachability, not promise business continuity or actual remediation.

**Implementation seams:** typed traversal semantics, scenario overlay, path comparison, selected-object map controls, versioned scenario export.

**Acceptance:** selecting a relationship never changes the original snapshot; alternate routes remain visible; unsupported control transitions are rejected; truncated analysis yields qualified results. R1 and R2 are mandatory prerequisites. This is the strongest potential differentiator once the model is trustworthy.

### 5. Credential and federation lifecycle workbench

**User question:** “Which specific credentials changed, are replacements overlapping, and what depends on this identity?”

The scanner already reads sanitized credential metadata and federated trust, but normalization reduces password/certificate credentials to one status and one expiry. Preserve a strictly allowlisted inventory of key ID, kind, start/end times and safe label. Add added/removed/expiring views, rotation-overlap indicators, and federation issuer/subject/audience diffs linked to the workload's configured access and accountable owner.

This extends the current aggregate expiry warnings and privileged federation-change rule into an operational lifecycle view. Existing inventory scopes should suffice. Keep raw certificate bytes, secret text and token material excluded, and do not infer which credential is in use from expiry metadata.

**Implementation seams:** credential domain types, normalizer, comparisons, application detail, owner grouping and focused evidence projections.

**Acceptance:** an expired old credential does not conceal a valid replacement; an unknown expiry differs from no credentials; each change has IDs and source evidence; rotation completion is never asserted solely from a new key appearing. Read-only planning only.

### 6. Contributor rule laboratory

**User question:** “Can I demonstrate a useful rule and its false-positive boundaries without connecting a real tenant?”

Build a developer command and optional fixture-mode workbench for replaying small, validated synthetic scenarios. Generate a rule scaffold plus positive, adjacent-negative, partial-evidence, ordering, tenant-isolation and stable-ID cases. Show the rule's prerequisites, expected findings, evidence references and version in a compact report that a contributor can include in a pull request.

The trusted catalog and Markdown contribution template already exist. The new value is executable scaffolding, scenario validation and visual replay. Keep authored rules repository-reviewed and compiled with the application; do not load arbitrary third-party executable plugins in a tenant session. Synthetic scenarios should remain separate from tenant exports.

**Implementation seams:** the existing rule interface and fixture helpers, a developer CLI, a versioned synthetic scenario schema, CI scenario checks, and an isolated fixture preview.

**Acceptance:** contributors can add a rule without credentials; invalid/mixed-tenant scenarios fail validation; the lab includes counterexamples such as R1 and R2; updating a rule shows changed expectations and requires a version decision.

## Suggested delivery order

First fix R1–R4 and the misleading evidence states; add worker/database and concurrent-review regressions. Then ship readiness/coverage and the permission ledger. Follow with the change timeline and credential workbench. Build the what-if planner only once path semantics and analysis completeness are dependable. The contributor laboratory can follow the stabilized rule contracts and make future expansion less dependent on the maintainer.

Scheduled scans, notification delivery, hosted multi-tenancy and write remediation remain separate decisions. None is required for these six additions to provide useful new capability.
