# Follow-up review and implementation — 8 October 2026

**Historical checkpoint.** The counts, machine limitations and open quality gaps below describe this earlier pass. The current contribution is verified in [Release verification](RELEASE_VERIFICATION_2026-10-08.md).

The owner requested another review, more fixes and more features after the initial six additions. This pass used separate standards and specification reviews, reproduced the actionable findings, and re-reviewed the corrections. The implementation was reviewed in the shared working tree.

## Added features

| Addition | User-visible behavior | Verification |
|---|---|---|
| Reusable scenario plans | Import a previously exported local plan; bind it to the same tenant, snapshot ID and scan time; recompute path results | Round trip, forged results, cross-tenant/stale/schema/size/exclusion rejection, browser export/reset/import, rejected import preserves plan, no network writes |
| Individual credential and trust history | Show added/removed/changed passwords, certificates and federation metadata for the selected snapshot pair; separate time-driven validity transitions from configuration edits | Replacement certificate, exact expiry, changed metadata, empty versus unknown inventory, failed source reads, managed identity expansion |
| Interactive synthetic rule laboratory | Load positive/negative cases, edit declarative JSON, replay compiled rules, inspect expected/actual counts and supporting evidence | Browser positive pass, intentional failure, negative pass, stale-result clearing, tenant-import rejection, accessibility and no writes |

## Standards review — corrected defects

- Current/prior encrypted review reads now enforce the same 30-day retention boundary as snapshot reads. Real PostgreSQL tests leave the expired row physically present and assert it cannot be read or revalidated through prior context.
- Saves, errors and dirty state are bound to each finding. Pending decisions cannot be edited after navigating away and back; another finding's draft remains unsaved when the original request completes. Initial GETs are canceled when selection changes. The real-database browser regression holds a PUT pending during navigation and checks persisted values.
- Owner-read failures no longer masquerade as confirmed owner removal or increased risk. Field-level uncertainty can coexist with confirmed changes from an available source. Metadata key order creates no change, and permission IDs/definitions now participate in comparisons.
- Optional metadata absent from an older snapshot schema remains unknown. Managed-identity federation requires evidence of the federation expansion, not just base identity inventory.
- Canvas labels say successful sign-in and policy inclusion. Invalid calendar dates are rejected for review expiry. OpenAPI documents the mandatory snapshot and revision contract and conflict responses.
- The browser run caught a selection-restoration regression introduced during the save refactor. The corrected selection effect preserves restored demo drafts; desktop and mobile reload tests pass.

## Specification review — corrected gaps

- The relationship inspector and focused Markdown packets preserve consent audience and principal ID.
- Requested-but-not-granted rows disclose the actual successful grant endpoint used to establish absence.
- Federation timeline changes correlate candidate audits through native credential and parent IDs. Unrelated parents remain excluded, and candidate events remain explicitly non-causal evidence.

Both follow-up reviewers reported no remaining blocker in their final scoped re-checks. This is not a claim that the entire repository has no defects.

## Verification

The final `pnpm verify` ran against a disposable loopback PostgreSQL 17 database containing only synthetic records: **1,064 unit/contract/database tests and 46 browser checks passed**. Compose security, lint, TypeScript and production build passed. The browser suites cover desktop/mobile routes and two actual PostgreSQL persistence flows. One optional real-Entra test and two intentional desktop skips remain. Details: [verification report](VERIFICATION_2026-10-08.md).

No new Graph permission or tenant write was introduced. The implementation pass did not scan a live tenant. A subsequent owner-authorized validation did exercise live sign-in, scans, exports and persistence; it also patched dependency advisories and measured failing mutation gates. See the updated [verification report](VERIFICATION_2026-10-08.md) for current results, coverage scope and the final Docker storage limitation. No public deployment or publication was performed.
