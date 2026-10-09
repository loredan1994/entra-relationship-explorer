# UI interaction review — 2026-10-09

This pass follows a report that Inspect appeared to do nothing and that navigation and refresh flows were unreliable. Earlier live checks established successful page loads and data agreement, not complete interaction coverage. This review exercises controls and their visible outcomes, including focus, viewport position, downloads, saved state and recovery.

Microsoft Graph remains read-only. Browser write/recovery tests use synthetic fixtures and an isolated PostgreSQL database. Live checks do not edit tenant configuration or saved analyst decisions. No tenant screenshots, exported records or credentials are included here.

## Reproduced failures and corrections

| Area | Failure | Correction and regression |
|---|---|---|
| Inspect | Evidence changed outside the visible area; keyboard focus stayed on the button; incoming evidence links selected an offscreen detail | Reveal and focus evidence, reset its scroll, then return to the matching relationship control; repeat selection, valid incoming links, stale links and presentation changes are covered |
| Responsive map | At a 980px viewport the inspector extended to x=1050; body-width checks missed the clipping | Stack the inspector before the three-column minimum is exceeded; test the panel's actual bounds |
| Long relationship tables | Intrinsic grid sizing pushed evidence outside the app frame; narrow columns broke names and headings mid-word | Bound desktop grid rows, scroll the result table independently, keep readable columns and a sticky Inspect column |
| Map controls | Fit retained pan; clearing an empty search lost canvas listeners | Recenter on Fit/Home and reconnect controls when the canvas returns; exercise pointer, wheel and keyboard actions |
| Filters and view changes | Table retained a selected map object's one-hop scope; same-route navigation retained old filters | Restore the full filtered table and synchronize state to navigation; exercise back navigation and no-results recovery |
| First mobile filter click | Streamed HTML enabled Filters before its event handler loaded, discarding a fast click | Keep the toggle disabled until interactive; a regression withholds JavaScript, then releases it and verifies one click opens the filters |
| Saved filters | Blocked browser storage threw an error while showing a saved filter | Show an explicit failure without claiming persistence |
| Overview and application detail | Review items lacked specific actions; missing application IDs could pair unrelated objects | Link exact findings and ownership category; pair only unambiguous nonempty IDs within the tenant |
| Authentication and scans | Callback errors were hidden; expired polling sessions retried indefinitely | Show safe failure guidance, stop unauthorized polling and offer sign-in recovery |
| Permissions | Demo export returned an error; unavailable tenant exports remained actionable; sort descriptions lied | Download synthetic CSV in demo, keep tenant authentication requirements, explain unavailable exports, and describe actual ordering |
| Changes | Historical lifecycle used future snapshots; earliest selection claimed only one scan existed; reset retained stale selectors | Bound history to the selected later scan, explain the missing earlier comparison, synchronize selectors and provide a working reset |
| Investigation filters | Clearing filters could show new records with an old visible state selection | Key forms to the selected view/query/state; assert both displayed controls and records after navigation |
| Application and finding selection | Selected details could remain below long lists | Reveal the selected detail with usable return navigation; test actual viewport position and keyboard focus |
| Long finding titles | Export actions squeezed a selected finding title into a narrow column | Give the title and action row their own space; inspect desktop and mobile previews |
| Review editing | Flow controls remained active while their updates were ignored during load/save | Disable all editing consistently and show pending feedback; exercise actual reorder/remove/add/reset and save/reload |
| Review limits | Successful saves silently truncated steps and text | Share limits between UI and API; reject invalid writes without changing data or revision; preserve exact boundary-sized input |
| Long generated reviews | Source explanations could exceed the editable narrative limit before any user edit | Mark shortened generated summaries and retain the complete source explanation; save/reload a real long-label fixture |
| Independent engine tools | Contract editing and offline import disappeared when an unrelated query was invalid | Keep these tools available; only package export requires a valid evaluated query |
| Asynchronous files and exports | Older work could overwrite a newer selection or download stale results | Assign request ownership, show pending status, and invalidate work after query/options changes; defer both file reads and hashing in regressions |
| Empty engine states | No federation trusts produced no feedback; clearing a rotation editor removed it | Explain missing evidence and keep editors available for correction |

Synthetic baseline measurements: mobile Inspect left the panel at y=2275 in an 851px viewport. A scrolled desktop selection left its heading above the viewport. These are interaction failures even though the content was present in the DOM and no JavaScript error was logged.

## Control coverage

| Screen | Controls exercised |
|---|---|
| Shared navigation / Guide | All nine primary destinations, all nine question links, local next-step links, global search submission, scrolled-page navigation and tablet reachability |
| Overview / application detail | Exact finding and ownership links, permission evidence, ID association boundaries |
| Relationship map | Map/table, search/clear, object filters, saved filters and failures, object/connection selection, return focus, pan/zoom/Fit/Home, paging and mobile filters |
| Permissions | Search, all exposure chips, type/write-only filters, four sort keys/directions, permission expansion, reset, load more, Inspect and real CSV downloads |
| Changes | Earlier/later selection, comparison submit/reset, earliest state, historical lifecycle, field and credential evidence |
| Investigations | Application selection/filter/reset, coverage disclosures, ledger filters/evidence, credential filters/reset, scenario selection/ranking/import/export/reset, rule cases/edit/replay |
| Threat workspace | Severity/lifecycle/category filters, exact finding links, evidence/packet exports, review revision conflicts, gated loading/saving, all flow edits, limits and persistence |
| Settings | Sign-in failure messages, authenticated/no-snapshot export availability, session expiry during start/poll/cancel, retained-job recovery, help/coverage links |
| Evidence engine | All ten workflows and eight question kinds; query context, proof links, costs/protection, policy intent, exact federation claims, rotation edits, contract templates/comparison, offline replay, exports and separate identity mapping |

## Reproduce

Use an isolated loopback PostgreSQL database named `entra_review_test` and set `TEST_DATABASE_URL` before running:

```sh
pnpm verify
pnpm quality:crap
pnpm --filter @entra-explorer/web test:mutation --force --concurrency 2
```

The added browser specifications are `map-interactions`, `navigation-interactions`, `settings-permissions-changes-interactions`, `investigation-interactions` and `engine-interactions`. Persistence specifications add empty-engine snapshots, review interaction/long-label saves and settings/session recovery. Existing browser tests remain part of the full run. Tests assert meaningful state changes; page loads, DOM visibility and absence of console errors alone do not establish that a control works.

## Verification status

- Compose security checks, lint, TypeScript and production build passed.
- **2,385 unit/integration tests and 18 CLI checks passed.** The opt-in Graph live test remains separate from the synthetic suite.
- **149 browser checks passed:** 129 desktop/mobile checks and 20 tests backed by an isolated PostgreSQL database. Three project-specific duplicates are intentionally skipped. The full browser suite was rerun after the incoming-link and loading-state fixes. The persistence suite was rerun in full after correcting synthetic job cleanup between session-expiry cases.
- Coverage and maintainability gates passed: 1,089 functions, none above the configured CRAP threshold of 30. Web server coverage is 100% for statements, branches and functions; this metric does not measure browser interaction coverage.
- A fresh web-server mutation run scored **99.85%**, above the unchanged 95% gate. The other packages are unchanged from the preceding fully verified revision.
- Dependency audit found no known vulnerabilities. The pre-publication scan found no known credentials or private tenant identifiers in candidate files.
- Independent source reviews found no remaining actionable issue after correcting return-focus behavior and long generated review summaries.
- In the existing live Chrome tab, selecting the last visible relationship focused the evidence panel with its heading inside the viewport and its internal scroll reset to zero. Back restored focus to that same selected row; browser reload completed successfully. After final deployment, Permissions → Inspect also revealed and focused live evidence at the mobile breakpoint. The local Docker health check passed with PostgreSQL storage and the read-only Graph boundary.
- The broader live audit passed **40 interaction checks and all ten engine workflows**, including nine primary destinations, Guide links, search/reload, Inspect/Back, filters, sorting, pagination and selection. It made 49 comparisons to recorded source data and reported zero browser errors, accessibility violations in the ten engine workflows, writes or downloads. Automatic export prefetches were blocked. Live exports, analyst edits and authentication/scan mutations were deliberately omitted; additional permission pages and material field-change disclosures were unavailable for the selected live data and remain covered synthetically.
- All five repository previews were refreshed from synthetic demo data. No live tenant screenshot was saved.

Scope remains bounded: synthetic browser coverage and read-only tenant checks cannot establish support for every tenant policy, browser extension or operating environment. Reload reads the saved snapshot; Settings → Start read-only scan requests a new collection. Session expiry, cancellation and scan recovery were exercised with synthetic sessions, without changing live tenant or analyst state.
