# Dependency follow-up — 8 October 2026

This change consolidates the remaining reviewed dependency work on top of the merged investigation release (#42). It preserves the GET-only Microsoft Graph boundary, existing consent scopes, Node 24 runtime and dependency license gate. At the time of this dependency change, the [custom-engine roadmap](CUSTOM_ENGINE_ROADMAP.md) contained proposals. The subsequent [engine validation report](CUSTOM_ENGINE_VALIDATION_2026-10-09.md) records their implementation.

## PR resolutions

| Reviewed update | Implemented resolution |
|---|---|
| #17: dependency review action | Adopt the pinned 5.0.0 revision; preserve severity and license settings. |
| #24: pnpm setup | Adopt the pinned 6.1.0 revision in both verification jobs; retain pnpm 11.23.0. |
| #38/#39, regenerated as #43: CodeQL | Use the same 4.38.2 commit for initialization and analysis. Keep the Dependabot group. |
| #30: development tooling | Adopt refreshed ESLint 10.12.0, typescript-eslint 8.71.1 and Playwright 1.63.0, with the matching Chromium installation. |
| #41, regenerated as #44: production patches | Adopt Cytoscape 3.34.3, tsx 4.23.15 and pg 8.23.1; retain Next 16.3.8 and the optional sharp exclusion. |
| #25: Node declarations | Retarget all four packages to 24.19.1, matching the Node 24 runtime. Prevent future automatic declaration upgrades beyond that runtime. |
| #40: Vitest major migration | Align Vitest and coverage-v8 at 5.0.3 in every package, retain explicit Node types, and group future Vitest updates. Keep Stryker 10, static mutations and the existing 95% gate. |
| #20: MSAL major migration | Adopt 6.0.0 with real-library synthetic protocol/cache tests and live sign-in, refresh and restart checks. No scope, callback or session-lifetime changes. |

Historical PRs are superseded only after the consolidated contribution passes its final checks and merges. Exact upstream versions and transitive resolutions are recorded in the lockfile; direct notices and inventory were updated together.

## Authentication verification

Four new tests exercise the installed MSAL implementation. Only its network transport is replaced. They validate the real PKCE hash, tenant-specific authorization URL and query callback, code redemption, serialized cache restoration in a fresh client, refresh-token rotation through another fresh client, and rejection of a revoked refresh credential. Synthetic expired cache entries are used only in tests; the live session was never extended or made artificially valid.

The owner completed a fresh sign-in on the upgraded local image. A real forced silent refresh returned `fromCache: false`; its access token successfully performed a GET of the configured tenant's organization record. The updated encrypted local cache was retained without changing session expiry. After restarting only web and worker, a fresh MSAL process returned `fromCache: true` from that persisted cache and passed the same tenant GET.

Before and after restart, authenticated browser checks matched **100 displayed fields across 50 identities** to the snapshot, with HTTP 200, zero page errors, zero non-GET/HEAD requests and zero axe violations on the application-access page. The unused image-optimization endpoint returned 404. This resolves the expired-session limitation in the earlier release report.

Independent Azure CLI validation repeated **19 GET requests and 5,136 comparisons**, with zero mismatches or unavailable reads. Raw tenant objects, tokens, session identifiers and secret values were kept out of repository files and public logs. No Entra permissions, roles, grants, registrations or credentials were changed. The earlier optional-collector limitations still apply.

## Automated verification

The first Vitest 5 mutation run exposed Stryker 10's nested-name compatibility bug: 699 domain mutations falsely survived because selected tests did not run. The installed runner constructs space-separated filters, while [Vitest 5 uses ` > ` between suites](https://vitest.dev/config/testnamepattern). A minimal pnpm patch backports the reviewed filter change from [upstream PR #6247](https://github.com/stryker-mutator/stryker-js/pull/6247), including its suffix anchor to avoid similarly named siblings. This is development-only; attribution and the modified component are recorded in the notices.

`pnpm test:mutation:runner` runs the actual installed runner against a tiny temporary synthetic project. It failed before the patch with zero selected tests and passed afterward: five boundary mutants killed, and one deliberately weak arithmetic test's survivor executing exactly its single covering test. Nested names contain regex metacharacters, and a prefix-matching sibling must not be selected. This canary precedes every root mutation run. Its deliberate survivor is separate from product scores; no production thresholds or exclusions change. Remove the backport only when an upstream version passes this canary and the full mutation suite.

- Full `pnpm verify` passed with **1,412 unit/contract/database tests**, including eight real PostgreSQL integration tests, and **52 browser checks** (50 desktop/mobile and two real persistence flows). Optional live-test and intentional desktop-only skips remain explicit.
- An initial local browser run reused an older preview server after the build changed. Verification now owns a fresh server on port 3102 and refuses reuse; preview port 3100 and persistence-test port 3101 remain separate. The complete verification command passed after this correction.
- `pnpm quality:crap` passed: **734 functions, zero above CRAP 30**. Measured coverage remains domain 100/99.88/100, Graph 99.86/99.85/100, backend 99.73/100/99.01 and web server 100/100/100 for statements/branches/functions.
- `pnpm security:dependencies` reported zero known advisories. The production image built, ran as the existing non-root identity and preserved encrypted database history across restarts.
- Fresh local and hosted mutation verification are release gates for this migration, rather than relying on the earlier Vitest 4 results. The final commit's Product verification `quality` job records its score tables. No thresholds or exclusions were relaxed for the upgrade.

Coverage and mutation metrics cover the configured domain, Graph, backend and web-server modules, not every UI or worker line. Authentication protocol contracts use synthetic identity-service responses; the separately documented tenant checks supply the live acceptance evidence.

## Reproduce

Use an isolated PostgreSQL database named `entra_review_test`, bound to loopback, containing only synthetic fixtures. With its connection URL in `TEST_DATABASE_URL`, run these sequentially:

```sh
pnpm install --frozen-lockfile
pnpm --filter @entra-explorer/web exec playwright install chromium
pnpm verify
pnpm quality:crap
pnpm test:mutation --force --concurrency 2
pnpm security:dependencies
```

Live authentication acceptance requires the owner's existing tenant configuration and a fresh interactive sign-in. Do not copy real caches, tokens or tenant snapshots into fixtures. Normal MSAL token exchange and local encrypted cache persistence are distinct from Microsoft Graph configuration mutations; Graph validation remains GET-only.
