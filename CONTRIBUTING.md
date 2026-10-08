# Contributing

Thanks for considering a contribution. This document covers how to get the
project running, the rules a change has to respect, and what happens to your
pull request.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## The rules that are not negotiable

This product reads other people's identity infrastructure. Seven rules exist to
keep that trustworthy, and a pull request that breaks one will not be merged
regardless of how good the rest of it is.

1. **The product is read-only.** No code path may mutate Microsoft Entra. The
   Graph transport is GET-only and stays that way.
2. **Never request more Graph permission than a feature requires.** Adding a
   scope requires a written justification in the pull request.
3. **Configured access, observed activity, inferred possibility, and missing
   evidence are four different things** and must remain visually and technically
   distinct. Never imply a permission is *used* merely because it is *configured*.
4. **Every relationship must be explainable** with object IDs, relationship type,
   and the source Graph endpoint.
5. **No secret or tenant data in Git.** Not client secrets, not access tokens,
   not certificates, not exported tenant data, not real tenant or client GUIDs.
6. **Tenant boundaries are absolute.** A scan result belongs to exactly one
   tenant, and every database read is tenant-keyed.
7. **Follow [DESIGN.md](DESIGN.md)** for tokens and component rules.

If you believe a rule is wrong, open a discussion issue about the rule itself
rather than a pull request that quietly crosses it.

## Getting set up

Requirements: Node.js 22 or later, pnpm 11.23.0, and Docker Desktop only if you
want to run the live stack.

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:3000/overview`. This is **fixture mode**: a synthetic
tenant, no Microsoft account, no network calls to Graph. Nearly all development
can and should happen here.

Open **Guide** for the product boundary and a question-based walkthrough. Keep [README](README.md), [USER_GUIDE](docs/USER_GUIDE.md), in-app labels and [PRODUCT_SPEC](docs/PRODUCT_SPEC.md) aligned when a user-facing workflow changes. Public screenshots must use the bundled synthetic fixture; verify the sample-data banner before capturing them.

### Connecting your own tenant

Only needed when changing scan or authentication behaviour. Never point the
product at a tenant you do not administer.

1. In the Microsoft Entra admin center, create an app registration named
   whatever you like, restricted to **accounts in this organizational directory
   only** (single tenant).
2. Add a **Web** redirect URI of `http://127.0.0.1:3000/api/auth/callback`, and
   `http://127.0.0.1:3200/api/auth/callback` as well if you plan to run the
   container stack.
3. Under **API permissions**, add the **delegated** Microsoft Graph permissions
   `Application.Read.All` and `Directory.Read.All`, then grant administrator
   consent. Add nothing else; optional scopes are consented separately and only
   when a feature needs them.
4. Create a client secret and store it outside the repository.
5. Copy `apps/web/.env.example` to `.env.local` at the repository root and fill
   in your tenant ID, client ID, client secret, and a data-encryption key
   generated with `openssl rand -base64 32`. `.env.local` is git-ignored.
6. Run `pnpm dev:live` and open `http://127.0.0.1:3200/settings`.

Alternatively, set `ENTRA_KEY_VAULT_NAME` to an Azure Key Vault you control and
`pnpm dev:live` will read the three secrets from it.

## Before you open a pull request

```bash
pnpm run verify
```

That single command validates Compose isolation, lints, type-checks, runs the
domain, custom engine, offline CLI, scanner, storage, authentication, accessibility, and browser tests, and
builds every route. CI runs this with an isolated PostgreSQL service. A separate quality job runs
coverage, maintainability and fresh mutation checks.

Run the same quality checks when changing logic:

```bash
pnpm quality:crap      # coverage plus a Change Risk Anti-Patterns report
pnpm test:mutation     # StrykerJS mutation testing, per package
```

Each package enforces a mutation score of at least **95%**. CI tests every mutant
from scratch; locally use `pnpm test:mutation --force --concurrency 2` to do the same.
The maintainability report fails when a function exceeds CRAP 30. New logic is expected to arrive with tests that would fail if the logic
were wrong — not tests that merely execute it. Shared fixtures live in each
package's `test-support.ts`; prefer extending those over inventing new ones.

Mutation survivors must be reviewed for an observable behavioral difference. Add a
regression that fails for the mutation, or simplify redundant logic. Narrow Stryker
exclusions are reserved for proven equivalent mutations with an explanation beside
the code. Do not lower thresholds or ignore whole modules to pass the gate. Run
ordinary tests and mutation checks sequentially; package test discovery also excludes
sandbox copies left behind by interrupted mutation runs.

## Pull requests

- **Branch from `main`** and keep one logical change per pull request.
- **Write [Conventional Commits](https://www.conventionalcommits.org/)**:
  `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`. The subject line
  should say what changed for the user, not what you edited.
- **Explain the why.** The pull request description should state the problem,
  not just restate the diff. If the change touches Graph scopes, evidence
  classification, or the security model, say so explicitly.
- **Include evidence** for user-visible changes: a screenshot, or the exact
  command whose output changed.
- **Sign off your commits.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): add
  `Signed-off-by: Your Name <your@email>` with `git commit -s`. It certifies you
  wrote the contribution or have the right to submit it. There is no CLA and no
  copyright assignment; your contribution is licensed under
  [Apache-2.0](LICENSE) like the rest of the project.

Expect a first response within a week. Review focuses on the seven rules above,
on test strength, and on whether the change keeps the product explainable to a
non-expert. Small, well-tested pull requests are merged much faster than large
ones.

## Good first contributions

Issues labelled `good first issue` are scoped to be completable without deep
knowledge of the Graph model. Documentation corrections, accessibility fixes,
and test strengthening are always welcome and do not need prior discussion.

For anything larger — a new finding type, a new export format, a new Graph
endpoint — please open an issue first so the design can be agreed before you
spend time on it.

## Reporting security defects

Do not use the public issue tracker. Follow [SECURITY.md](SECURITY.md).

## Repository layout

| Path | What lives there |
|---|---|
| `apps/web` | Next.js application, API routes, server-side auth and config |
| `packages/domain` | Tenant intelligence: findings, attack paths, comparisons |
| `packages/engine` | Versioned evidence proofs, typed semantics, bounded planning and offline replay |
| `packages/graph` | Microsoft Graph client, scanner, and normalization |
| `packages/backend` | Storage, encryption, sessions, durable job queue |
| `docs/` | Product specification, architecture, security model, API contract |
| `security/` | Threat models, ASVS mapping, and scanner configuration |
| `scripts/` | Local operations and quality tooling |

## Adding investigation rules

Use the [synthetic rule laboratory](docs/RULE_LAB.md) to scaffold and replay a declarative regression case. New compiled rules need positive, nearby negative, coverage and version-change tests. The [investigation guide](docs/INVESTIGATIONS.md) describes the database and browser checks; passing mocks alone is not evidence of PostgreSQL concurrency correctness.

## Changing engine semantics

Read [CUSTOM_ENGINE.md](docs/CUSTOM_ENGINE.md) for supported rules, limits and the offline format. Add independent expected outcomes for positive, nearby negative, unknown and conflicting evidence. Use exhaustive small cases for planning and sampled time intervals for continuity. Review public-format snapshots before updating them; version provenance and replay changes deliberately. `pnpm test:engine-cli` checks real process exit codes and filesystem behavior using temporary synthetic files.
