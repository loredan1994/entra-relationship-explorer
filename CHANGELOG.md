# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until `1.0.0` the public surface — the HTTP API in [docs/openapi.yaml](docs/openapi.yaml),
the export formats, and the database schema — may change in a minor release.
Breaking changes are always called out under **Changed** with a migration note.

## [Unreleased]

### Added

- Apache-2.0 license, contribution guide, security policy, and code of conduct.
- CodeQL analysis, dependency review, and Dependabot in CI.
- An explicit save state in the threat workspace decision record, so a rejected
  or failed review write can no longer look like a saved decision.

### Changed

- Tenant and client identifiers are now supplied through the environment rather
  than committed as defaults in `compose.yaml`.
- `pnpm dev:live` reads secrets from a Key Vault named by `ENTRA_KEY_VAULT_NAME`,
  or from a git-ignored `.env.local`, instead of a hard-coded vault.

## Prior work

Before this changelog began, the project reached a code-complete read-only
product: fixture-driven exploration, single-tenant Microsoft sign-in, GET-only
paginated Graph reads, PostgreSQL-backed encrypted sessions and snapshots, a
durable resumable scan queue, throttling-aware progress and cancellation,
snapshot comparison, attack-path discovery, editable review copies of attack
flows, and CSV, HTML report, and MITRE Attack Flow exports.

[Unreleased]: https://github.com/loredan1994/entra-relationship-explorer/commits/main
