# Security policy

Entra Relationship Explorer reads a Microsoft Entra tenant and stores an encrypted
snapshot of it. A defect here can expose an organization's identity topology, so
security reports are treated as the highest-priority class of issue.

## Reporting a vulnerability

**Do not open a public issue for a security defect.**

Report privately through [GitHub's private vulnerability reporting](https://github.com/loredan1994/entra-relationship-explorer/security/advisories/new).
If that is unavailable to you, email loredan6@live.com with `SECURITY` in the
subject line.

Please include:

- The affected version or commit.
- What an attacker gains, and what access they need to start.
- Reproduction steps, ideally against fixture mode so no real tenant is involved.
- Any log or export excerpt, **with tenant identifiers redacted**.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or documented mitigation for high and critical findings | 90 days |

This is a volunteer-maintained project and these are targets, not contractual
commitments. You will be told promptly if a timeline is going to slip.

Coordinated disclosure is expected: please give the project a reasonable window
to ship a fix before publishing. Reporters are credited in the advisory and the
changelog unless they ask not to be. There is no bug bounty.

## Supported versions

The project has not yet cut a stable release. Until `1.0.0`, only the `main`
branch receives security fixes. Once releases begin, this table will name the
supported minor versions.

## Scope

### In scope

- Anything that discloses tenant data across a tenant boundary, or to an
  unauthenticated caller.
- Weaknesses in snapshot encryption, session handling, or the OAuth flow —
  authorization-code/PKCE handling, state validation, redirect URI enforcement,
  token storage, or cookie attributes.
- Any path that causes the product to issue a non-GET Microsoft Graph request,
  or to request a Graph scope beyond its configured set. The product is
  read-only by design; a write path is a vulnerability, not a feature.
- Injection, SSRF, or deserialization defects in scan, export, or comparison
  code, including via attacker-controlled directory object names.
- Container or Compose configuration that exposes the database, the worker, or
  the application beyond loopback.
- Secrets or tenant data reaching logs, exports, error responses, or browser
  code.

### Out of scope

- Findings that require an attacker who already has directory-administrator
  privileges in the tenant being scanned.
- Vulnerabilities in Microsoft Entra or Microsoft Graph themselves. Report those
  to [MSRC](https://msrc.microsoft.com/report).
- Missing hardening on a deployment you configured contrary to the documented
  local-only model — for example, binding the application to a public interface
  or enabling `ENTRA_ALLOW_LOCAL_CLIENT_SECRET` on a shared host.
- Reports produced solely by an automated scanner, with no demonstrated impact.
- Denial of service through unrealistic request volume against your own instance.

## The product's security model

These properties are enforced in code and covered by tests. A change that breaks
one is a security regression regardless of intent.

- **Read-only transport.** The Graph client exposes GET only. Pagination links
  are accepted only under `https://graph.microsoft.com/v1.0/`.
- **Least privilege.** The default delegated scopes are `Application.Read.All`
  and `Directory.Read.All`. Optional scopes are restricted to a fixed read-only
  set; unknown and write-capable scopes are rejected.
- **A concrete tenant.** `common` and `organizations` are rejected; a tenant
  GUID is mandatory, and every database read is tenant-keyed.
- **Encryption at rest.** Snapshots are AES-256-GCM encrypted, with associated
  data binding ciphertext to snapshot ID, tenant ID, and scan time.
- **No credential material in results.** Access tokens, refresh tokens, client
  secrets, certificate material, and raw response bodies are never written to
  snapshots or returned to browser code.
- **Local by default.** Live mode is off until `ENTRA_ENABLE_LIVE=true` is set,
  and the documented deployment binds only to loopback interfaces.
- **Nothing leaves your machine.** The product sends tenant data to no
  third-party service. It talks to Microsoft Graph and to your own PostgreSQL.

[docs/SECURITY_PRIVACY.md](docs/SECURITY_PRIVACY.md) documents the full model,
and `pnpm run verify` includes the Compose isolation check that enforces the
network boundary.

## Operator responsibilities

The product cannot protect you from your own deployment. When running it against
a real tenant:

- Create a dedicated single-tenant app registration; do not reuse one that has
  write permissions.
- Keep redirect URIs on loopback addresses.
- Hold the client secret, the data-encryption key, and the database password
  outside the repository — a secret manager, or a git-ignored `.env.local`.
- Treat snapshots and exports as sensitive: they describe your privilege
  topology and are exactly what an attacker would want to read.
