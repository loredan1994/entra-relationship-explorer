# Phase 1 security validation

Validation date: 2026-08-26

Scope: the local, delegated administrator implementation. This is a code-path validation, not evidence that a real tenant has granted consent or completed a scan.

| Claim | Result | Evidence |
|---|---|---|
| Only the approved read scopes can be requested | Pass | Configuration constructs scopes from a fixed allowlist; tests accept `Application.Read.All` and `Directory.Read.All` and reject write or activity scopes. |
| Microsoft Graph transport cannot mutate the tenant | Pass | The transport exposes only paginated GET, fixes the Graph v1.0 origin, rejects hostile next links, caps traversal, and has no POST, PUT, PATCH, or DELETE method. |
| Tokens and credential secrets remain outside snapshots and browser responses | Pass | Tokens live only in the server session and Graph client. Tests prove bearer tokens are absent from errors and secret-like credential fields are dropped while non-secret credential metadata remains. |
| Stored data cannot cross tenant boundaries and is encrypted at rest | Pass | Normalization asserts one tenant per snapshot; session, job, export, and storage reads match the configured tenant; AES-256-GCM binds ciphertext to tenant metadata. Tests cover tenant separation and unreadable snapshot names in the SQLite file. |
| Browser and authentication controls resist request forgery and script injection | Pass | Authorization uses PKCE plus one-time constant-time state validation. Cookies are HttpOnly and SameSite. Mutation-like local actions require exact same origin. A per-request CSP nonce keeps the Next.js UI interactive without allowing arbitrary inline scripts. |

## Residual limits

- The client-secret authentication mode is restricted to local development and is rejected in production.
- Sessions and scan jobs are process-local; shared or scheduled hosting requires a separately reviewed durable session/job design.
- The SQLite database intentionally leaves minimal indexing metadata (tenant ID, snapshot ID, scan time, completion status) in plaintext while encrypting the snapshot payload.
- The owner approved the local app registration and administrator consent on 2026-08-26. A GET-only representative scan of the active tenant completed successfully through the project scanner; interactive browser sign-in remains the final UI-session acceptance step.
- Durable access auditing is required before any shared deployment.
