# Phase 1 read-only tenant scan

## Outcome

Phase 1 adds an opt-in, local administrator workflow that signs in to one explicitly configured Microsoft Entra tenant, reads the approved Microsoft Graph inventory, normalizes explainable relationships, and stores an encrypted tenant snapshot. The application still has no Entra mutation path.

The repository is code-complete for this workflow. On 2026-08-26, the owner explicitly approved creation of the single-tenant `Entra Relationship Explorer Local` registration in tenant `11111111-1111-4111-8111-111111111111`. Its client ID is `11111111-1111-4111-8111-111111111112`; its callbacks are the local-only `http://127.0.0.1:3000/api/auth/callback` and `http://127.0.0.1:3200/api/auth/callback`; and administrator consent is effective only for delegated `Application.Read.All Directory.Read.All`. Credentials are stored in `your-key-vault`; no value is committed. Nothing has been deployed.

## Safety boundary

- Live mode defaults to off and returns no sign-in or scan action until `ENTRA_ENABLE_LIVE=true` is set locally.
- A concrete tenant UUID is mandatory; `common` and `organizations` are rejected.
- The allowed Graph scopes are fixed to delegated `Application.Read.All` and `Directory.Read.All`. Unknown and write-capable scopes are rejected.
- Authentication uses authorization code with PKCE, one-time state, an exact callback path, short HttpOnly cookies, and server-side token handling.
- The Graph transport exposes GET only, accepts pagination links only under `https://graph.microsoft.com/v1.0/`, applies bounded retry/backoff, and caps pages and records.
- Access tokens, refresh tokens, credential secrets, certificate material, and raw response bodies are not written to snapshots or returned to browser code.
- Tenant snapshots are encrypted with AES-256-GCM. Associated data binds ciphertext to snapshot ID, tenant ID, and scan time. Every database read is tenant-keyed.
- The user interface and CSV export describe configured access only. Sign-in activity and `AuditLog.Read.All` remain absent.

## Inventory collected

- Applications (app registrations), including credential dates and identifiers but never secret values.
- Service principals (enterprise applications).
- App-role assignments.
- OAuth2 delegated permission grants.
- Application and service-principal owners.

Every normalized connection includes the source and target object IDs, relationship type, source endpoint, source record IDs, scan time, and completeness state. Unresolved references are kept visible instead of being silently inferred.

## Local configuration

Copy `apps/web/.env.example` to a local ignored environment file and supply:

- one concrete tenant ID;
- the client ID of an app registration configured with the exact local callback;
- a local-development client secret;
- a random 32-byte base64 snapshot-encryption key.

The app registration and administrator consent must be created manually and reviewed before enabling live mode. The implementation refuses this client-secret configuration when `NODE_ENV=production`; a future approved hosted phase must use a certificate or managed identity.

The permissions reflect current Microsoft Graph documentation for [listing applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0), [listing service principals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0), [app-role assignments](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0), and [OAuth2 permission grants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0). Revalidate them before any real tenant consent because Microsoft can change permission requirements.

## Operator flow

1. Run `pnpm dev:live` and open Settings.
2. Sign in to the one configured tenant.
3. Review the two delegated read permissions in the consent experience.
4. Start a read-only scan and watch named stages and record counts.
5. Review completion, skipped endpoints, and any partial-result warnings.
6. Explore the normalized snapshot or explicitly export the relationship table.

Snapshots older than 30 days are pruned after a successful scan. The current implementation retains the latest encrypted snapshots locally; it does not upload them or schedule scans.

## Validation still requiring explicit approval

- Register or configure the Microsoft identity application in a real tenant.
- Grant administrator consent to the two delegated read scopes.
- Run a representative tenant scan and compare sampled relationships with the Entra admin center.
- Choose a production hosting and non-secret authentication model.

None of those external actions were performed during implementation.
