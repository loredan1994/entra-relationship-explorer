# Architecture and graph model

## Recommended shape

A TypeScript monorepo with a Next.js web application, a background scanner, and a small relational store. The graph is a presentation/query model; Microsoft Graph remains the authority.

- **Web:** Next.js, React, accessible HTML controls, and Cytoscape.js for headless relationship layout. The graph always has a table equivalent.
- **API/scanner:** TypeScript, a narrow GET-only Microsoft Graph transport, a thin versioned API, and a separate restart-safe worker.
- **Storage:** PostgreSQL stores encrypted OAuth sessions and snapshot payloads plus a durable scan queue and access events. Every retrieval is tenant-keyed.
- **Authentication:** Microsoft identity platform authorization-code flow with PKCE.
- **Local runtime:** Docker Compose runs PostgreSQL, an idempotent migration job, the web service, and one worker. The application uses a pinned non-root distroless Node 24 Debian 13 runtime with production-only dependencies and Next.js standalone output. Only the web and database development ports bind to loopback.
- **Future deployment:** Azure App Service or Container Apps; managed identity or certificate for a scheduled scanner requires a separate approval.

## Backend modules and seams

- The `Backend` interface owns auth flows, encrypted sessions, scan jobs, snapshots, and access events.
- `PostgresBackend` is the real local implementation. Parameterized queries and explicit tenant IDs are mandatory.
- `MemoryBackend` is the deterministic contract-test implementation; it is not used for live data.
- Workers claim queued jobs with `FOR UPDATE SKIP LOCKED`. A ten-minute stale lease is recovered after worker interruption.
- Saving a snapshot and marking its job complete occurs in one database transaction.

## Identity objects

- `Application`: app registration; the reusable blueprint. Key join field: `appId`.
- `ServicePrincipal`: enterprise application; the tenant-local identity. It has its own `id` and shares the application's `appId`.
- `AppRole`: application permission exposed by a resource application.
- `AppRoleAssignment`: grants a principal an app role on a resource service principal.
- `OAuth2PermissionGrant`: delegated permission consent involving a user or all users.
- `DirectoryObject`: user, group, or service principal assigned to an enterprise app.

## Normalized edges

| From | Edge | To | Microsoft source |
|---|---|---|---|
| Application | `INSTANTIATES_AS` | ServicePrincipal | matching `appId` |
| ServicePrincipal | `CAN_CALL_AS_APP` | ServicePrincipal | app-role assignment |
| ServicePrincipal | `CAN_CALL_DELEGATED` | ServicePrincipal | OAuth2 permission grant |
| User/Group | `ASSIGNED_TO` | ServicePrincipal | app-role assignment |
| User/ServicePrincipal | `MEMBER_OF` | Group | direct group members |
| Principal | `ACTIVE_IN_ROLE` / `ELIGIBLE_FOR_ROLE` | DirectoryRole | role management schedules, optional |
| User | `OWNS` | Application/ServicePrincipal | owners relationship |
| Object | `GOVERNED_BY` | Policy | Conditional Access, optional |
| ExternalTenant | `CROSS_TENANT_ACCESS` | Policy | partner cross-tenant settings, optional |
| ServicePrincipal | `OBSERVED_CALL` | Resource | sign-in logs, optional |

## Microsoft Graph reads

The current implementation reads:

- `/applications`
- `/servicePrincipals`
- `/users`
- `/groups`
- `/groups/{id}/members`
- `/servicePrincipals/{id}/appRoleAssignedTo`
- `/oauth2PermissionGrants`
- `/applications/{id}/owners`
- `/servicePrincipals/{id}/owners`
- optional `/roleManagement/directory/roleDefinitions`, `/roleAssignments`, and `/roleEligibilitySchedules`
- optional `/identity/conditionalAccess/policies`
- core `/devices`, `/directory/administrativeUnits`, administrative-unit members, and federated identity credentials
- optional `/policies/authorizationPolicy` and `/policies/permissionGrantPolicies` with include/exclude conditions
- optional `/policies/crossTenantAccessPolicy/partners`
- optional `/auditLogs/signIns` with a 30-day filter

Every request, including a continuation link, is HTTPS GET-only to the exact `graph.microsoft.com` origin and `/v1.0/` path. The transport honors server throttling guidance with bounded retries and also caps pages, items, request time, and scanner concurrency. Failed endpoints are recorded as an explicit partial result. Do not infer a complete edge when source objects are incomplete; mark it unresolved.

The default consent excludes optional evidence. `RoleManagement.Read.Directory`, `Policy.Read.All`, `Policy.Read.PermissionGrant`, and `AuditLog.Read.All` are separately allowlisted and collected only when explicitly configured. Activity reads include a server-enforced 30-day timestamp filter; authorization and cross-tenant partner settings use `Policy.Read.All`, while consent-policy detail uses `Policy.Read.PermissionGrant`.

## API shape

The stable local surface is `/api/v1`; the Microsoft callback remains `/api/auth/callback`. See `docs/openapi.yaml`.

The internal API should return stable, UI-oriented records:

```json
{
  "edgeId": "assignment-guid",
  "type": "CAN_CALL_AS_APP",
  "source": { "id": "client-sp-id", "label": "clean-project-orchestrator" },
  "target": { "id": "resource-sp-id", "label": "clean-project-api" },
  "permissions": ["Api.Read", "Api.Write"],
  "evidence": {
    "configured": true,
    "observed": null,
    "scannedAt": "2026-08-26T10:00:00Z"
  }
}
```

## Scale strategy

Do not render an entire large tenant at once. Start with an overview, cluster by publisher/project, fetch one-hop neighbors on selection, cap visible nodes, and always offer the equivalent table.

## IAM intelligence model

The domain package discovers bounded directed paths over evidence-bearing normalized relationships. Each step retains its object IDs, relationship type, Graph endpoint, collection time, and completeness. Findings classify conclusions as configured access, observed activity, inferred possibility, or missing evidence. Dormancy is evaluated only when the optional activity endpoint was actually collected and is always phrased as a bounded-window inference.

MITRE ATT&CK® technique identifiers are classification references, not embedded product logic or an endorsement. Attack paths include prerequisites, confidence, mitigations, and residual uncertainty. Standards-oriented exports use STIX 2.1 with the MITRE Attack Flow 2.0 extension. Review decisions and editable analyst flow copies are encrypted and shared within the authenticated tenant and snapshot boundary.

The worker checkpoints sanitized collection state after each completed stage. A recovered job resumes at the next stage rather than re-reading completed stages. Checkpoints use tenant-bound authenticated encryption and are deleted after completion or cancellation.

The Compose bridge is private. Web and PostgreSQL publish loopback ports only; worker and migration have no host port. All services use `no-new-privileges`; the application runtime is non-root. Sensitive PostgreSQL payloads use tenant-bound authenticated encryption, while scheduling/index metadata remains plaintext by design.
