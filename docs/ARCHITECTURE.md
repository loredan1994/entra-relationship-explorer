# Architecture and graph model

## Recommended shape

A TypeScript monorepo with a Next.js web application, a background scanner, and a small relational store. The graph is a presentation/query model; Microsoft Graph remains the authority.

- **Web:** Next.js, React, accessible component primitives, Cytoscape.js or React Flow.
- **API/scanner:** TypeScript, Microsoft Graph SDK, job queue abstraction.
- **Storage:** SQLite for local development; PostgreSQL for shared deployments.
- **Authentication:** Microsoft identity platform authorization-code flow with PKCE.
- **Deployment:** Azure App Service or Container Apps; managed identity or certificate for a scheduled scanner.

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
| User | `OWNS` | Application/ServicePrincipal | owners relationship |
| ServicePrincipal | `OBSERVED_CALL` | Resource | sign-in logs, optional |

## Microsoft Graph reads

- `/applications`
- `/servicePrincipals`
- `/servicePrincipals/{id}/appRoleAssignedTo`
- `/servicePrincipals/{id}/appRoleAssignments`
- `/oauth2PermissionGrants`
- owner and assignment navigations
- `/auditLogs/signIns` only when the optional activity feature is enabled

Paginate every collection, apply throttling backoff, record scan completeness, and preserve raw source IDs. Do not infer an edge when the source objects are incomplete; mark it unresolved.

## API shape

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

