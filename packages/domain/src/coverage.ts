import type { CollectorCoverage, TenantSnapshot } from "./types";

export const COLLECTORS = [
  { id: "applications", label: "Application blueprints", scope: "Application.Read.All", role: "Directory reader access", prefixes: ["/applications?"] },
  { id: "servicePrincipals", label: "Tenant identities", scope: "Application.Read.All", role: "Directory reader access", prefixes: ["/servicePrincipals?"] },
  { id: "federatedIdentityCredentials", label: "Workload federation", scope: "Application.Read.All", role: "Application reader access", prefixes: ["federatedIdentityCredentials"] },
  { id: "usersAndGroups", label: "People and groups", scope: "Directory.Read.All", role: "Directory reader access", prefixes: ["/users", "/groups?"] },
  { id: "groupMemberships", label: "Group membership", scope: "Directory.Read.All", role: "Hidden memberships can require additional authorization", prefixes: ["/members?"] },
  { id: "devices", label: "Devices", scope: "Directory.Read.All", role: "Directory reader access", prefixes: ["/devices"] },
  { id: "administrativeUnits", label: "Administrative units", scope: "Directory.Read.All", role: "Directory reader access", prefixes: ["/directory/administrativeUnits"] },
  { id: "delegatedPermissionGrants", label: "Delegated consent", scope: "Directory.Read.All", role: "Directory reader access", prefixes: ["/oauth2PermissionGrants"] },
  { id: "appRoleAssignments", label: "Application grants", scope: "Application.Read.All", role: "Application reader access", prefixes: ["/appRoleAssignedTo"] },
  { id: "owners", label: "Accountable owners", scope: "Application.Read.All", role: "Application reader access", prefixes: ["/owners"] },
  { id: "roles", label: "Active and eligible roles", scope: "RoleManagement.Read.Directory", role: "Supported Entra role, such as Global Reader", prefixes: ["/roleManagement/directory/"] },
  { id: "conditionalAccess", label: "Conditional Access references", scope: "Policy.Read.All", role: "Supported role, such as Security Reader", prefixes: ["/identity/conditionalAccess/"] },
  { id: "authorizationPolicy", label: "Authorization policy", scope: "Policy.Read.All", role: "Supported policy reader role", prefixes: ["/policies/authorizationPolicy"] },
  { id: "permissionGrantPolicies", label: "Consent conditions", scope: "Policy.Read.PermissionGrant", role: "Supported policy reader role", prefixes: ["/policies/permissionGrantPolicies"] },
  { id: "crossTenantAccess", label: "Partner trust", scope: "Policy.Read.All", role: "Supported policy reader role", prefixes: ["/policies/crossTenantAccessPolicy/"] },
  { id: "activity", label: "User sign-ins", scope: "AuditLog.Read.All", role: "Supported role, such as Reports Reader; available retention varies", prefixes: ["/auditLogs/signIns"] },
  { id: "directoryAudits", label: "Directory change events", scope: "Directory.Read.All", role: "Reports Reader, Security Reader or supported custom role; explicit collection opt-in", prefixes: ["/auditLogs/directoryAudits"] },
] as const;

/** Historical snapshots without collector metadata cannot establish collection completeness. */
export function coverageMatrix(snapshot: TenantSnapshot): Array<CollectorCoverage & { label: string; role: string }> {
  return COLLECTORS.map(definition => {
    const recorded = snapshot.completion.collectors?.find(c => c.id === definition.id);
    return { ...(recorded ?? { id: definition.id, state: "unknown" as const, reason: "This snapshot predates detailed collector coverage. Run another read-only scan to establish it.", collectedAt: null, endpoints: [], failedEndpoints: [], itemCount: 0, scope: definition.scope }), label: definition.label, role: definition.role };
  });
}

export function endpointWasCollected(snapshot: TenantSnapshot, endpoint: string): boolean {
  const path = endpoint.split("?")[0];
  const expansion = new URLSearchParams(endpoint.split("?")[1]).get("$expand");
  const matches = (candidate: string) => candidate.split("?")[0] === path && (!expansion || new URLSearchParams(candidate.split("?")[1]).get("$expand") === expansion);
  return !snapshot.completion.skippedEndpoints.some(matches) && snapshot.completion.collectedEndpoints.some(matches);
}
