import { assertTenantBoundary } from "./queries";
import { endpointWasCollected } from "./coverage";
import type { DirectoryNode, RequestedPermission, RelationshipEdge, TenantSnapshot } from "./types";

export interface PermissionLedgerRow {
  id: string; applicationId: string | null; identityId: string | null; identity: string;
  resourceId: string | null; resource: string; permissionId: string | null; permission: string;
  kind: "application" | "delegated";
  status: "requested-and-granted" | "requested-not-granted" | "granted-not-requested" | "unknown";
  audience: string; principalId: string | null; edgeId: string | null; sourceEndpoints: string[]; reason: string;
}

/** Reconcile configured declarations and consent; neither is evidence of use. */
export function permissionLedger(snapshot: TenantSnapshot): PermissionLedgerRow[] {
  assertTenantBoundary(snapshot);
  const nodes = new Map(snapshot.nodes.map(n => [n.id, n]));
  const registrations = snapshot.nodes.filter(n => n.kind === "application");
  const grants = snapshot.edges.filter(e => e.type === "CAN_CALL_AS_APP" || e.type === "CAN_CALL_DELEGATED");
  const rows: PermissionLedgerRow[] = [];
  const coveredRequests = new Set<string>();
  for (const grant of grants) rows.push(...grantRows(grant, nodes, registrations, coveredRequests));
  for (const app of registrations) for (const request of app.requestedPermissions ?? []) {
    if (!coveredRequests.has(`${app.id}:${request.resourceAppId}:${request.kind}:${request.permissionId}`)) rows.push(requestRow(snapshot, app, request));
  }
  return rows.sort((a,b) => `${a.identity}:${a.resource}:${a.permission}:${a.id}`.localeCompare(`${b.identity}:${b.resource}:${b.permission}:${b.id}`));
}

function grantRows(grant: RelationshipEdge, nodes: Map<string, DirectoryNode>, registrations: DirectoryNode[], coveredRequests: Set<string>): PermissionLedgerRow[] {
  const rows: PermissionLedgerRow[] = [];
  const identity = nodes.get(grant.sourceId)!;
  const resource = nodes.get(grant.targetId)!;
  const application = registrations.find(n => Boolean(n.appId) && n.appId === identity.appId);
  const kind = grant.type === "CAN_CALL_AS_APP" ? "application" : "delegated";
  const definitions = resource.permissionDefinitions?.filter(d => d.kind === kind);
  const permissionKeys = kind === "application" && grant.permissionIds?.length ? grant.permissionIds : grant.permissions;
  for (const key of permissionKeys) {
    const definition = definitions?.find(d => d.id === key || d.value === key);
    const permissionId = definition?.id ?? (kind === "application" && grant.permissionIds?.includes(key) ? key : null);
    const requested = isRequested(application, resource.appId, permissionId, kind);
    if (requested) coveredRequests.add(`${application!.id}:${resource.appId}:${kind}:${permissionId}`);
    const known = requested || (application?.requestedPermissions !== undefined && permissionId && resource.appId);
    const status = grant.evidence.completeness !== "complete" || !known ? "unknown" : requested ? "requested-and-granted" : "granted-not-requested";
    rows.push({ id: `${grant.id}:${key}`, applicationId: application?.id ?? null, identityId: identity.id, identity: identity.label, resourceId: resource.id, resource: resource.label, permissionId, permission: definition?.value ?? key, kind, status, ...audience(grant), edgeId: grant.id, sourceEndpoints: grantSourceEndpoints(grant, application, resource), reason: status === "unknown" ? "The local manifest, permission definition or grant evidence is incomplete. External app manifests are not available in this tenant." : requested ? "The declaration and a configured grant match. This does not prove permission use." : "Configured grant is absent from the collected local manifest; review intent before planning removal." });
  }
  return rows;
}

function requestRow(snapshot: TenantSnapshot, app: DirectoryNode, request: RequestedPermission): PermissionLedgerRow {
  const identities = snapshot.nodes.filter(n => ["servicePrincipal", "managedIdentity"].includes(n.kind) && Boolean(n.appId) && n.appId === app.appId);
  const resource = snapshot.nodes.find(n => ["servicePrincipal", "managedIdentity"].includes(n.kind) && n.appId === request.resourceAppId);
  const definition = resource?.permissionDefinitions?.find(d => d.id === request.permissionId && d.kind === request.kind);
  const grantEndpoint = request.kind === "application" ? (resource ? `/servicePrincipals/${resource.id}/appRoleAssignedTo` : null) : "/oauth2PermissionGrants";
  const collectedGrantEndpoint = grantEndpoint && endpointWasCollected(snapshot, grantEndpoint)
    ? snapshot.completion.collectedEndpoints.find(endpoint => endpoint.split("?")[0] === grantEndpoint) : undefined;
  const covered = identities.length > 0 && resource && collectedGrantEndpoint;
  return { id: `request:${app.id}:${request.resourceAppId}:${request.kind}:${request.permissionId}`, applicationId: app.id, identityId: identities[0]?.id ?? null, identity: app.label, resourceId: resource?.id ?? null, resource: resource?.label ?? request.resourceAppId, permissionId: request.permissionId, permission: definition?.value ?? request.permissionId, kind: request.kind, status: covered && definition ? "requested-not-granted" : "unknown", audience: "No matched grant", principalId: null, edgeId: null, sourceEndpoints: [app.sourceEndpoint ?? "/applications", ...(resource?.sourceEndpoint ? [resource.sourceEndpoint] : []), ...(collectedGrantEndpoint ? [collectedGrantEndpoint] : [])], reason: covered && definition ? "Declared in the manifest, but no matching grant was collected in the covered endpoint." : "A missing identity, resource definition or grant collection prevents reconciliation." };
}

function audience(edge: RelationshipEdge): Pick<PermissionLedgerRow, "audience" | "principalId"> {
  if (edge.type === "CAN_CALL_AS_APP") return { audience: "Application identity", principalId: null };
  return { audience: edge.consent?.audience === "all-users" ? "All users" : edge.consent?.audience === "single-user" ? "One user" : "Unknown consent audience", principalId: edge.consent?.principalId ?? null };
}

function grantSourceEndpoints(grant: RelationshipEdge, application: DirectoryNode | undefined, resource: DirectoryNode): string[] {
  return [...new Set([grant.evidence.sourceEndpoint, ...(application?.sourceEndpoint ? [application.sourceEndpoint] : []), ...(resource.sourceEndpoint ? [resource.sourceEndpoint] : [])])];
}

function isRequested(application: DirectoryNode | undefined, resourceAppId: string | undefined, permissionId: string | null, kind: PermissionLedgerRow["kind"]): boolean {
  return Boolean(permissionId && resourceAppId && application?.requestedPermissions?.some(r => r.resourceAppId === resourceAppId && r.permissionId === permissionId && r.kind === kind));
}
