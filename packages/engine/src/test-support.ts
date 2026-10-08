import { COLLECTORS, type ConditionalAccessDefinition, type DirectoryNode, type NodeKind, type RelationshipEdge, type RelationshipType, type TenantSnapshot } from "@entra-explorer/domain";
import type { AuthorizationQuery } from "./types";

export const TIME = "2026-10-08T12:00:00.000Z";
export function node(id: string, kind: NodeKind = "servicePrincipal"): DirectoryNode {
  return { id, tenantId: "synthetic-tenant", kind, label: id, description: "Synthetic engine case", ownerIds: [], sourceEndpoint: "/servicePrincipals", risk: { level: "low", reason: "Synthetic" } };
}
export function edge(id: string, sourceId: string, targetId: string, type: RelationshipType = "CAN_CALL_AS_APP"): RelationshipEdge {
  return { id, sourceId, targetId, type, tenantId: "synthetic-tenant", plainLabel: type, permissions: ["Read"], permissionIds: ["read-id"], evidence: { configured: true, observed: null, scannedAt: TIME,
    sourceEndpoint: `/servicePrincipals/${targetId}/appRoleAssignedTo`, sourceRecordIds: [id], sourceObjectId: sourceId, targetObjectId: targetId, completeness: "complete" } };
}
export function snapshot(edges: RelationshipEdge[] = [edge("grant", "client", "resource")]): TenantSnapshot {
  return { id: "synthetic-snapshot", tenant: { tenantId: "synthetic-tenant", tenantLabel: "Synthetic engine" }, scannedAt: TIME, mode: "fixture",
    nodes: [node("client"), node("resource"), node("blueprint", "application"), node("person", "user"), node("other", "user"), node("team", "group"), node("nested", "group"), node("role", "directoryRole"), node("trust", "federatedCredential")], edges,
    completion: { status: "complete", collectedEndpoints: [], skippedEndpoints: [], errors: [], collectors: COLLECTORS.map(c => ({ id: c.id, state: "complete", reason: "Synthetic complete collector", collectedAt: TIME, endpoints: [`/${c.id}`], failedEndpoints: [], itemCount: edges.length, scope: c.scope })) } };
}
export const query: AuthorizationQuery = { tenantId: "synthetic-tenant", kind: "application-permission", principalId: "client", resourceId: "resource", permissionId: "read-id" };
export function policy(overrides: Partial<ConditionalAccessDefinition> = {}): DirectoryNode {
  return { ...node("policy", "policy"), sourceEndpoint: "/identity/conditionalAccess/policies", conditionalAccess: {
    state: "enabled", users: { include: ["All"], exclude: [], includeGroups: [], excludeGroups: [] }, applications: { include: ["All"], exclude: [] },
    platforms: null, locations: null, clientAppTypes: [], grant: { operator: "AND", controls: ["mfa"] }, unsupported: [], ...overrides } };
}
