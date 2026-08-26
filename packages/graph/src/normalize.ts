import { createHash, randomUUID } from "node:crypto";
import {
  assertTenantBoundary,
  type DirectoryNode,
  type NodeKind,
  type RelationshipEdge,
  type RelationshipType,
  type TenantSnapshot,
} from "@entra-explorer/domain";
import type {
  GraphAppRoleAssignment,
  GraphApplication,
  GraphCredentialMetadata,
  GraphDirectoryObject,
  GraphServicePrincipal,
  RawTenantScan,
  Sourced,
} from "./types";

export interface NormalizeOptions {
  tenantLabel?: string;
  snapshotId?: string;
}

export function normalizeTenantScan(raw: RawTenantScan, options: NormalizeOptions = {}): TenantSnapshot {
  const applicationOwners = ownerIndex(raw.applicationOwners);
  const servicePrincipalOwners = ownerIndex(raw.servicePrincipalOwners);
  const nodes = new Map<string, DirectoryNode>();

  for (const { record } of raw.applications) {
    nodes.set(record.id, applicationNode(record, raw, applicationOwners.get(record.id) ?? []));
  }
  for (const { record } of raw.servicePrincipals) {
    nodes.set(record.id, servicePrincipalNode(record, raw, servicePrincipalOwners.get(record.id) ?? []));
    for (const role of record.appRoles) {
      const roleId = appRoleNodeId(record.id, role.id);
      nodes.set(roleId, { id: roleId, tenantId: raw.tenantId, kind: "appRole", label: role.value || role.displayName || `App role ${role.id.slice(0, 8)}`, description: `Application role exposed by ${record.displayName}.`, ownerIds: [], metadata: { appRoleId: role.id, resourceServicePrincipalId: record.id, enabled: role.isEnabled === true }, risk: { level: role.isEnabled === false ? "review" : "low", reason: role.isEnabled === false ? "The role is disabled but may remain referenced by assignments." : "Risk depends on the principals granted this role." } });
    }
  }
  for (const { record } of raw.users ?? []) ensureDirectoryObjectNode(nodes, record, raw.tenantId);
  for (const { record } of raw.groups ?? []) ensureDirectoryObjectNode(nodes, record, raw.tenantId);
  for (const membership of raw.groupMemberships ?? []) ensureDirectoryObjectNode(nodes, membership.record, raw.tenantId);
  for (const { record } of raw.roleDefinitions ?? []) nodes.set(record.id, { id: record.id, tenantId: raw.tenantId, kind: "directoryRole", label: record.displayName, description: "Microsoft Entra administrative role.", ownerIds: [], metadata: { templateId: record.templateId ?? null, isBuiltIn: record.isBuiltIn ?? false }, risk: { level: "review", reason: "Administrative role membership can provide privileged directory access." } });
  for (const { record } of raw.conditionalAccessPolicies ?? []) nodes.set(record.id, { id: record.id, tenantId: raw.tenantId, kind: "policy", label: record.displayName, description: "Conditional Access policy collected from Microsoft Graph.", ownerIds: [], metadata: { policyType: "conditionalAccess", state: record.state, controls: record.grantControls?.builtInControls?.join(", ") ?? "none" }, risk: { level: record.state === "enabled" ? "low" : "review", reason: record.state === "enabled" ? "Policy is enabled; applicability still depends on its conditions." : `Policy state is ${record.state}.` } });
  for (const { record } of raw.crossTenantPartners ?? []) {
    const id = `external-tenant:${record.tenantId}`;
    nodes.set(id, { id, tenantId: raw.tenantId, kind: "externalTenant", label: `External tenant ${record.tenantId.slice(0, 8)}`, description: "Partner organization with explicit cross-tenant access settings.", isExternal: true, ownerIds: [], metadata: { externalTenantId: record.tenantId, trustsMfa: record.inboundTrust?.isMfaAccepted === true, trustsCompliantDevice: record.inboundTrust?.isCompliantDeviceAccepted === true, trustsHybridJoinedDevice: record.inboundTrust?.isHybridAzureADJoinedDeviceAccepted === true, multiTenantOrganization: record.isInMultiTenantOrganization === true }, risk: { level: record.inboundTrust?.isMfaAccepted || record.inboundTrust?.isCompliantDeviceAccepted || record.inboundTrust?.isHybridAzureADJoinedDeviceAccepted ? "review" : "low", reason: "Partner-specific cross-tenant trust must be reviewed in context." } });
    const policyId = `cross-tenant-policy:${record.tenantId}`;
    nodes.set(policyId, { id: policyId, tenantId: raw.tenantId, kind: "policy", label: `Partner policy ${record.tenantId.slice(0, 8)}`, description: "Partner-specific Microsoft Entra cross-tenant access policy.", ownerIds: [], metadata: { policyType: "crossTenantAccess", state: "configured" }, risk: { level: "review", reason: "Cross-tenant settings require periodic owner review." } });
  }
  for (const owner of [...raw.applicationOwners, ...raw.servicePrincipalOwners]) {
    ensureDirectoryObjectNode(nodes, owner.record, raw.tenantId);
  }
  for (const { record } of raw.appRoleAssignments) {
    ensureAssignmentPrincipalNode(nodes, record, raw.tenantId);
  }

  const edges: RelationshipEdge[] = [];
  edges.push(...instantiationEdges(raw));
  edges.push(...assignmentEdges(raw, nodes));
  edges.push(...appRoleEdges(raw));
  edges.push(...delegatedGrantEdges(raw, nodes));
  edges.push(...ownershipEdges(raw, nodes));
  edges.push(...membershipEdges(raw, nodes));
  edges.push(...roleEdges(raw, nodes));
  edges.push(...policyEdges(raw, nodes));
  edges.push(...activityEdges(raw, nodes));
  edges.push(...crossTenantEdges(raw, nodes));

  const snapshot: TenantSnapshot = {
    id: options.snapshotId ?? randomUUID(),
    tenant: {
      tenantId: raw.tenantId,
      tenantLabel: options.tenantLabel?.trim() || `Tenant ${raw.tenantId.slice(0, 8)}`,
    },
    scannedAt: raw.scannedAt,
    mode: "tenant",
    completion: {
      status: raw.errors.length > 0 ? "partial" : "complete",
      collectedEndpoints: unique(raw.collectedEndpoints),
      skippedEndpoints: unique(raw.skippedEndpoints),
      errors: raw.errors.map((error) => `${error.endpoint}: ${error.code}`),
    },
    nodes: Array.from(nodes.values()),
    edges,
  };
  assertTenantBoundary(snapshot);
  return snapshot;
}

function appRoleNodeId(resourceId: string, roleId: string): string { return `app-role:${resourceId}:${roleId}`; }

function appRoleEdges(raw: RawTenantScan): RelationshipEdge[] {
  const exposed = raw.servicePrincipals.flatMap(({ record, endpoint }) => record.appRoles.map((role) => { const roleId = appRoleNodeId(record.id, role.id); return { id: stableId("exposes-role", roleId), tenantId: raw.tenantId, type: "EXPOSES_APP_ROLE" as const, sourceId: record.id, targetId: roleId, plainLabel: "Exposes app role", permissions: [role.value || role.displayName || role.id], evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.id, role.id], sourceObjectId: record.id, targetObjectId: roleId, completeness: "complete" as const } }; }));
  const granted = raw.appRoleAssignments.flatMap(({ record, endpoint }) => {
    const roleId = appRoleNodeId(record.resourceId, record.appRoleId);
    if (!raw.servicePrincipals.some(({ record: service }) => service.id === record.resourceId && service.appRoles.some((role) => role.id === record.appRoleId))) return [];
    return [{ id: stableId("granted-role", record.id), tenantId: raw.tenantId, type: "GRANTED_APP_ROLE" as const, sourceId: record.principalId, targetId: roleId, plainLabel: "Granted app role", permissions: [record.appRoleId], evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.id, record.appRoleId], sourceObjectId: record.principalId, targetObjectId: roleId, completeness: "complete" as const } }];
  });
  return [...exposed, ...granted];
}

function crossTenantEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  return (raw.crossTenantPartners ?? []).flatMap(({ record, endpoint }) => {
    const id = `external-tenant:${record.tenantId}`;
    if (!nodes.has(id)) return [];
    const trusted = [record.inboundTrust?.isMfaAccepted ? "MFA" : null, record.inboundTrust?.isCompliantDeviceAccepted ? "compliant device" : null, record.inboundTrust?.isHybridAzureADJoinedDeviceAccepted ? "hybrid joined device" : null].filter((value): value is string => Boolean(value));
    const policyId = `cross-tenant-policy:${record.tenantId}`;
    return [{ id: stableId("cross-tenant", record.tenantId), tenantId: raw.tenantId, type: "CROSS_TENANT_ACCESS" as const, sourceId: id, targetId: policyId, plainLabel: "Has partner access settings", permissions: trusted, evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.tenantId], sourceObjectId: id, targetObjectId: policyId, completeness: "complete" as const } }];
  });
}

function roleEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const schedules = [...(raw.roleAssignments ?? []).map((item) => ({ ...item, type: "ACTIVE_IN_ROLE" as const, label: "Active in role" })), ...(raw.roleEligibilities ?? []).map((item) => ({ ...item, type: "ELIGIBLE_FOR_ROLE" as const, label: "Eligible for role" }))];
  return schedules.flatMap((item) => {
    if (!nodes.has(item.record.principalId)) ensureDirectoryObjectNode(nodes, { id: item.record.principalId }, raw.tenantId);
    if (!nodes.has(item.record.roleDefinitionId)) return [];
    return [{ id: stableId("role", item.record.id), tenantId: raw.tenantId, type: item.type, sourceId: item.record.principalId, targetId: item.record.roleDefinitionId, plainLabel: item.label, permissions: item.record.directoryScopeId ? [item.record.directoryScopeId] : [], evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: item.endpoint, sourceRecordIds: [item.record.id], sourceObjectId: item.record.principalId, targetObjectId: item.record.roleDefinitionId, completeness: "complete" as const } }];
  });
}

function policyEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const appObjectByAppId = new Map(raw.servicePrincipals.map(({ record }) => [record.appId, record.id]));
  return (raw.conditionalAccessPolicies ?? []).flatMap(({ record, endpoint }) => {
    const ids = [...(record.conditions?.users?.includeUsers ?? []), ...(record.conditions?.users?.includeGroups ?? []), ...(record.conditions?.applications?.includeApplications ?? []).map((id) => appObjectByAppId.get(id) ?? id)].filter((id) => !["All", "None", "GuestsOrExternalUsers", "Office365"].includes(id));
    return unique(ids).flatMap((id) => nodes.has(id) ? [{ id: stableId("policy", `${id}:${record.id}`), tenantId: raw.tenantId, type: "GOVERNED_BY" as const, sourceId: id, targetId: record.id, plainLabel: "Governed by", permissions: record.grantControls?.builtInControls ?? [], evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.id], sourceObjectId: id, targetObjectId: record.id, completeness: "complete" as const } }] : []);
  });
}

function activityEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  return (raw.signIns ?? []).flatMap(({ record, endpoint }) => {
    if (!record.servicePrincipalId || !record.resourceServicePrincipalId) return [];
    ensureMissingTarget(nodes, record.servicePrincipalId, record.appDisplayName, raw.tenantId);
    ensureMissingTarget(nodes, record.resourceServicePrincipalId, record.resourceDisplayName, raw.tenantId);
    return [{ id: stableId("activity", record.id), tenantId: raw.tenantId, type: "OBSERVED_CALL" as const, sourceId: record.servicePrincipalId, targetId: record.resourceServicePrincipalId, plainLabel: "Called recently", permissions: [], evidence: { configured: false, observed: { lastSeenAt: record.createdDateTime, windowStartsAt: new Date(new Date(raw.scannedAt).getTime() - 30 * 86_400_000).toISOString() }, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.id], sourceObjectId: record.servicePrincipalId, targetObjectId: record.resourceServicePrincipalId, completeness: "complete" as const } }];
  });
}

function applicationNode(record: GraphApplication, raw: RawTenantScan, ownerIds: string[]): DirectoryNode {
  return {
    id: record.id,
    tenantId: raw.tenantId,
    kind: "application",
    label: record.displayName,
    description: "Reusable application blueprint (app registration) collected from Microsoft Graph.",
    appId: record.appId,
    publisher: record.publisherDomain ?? undefined,
    ownerIds,
    credential: credentialState([...record.passwordCredentials, ...record.keyCredentials], raw.scannedAt),
    risk: entityRisk(ownerIds, [...record.passwordCredentials, ...record.keyCredentials], raw.scannedAt),
  };
}

function servicePrincipalNode(record: GraphServicePrincipal, raw: RawTenantScan, ownerIds: string[]): DirectoryNode {
  const managedIdentity = record.servicePrincipalType?.toLocaleLowerCase() === "managedidentity";
  const ownershipExpected = managedIdentity || raw.applications.some(({ record: application }) => application.appId === record.appId);
  const credentials = [...record.passwordCredentials, ...record.keyCredentials];
  return {
    id: record.id,
    tenantId: raw.tenantId,
    kind: managedIdentity ? "managedIdentity" : "servicePrincipal",
    label: record.displayName,
    description: record.servicePrincipalType?.toLocaleLowerCase() === "managedidentity" ? "Managed workload identity collected from Microsoft Graph." : "Tenant-local application identity (service principal) collected from Microsoft Graph.",
    appId: record.appId,
    publisher: record.publisherName ?? undefined,
    metadata: { servicePrincipalType: record.servicePrincipalType ?? "Application", ownershipExpected },
    ownerIds,
    credential: credentialState(credentials, raw.scannedAt),
    risk: ownershipExpected ? entityRisk(ownerIds, credentials, raw.scannedAt) : { level: "low", reason: "This tenant-local enterprise application is publisher-managed; a local owner is not expected." },
  };
}

function credentialState(credentials: GraphCredentialMetadata[], scannedAt: string): NonNullable<DirectoryNode["credential"]> {
  const expirations = credentials
    .map((credential) => credential.endDateTime)
    .filter((value): value is string => Boolean(value))
    .map((value) => new Date(value))
    .filter((value) => Number.isFinite(value.getTime()))
    .sort((a, b) => a.getTime() - b.getTime());
  if (credentials.length === 0 || expirations.length === 0) return { status: "none", expiresAt: null };
  const next = expirations[0]!;
  const scanTime = new Date(scannedAt).getTime();
  const remaining = next.getTime() - scanTime;
  if (remaining <= 0) return { status: "expired", expiresAt: next.toISOString() };
  if (remaining <= 90 * 24 * 60 * 60 * 1_000) return { status: "expiring", expiresAt: next.toISOString() };
  return { status: "healthy", expiresAt: next.toISOString() };
}

function entityRisk(ownerIds: string[], credentials: GraphCredentialMetadata[], scannedAt: string): DirectoryNode["risk"] {
  const credential = credentialState(credentials, scannedAt);
  if (credential.status === "expired") return { level: "high", reason: `A credential expired on ${credential.expiresAt}.` };
  if (credential.status === "expiring") return { level: "review", reason: `A credential expires within 90 days (${credential.expiresAt}).` };
  if (ownerIds.length === 0) return { level: "review", reason: "No owner was returned in this scan." };
  return { level: "low", reason: "An owner is recorded and no credential expires within 90 days." };
}

function ownerIndex(owners: Array<Sourced<GraphDirectoryObject> & { targetId: string }>): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const owner of owners) {
    const current = index.get(owner.targetId) ?? [];
    if (!current.includes(owner.record.id)) current.push(owner.record.id);
    index.set(owner.targetId, current);
  }
  return index;
}

function ensureDirectoryObjectNode(nodes: Map<string, DirectoryNode>, record: GraphDirectoryObject, tenantId: string): DirectoryNode {
  const existing = nodes.get(record.id);
  if (existing) return existing;
  const kind = directoryKind(record["@odata.type"]);
  const node: DirectoryNode = {
    id: record.id,
    tenantId,
    kind,
    label: record.displayName?.trim() || `Unresolved ${kind}`,
    description: record.displayName ? "Directory object collected from an ownership relationship." : "Directory object returned with limited information.",
    isExternal: record.userType?.toLocaleLowerCase() === "guest",
    ownerIds: [],
    risk: { level: "low", reason: record.displayName ? "No advisory entity rule applies." : "Limited directory information was returned." },
  };
  nodes.set(node.id, node);
  return node;
}

function membershipEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  return (raw.groupMemberships ?? []).flatMap((membership) => {
    const source = ensureDirectoryObjectNode(nodes, membership.record, raw.tenantId);
    const target = nodes.get(membership.groupId);
    if (!target) return [];
    return [{
      id: stableId("member", `${source.id}:${target.id}`), tenantId: raw.tenantId, type: "MEMBER_OF" as const,
      sourceId: source.id, targetId: target.id, plainLabel: "Member of", permissions: [],
      evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: membership.endpoint, sourceRecordIds: [source.id, target.id], sourceObjectId: source.id, targetObjectId: target.id, completeness: membership.record.displayName ? "complete" as const : "partial" as const },
    }];
  });
}

function ensureAssignmentPrincipalNode(nodes: Map<string, DirectoryNode>, record: GraphAppRoleAssignment, tenantId: string): DirectoryNode {
  const existing = nodes.get(record.principalId);
  if (existing) return existing;
  const kind = principalKind(record.principalType);
  const node: DirectoryNode = {
    id: record.principalId,
    tenantId,
    kind,
    label: record.principalDisplayName?.trim() || `Unresolved ${kind}`,
    description: record.principalDisplayName ? "Directory principal collected from an app-role assignment." : "Assignment principal returned with limited information.",
    ownerIds: [],
    risk: { level: "review", reason: "This object was discovered from an assignment and has limited inventory detail." },
  };
  nodes.set(node.id, node);
  return node;
}

function instantiationEdges(raw: RawTenantScan): RelationshipEdge[] {
  const applicationsByAppId = new Map(raw.applications.map(({ record }) => [record.appId, record]));
  return raw.servicePrincipals.flatMap(({ record: servicePrincipal, endpoint: serviceEndpoint }) => {
    const application = applicationsByAppId.get(servicePrincipal.appId);
    if (!application) return [];
    const appSource = raw.applications.find(({ record }) => record.id === application.id);
    return [{
      id: stableId("instantiates", `${application.id}:${servicePrincipal.id}`),
      tenantId: raw.tenantId,
      type: "INSTANTIATES_AS" as const,
      sourceId: application.id,
      targetId: servicePrincipal.id,
      plainLabel: "Creates a tenant identity",
      permissions: [],
      evidence: {
        configured: true,
        observed: null,
        scannedAt: raw.scannedAt,
        sourceEndpoint: `${appSource?.endpoint ?? "/applications"} + ${serviceEndpoint} (matching appId)`,
        sourceRecordIds: [application.id, servicePrincipal.id],
        sourceObjectId: application.id,
        targetObjectId: servicePrincipal.id,
        completeness: "complete" as const,
      },
    }];
  });
}

function assignmentEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const services = new Map(raw.servicePrincipals.map(({ record }) => [record.id, record]));
  const groups = new Map<string, Sourced<GraphAppRoleAssignment>[]>();
  for (const assignment of raw.appRoleAssignments) {
    const type: RelationshipType = assignment.record.principalType.toLocaleLowerCase() === "serviceprincipal" ? "CAN_CALL_AS_APP" : "ASSIGNED_TO";
    const key = `${type}:${assignment.record.principalId}:${assignment.record.resourceId}`;
    groups.set(key, [...(groups.get(key) ?? []), assignment]);
  }

  return Array.from(groups.entries(), ([key, assignments]) => {
    const first = assignments[0]!;
    const record = first.record;
    ensureMissingTarget(nodes, record.resourceId, record.resourceDisplayName, raw.tenantId);
    const resource = services.get(record.resourceId);
    const roleIndex = new Map((resource?.appRoles ?? []).map((role) => [role.id, role]));
    const permissions = unique(assignments.map(({ record: item }) => roleIndex.get(item.appRoleId)?.value || roleIndex.get(item.appRoleId)?.displayName || `Unresolved role ${item.appRoleId}`));
    const unresolved = !resource || assignments.some(({ record: item }) => !roleIndex.has(item.appRoleId));
    const type: RelationshipType = record.principalType.toLocaleLowerCase() === "serviceprincipal" ? "CAN_CALL_AS_APP" : "ASSIGNED_TO";
    return {
      id: stableId("assignment", key),
      tenantId: raw.tenantId,
      type,
      sourceId: record.principalId,
      targetId: record.resourceId,
      plainLabel: type === "CAN_CALL_AS_APP" ? "Can call" : "Assigned to use",
      permissions,
      evidence: {
        configured: true,
        observed: null,
        scannedAt: raw.scannedAt,
        sourceEndpoint: first.endpoint,
        sourceRecordIds: assignments.map(({ record: item }) => item.id),
        sourceObjectId: record.principalId,
        targetObjectId: record.resourceId,
        completeness: unresolved ? "unresolved" : "complete",
      },
    };
  });
}

function delegatedGrantEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  return raw.oauth2PermissionGrants.map(({ record, endpoint }) => {
    ensureMissingTarget(nodes, record.clientId, null, raw.tenantId);
    ensureMissingTarget(nodes, record.resourceId, null, raw.tenantId);
    const unresolved = !raw.servicePrincipals.some(({ record: service }) => service.id === record.clientId) ||
      !raw.servicePrincipals.some(({ record: service }) => service.id === record.resourceId);
    return {
      id: stableId("delegated", record.id),
      tenantId: raw.tenantId,
      type: "CAN_CALL_DELEGATED",
      sourceId: record.clientId,
      targetId: record.resourceId,
      plainLabel: "Can call with a signed-in person",
      permissions: unique(record.scope.split(/\s+/).filter(Boolean)),
      evidence: {
        configured: true,
        observed: null,
        scannedAt: raw.scannedAt,
        sourceEndpoint: endpoint,
        sourceRecordIds: [record.id],
        sourceObjectId: record.clientId,
        targetObjectId: record.resourceId,
        completeness: unresolved ? "unresolved" : "complete",
      },
    };
  });
}

function ownershipEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  return [...raw.applicationOwners, ...raw.servicePrincipalOwners].flatMap((owner) => {
    if (!nodes.has(owner.targetId)) return [];
    const source = ensureDirectoryObjectNode(nodes, owner.record, raw.tenantId);
    return [{
      id: stableId("owner", `${source.id}:${owner.targetId}`),
      tenantId: raw.tenantId,
      type: "OWNS" as const,
      sourceId: source.id,
      targetId: owner.targetId,
      plainLabel: "Owns",
      permissions: [],
      evidence: {
        configured: true,
        observed: null,
        scannedAt: raw.scannedAt,
        sourceEndpoint: owner.endpoint,
        sourceRecordIds: [source.id],
        sourceObjectId: source.id,
        targetObjectId: owner.targetId,
        completeness: owner.record.displayName ? "complete" as const : "partial" as const,
      },
    }];
  });
}

function ensureMissingTarget(nodes: Map<string, DirectoryNode>, id: string, label: string | null | undefined, tenantId: string): void {
  if (nodes.has(id)) return;
  nodes.set(id, {
    id,
    tenantId,
    kind: "servicePrincipal",
    label: label?.trim() || "Unresolved tenant identity",
    description: "Referenced by a configured relationship but missing from the collected service-principal inventory.",
    ownerIds: [],
    risk: { level: "review", reason: "The source object is incomplete; inspect scan errors and skipped endpoints." },
  });
}

function directoryKind(odataType: string | undefined): NodeKind {
  if (odataType?.endsWith("group")) return "group";
  if (odataType?.endsWith("servicePrincipal")) return "servicePrincipal";
  return "user";
}

function principalKind(principalType: string): NodeKind {
  if (principalType.toLocaleLowerCase() === "group") return "group";
  if (principalType.toLocaleLowerCase() === "serviceprincipal") return "servicePrincipal";
  return "user";
}

function stableId(prefix: string, value: string): string {
  return `${prefix}:${createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}
