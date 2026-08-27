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
  GraphAppRole,
  GraphAppRoleAssignment,
  GraphApplication,
  GraphConditionalAccessPolicy,
  GraphCredentialMetadata,
  GraphCrossTenantPartner,
  GraphDirectoryObject,
  GraphRoleDefinition,
  GraphServicePrincipal,
  RawTenantScan,
  Sourced,
} from "./types";

export interface NormalizeOptions {
  tenantLabel?: string;
  snapshotId?: string;
}

export function normalizeTenantScan(raw: RawTenantScan, options: NormalizeOptions = {}): TenantSnapshot {
  const nodes = collectNodes(raw);
  // The relationship builders below can add a placeholder for an object a relationship
  // references but the inventory never returned, so the node list is read afterwards.
  const edges = collectEdges(raw, nodes);

  const snapshot: TenantSnapshot = {
    id: options.snapshotId ?? randomUUID(),
    tenant: {
      tenantId: raw.tenantId,
      tenantLabel: options.tenantLabel?.trim() || `Tenant ${raw.tenantId.slice(0, 8)}`,
    },
    scannedAt: raw.scannedAt,
    mode: "tenant",
    completion: scanCompletion(raw),
    nodes: Array.from(nodes.values()),
    edges,
  };
  // Stryker disable next-line all: defense in depth. Every node and edge above is stamped with
  // raw.tenantId, so no input can make this assertion fail; it exists to stop a future change
  // from letting another tenant's record into a snapshot.
  assertTenantBoundary(snapshot);
  return snapshot;
}

/** Every object the scan inventoried, keyed by id; later records never displace earlier ones. */
function collectNodes(raw: RawTenantScan): Map<string, DirectoryNode> {
  const applicationOwners = ownerIndex(raw.applicationOwners);
  const servicePrincipalOwners = ownerIndex(raw.servicePrincipalOwners);
  const nodes = new Map<string, DirectoryNode>();

  for (const { record } of raw.applications) {
    nodes.set(record.id, applicationNode(record, raw, applicationOwners.get(record.id) ?? []));
  }
  for (const { record } of raw.servicePrincipals) {
    nodes.set(record.id, servicePrincipalNode(record, raw, servicePrincipalOwners.get(record.id) ?? []));
    for (const role of record.appRoles) {
      const node = appRoleNode(record, role, raw.tenantId);
      nodes.set(node.id, node);
    }
  }
  for (const { record } of raw.users ?? []) ensureDirectoryObjectNode(nodes, record, raw.tenantId);
  for (const { record } of raw.groups ?? []) ensureDirectoryObjectNode(nodes, record, raw.tenantId);
  for (const membership of raw.groupMemberships ?? []) ensureDirectoryObjectNode(nodes, membership.record, raw.tenantId);
  for (const { record } of raw.roleDefinitions ?? []) nodes.set(record.id, directoryRoleNode(record, raw.tenantId));
  for (const { record } of raw.conditionalAccessPolicies ?? []) nodes.set(record.id, conditionalAccessPolicyNode(record, raw.tenantId));
  for (const { record } of raw.crossTenantPartners ?? []) {
    for (const node of partnerNodes(record, raw.tenantId)) nodes.set(node.id, node);
  }
  for (const owner of [...raw.applicationOwners, ...raw.servicePrincipalOwners]) {
    ensureDirectoryObjectNode(nodes, owner.record, raw.tenantId);
  }
  for (const { record } of raw.appRoleAssignments) {
    ensureAssignmentPrincipalNode(nodes, record, raw.tenantId);
  }
  return nodes;
}

/** Every relationship the scan can justify, with each relationship appearing once. */
function collectEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const edges: RelationshipEdge[] = [
    ...instantiationEdges(raw),
    ...assignmentEdges(raw, nodes),
    ...appRoleEdges(raw),
    ...delegatedGrantEdges(raw, nodes),
    ...ownershipEdges(raw, nodes),
    ...membershipEdges(raw, nodes),
    ...roleEdges(raw, nodes),
    ...policyEdges(raw, nodes),
    ...activityEdges(raw, nodes),
    ...crossTenantEdges(raw),
  ];
  // Edge ids are derived from the relationship itself, so two edges sharing an id are
  // the same relationship. A resumed scan re-runs the per-object owner and membership
  // fan-out from the start and appends, which would otherwise emit it twice.
  return Array.from(new Map(edges.map((edge) => [edge.id, edge])).values());
}

function scanCompletion(raw: RawTenantScan): TenantSnapshot["completion"] {
  return {
    status: raw.errors.length > 0 ? "partial" : "complete",
    collectedEndpoints: unique(raw.collectedEndpoints),
    skippedEndpoints: unique(raw.skippedEndpoints),
    errors: raw.errors.map((error) => `${error.endpoint}: ${error.code}`),
  };
}

function appRoleNode(record: GraphServicePrincipal, role: GraphAppRole, tenantId: string): DirectoryNode {
  const disabled = role.isEnabled === false;
  return {
    id: appRoleNodeId(record.id, role.id),
    tenantId,
    kind: "appRole",
    label: role.value || role.displayName || `App role ${role.id.slice(0, 8)}`,
    description: `Application role exposed by ${record.displayName}.`,
    ownerIds: [],
    metadata: { appRoleId: role.id, resourceServicePrincipalId: record.id, enabled: role.isEnabled === true },
    risk: {
      level: disabled ? "review" : "low",
      reason: disabled
        ? "The role is disabled but may remain referenced by assignments."
        : "Risk depends on the principals granted this role.",
    },
  };
}

function directoryRoleNode(record: GraphRoleDefinition, tenantId: string): DirectoryNode {
  return {
    id: record.id,
    tenantId,
    kind: "directoryRole",
    label: record.displayName,
    description: "Microsoft Entra administrative role.",
    ownerIds: [],
    metadata: { templateId: record.templateId ?? null, isBuiltIn: record.isBuiltIn ?? false },
    risk: { level: "review", reason: "Administrative role membership can provide privileged directory access." },
  };
}

function conditionalAccessPolicyNode(record: GraphConditionalAccessPolicy, tenantId: string): DirectoryNode {
  const enabled = record.state === "enabled";
  return {
    id: record.id,
    tenantId,
    kind: "policy",
    label: record.displayName,
    description: "Conditional Access policy collected from Microsoft Graph.",
    ownerIds: [],
    metadata: {
      policyType: "conditionalAccess",
      state: record.state,
      controls: record.grantControls?.builtInControls?.join(", ") ?? "none",
    },
    risk: {
      level: enabled ? "low" : "review",
      // An enabled policy is not the same as an effective one, and the snapshot cannot tell.
      reason: enabled
        ? "Policy is enabled; applicability still depends on its conditions."
        : `Policy state is ${record.state}.`,
    },
  };
}

/** A partner tenant and the cross-tenant policy that describes what it is trusted for. */
function partnerNodes(record: GraphCrossTenantPartner, tenantId: string): [DirectoryNode, DirectoryNode] {
  const trust = record.inboundTrust;
  const acceptsAnyClaim = Boolean(trust?.isMfaAccepted || trust?.isCompliantDeviceAccepted || trust?.isHybridAzureADJoinedDeviceAccepted);
  return [
    {
      id: `external-tenant:${record.tenantId}`,
      tenantId,
      kind: "externalTenant",
      label: `External tenant ${record.tenantId.slice(0, 8)}`,
      description: "Partner organization with explicit cross-tenant access settings.",
      isExternal: true,
      ownerIds: [],
      metadata: {
        externalTenantId: record.tenantId,
        trustsMfa: trust?.isMfaAccepted === true,
        trustsCompliantDevice: trust?.isCompliantDeviceAccepted === true,
        trustsHybridJoinedDevice: trust?.isHybridAzureADJoinedDeviceAccepted === true,
        multiTenantOrganization: record.isInMultiTenantOrganization === true,
      },
      risk: {
        level: acceptsAnyClaim ? "review" : "low",
        reason: "Partner-specific cross-tenant trust must be reviewed in context.",
      },
    },
    {
      id: `cross-tenant-policy:${record.tenantId}`,
      tenantId,
      kind: "policy",
      label: `Partner policy ${record.tenantId.slice(0, 8)}`,
      description: "Partner-specific Microsoft Entra cross-tenant access policy.",
      ownerIds: [],
      metadata: { policyType: "crossTenantAccess", state: "configured" },
      risk: { level: "review", reason: "Cross-tenant settings require periodic owner review." },
    },
  ];
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

function crossTenantEdges(raw: RawTenantScan): RelationshipEdge[] {
  return (raw.crossTenantPartners ?? []).flatMap(({ record, endpoint }) => {
    // Both endpoints of this edge are created from this same partner record above,
    // so no presence check is needed here.
    const id = `external-tenant:${record.tenantId}`;
    const trusted = [record.inboundTrust?.isMfaAccepted ? "MFA" : null, record.inboundTrust?.isCompliantDeviceAccepted ? "compliant device" : null, record.inboundTrust?.isHybridAzureADJoinedDeviceAccepted ? "hybrid joined device" : null].filter((value): value is string => Boolean(value));
    const policyId = `cross-tenant-policy:${record.tenantId}`;
    return [{ id: stableId("cross-tenant", record.tenantId), tenantId: raw.tenantId, type: "CROSS_TENANT_ACCESS" as const, sourceId: id, targetId: policyId, plainLabel: "Has partner access settings", permissions: trusted, evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: endpoint, sourceRecordIds: [record.tenantId], sourceObjectId: id, targetObjectId: policyId, completeness: "complete" as const } }];
  });
}

function roleEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const schedules = [...(raw.roleAssignments ?? []).map((item) => ({ ...item, type: "ACTIVE_IN_ROLE" as const, label: "Active in role" })), ...(raw.roleEligibilities ?? []).map((item) => ({ ...item, type: "ELIGIBLE_FOR_ROLE" as const, label: "Eligible for role" }))];
  return schedules.flatMap((item) => {
    // Stryker disable next-line ConditionalExpression: ensureDirectoryObjectNode returns an existing node untouched, so the guard only avoids the call.
    if (!nodes.has(item.record.principalId)) ensureDirectoryObjectNode(nodes, { id: item.record.principalId }, raw.tenantId);
    if (!nodes.has(item.record.roleDefinitionId)) return [];
    return [{ id: stableId("role", item.record.id), tenantId: raw.tenantId, type: item.type, sourceId: item.record.principalId, targetId: item.record.roleDefinitionId, plainLabel: item.label, permissions: item.record.directoryScopeId ? [item.record.directoryScopeId] : [], evidence: { configured: true, observed: null, scannedAt: raw.scannedAt, sourceEndpoint: item.endpoint, sourceRecordIds: [item.record.id], sourceObjectId: item.record.principalId, targetObjectId: item.record.roleDefinitionId, completeness: "complete" as const } }];
  });
}

function policyEdges(raw: RawTenantScan, nodes: Map<string, DirectoryNode>): RelationshipEdge[] {
  const appObjectByAppId = new Map(raw.servicePrincipals.map(({ record }) => [record.appId, record.id]));
  return (raw.conditionalAccessPolicies ?? []).flatMap(({ record, endpoint }) => {
    // Stryker disable next-line ArrayDeclaration: a seeded id matches no collected object, so it is dropped by the `nodes.has` test below.
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
  // Stryker disable next-line ConditionalExpression: no credentials also means no expirations, so the second test already covers this one.
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
  const applicationsByAppId = new Map(raw.applications.map((entry) => [entry.record.appId, entry]));
  return raw.servicePrincipals.flatMap(({ record: servicePrincipal, endpoint: serviceEndpoint }) => {
    const applicationSource = applicationsByAppId.get(servicePrincipal.appId);
    if (!applicationSource) return [];
    const { record: application, endpoint: applicationEndpoint } = applicationSource;
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
        sourceEndpoint: `${applicationEndpoint} + ${serviceEndpoint} (matching appId)`,
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
    // Stryker disable next-line ArrayDeclaration: a seeded entry indexes under an undefined id, which no assignment can look up.
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
      // Stryker disable next-line Regex: filter(Boolean) drops the empty entries a single-space split would leave.
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
