import { createHash, randomUUID } from "node:crypto";
import {
  assertTenantBoundary,
  type DirectoryNode,
  type NodeKind,
  type RelationshipEdge,
  type RelationshipType,
  type RiskLevel,
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
  edges.push(...delegatedGrantEdges(raw, nodes));
  edges.push(...ownershipEdges(raw, nodes));

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
  return {
    id: record.id,
    tenantId: raw.tenantId,
    kind: "servicePrincipal",
    label: record.displayName,
    description: "Tenant-local application identity (service principal) collected from Microsoft Graph.",
    appId: record.appId,
    publisher: record.publisherName ?? undefined,
    ownerIds,
    credential: credentialState([...record.passwordCredentials, ...record.keyCredentials], raw.scannedAt),
    risk: entityRisk(ownerIds, [...record.passwordCredentials, ...record.keyCredentials], raw.scannedAt),
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
    ownerIds: [],
    risk: { level: "low", reason: record.displayName ? "No advisory entity rule applies." : "Limited directory information was returned." },
  };
  nodes.set(node.id, node);
  return node;
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
