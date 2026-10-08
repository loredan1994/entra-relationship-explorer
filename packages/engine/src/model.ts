import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "@entra-explorer/domain";
import { canonical, compare, immutable, timestamp, unique } from "./canonical";
import { ENGINE_VERSION, RULE_VERSION, type Conflict, type EngineContext, type EvidenceModel } from "./types";

/** Project only the fields the engine understands; arbitrary metadata never enters replay. */
export function projectNode(node: DirectoryNode): DirectoryNode {
  return {
    id: node.id, tenantId: node.tenantId, kind: node.kind, label: node.label,
    description: "", ownerIds: [], risk: { level: "low", reason: "Engine facts carry no risk score." },
    ...(node.appId ? { appId: node.appId } : {}),
    ...(node.sourceEndpoint ? { sourceEndpoint: node.sourceEndpoint } : {}),
    ...(node.kind === "policy" && typeof node.metadata?.policyType === "string" && ["conditionalAccess", "authorization", "permissionGrant", "crossTenantAccess"].includes(node.metadata.policyType)
      ? { metadata: { policyType: node.metadata.policyType } } : {}),
    ...(node.applicationProfile ? { applicationProfile: {
      signInAudience: node.applicationProfile.signInAudience,
      verifiedPublisherId: null, verifiedPublisherName: null,
      accountEnabled: node.applicationProfile.accountEnabled,
      assignmentRequired: node.applicationProfile.assignmentRequired,
    } } : {}),
    ...(node.credentials ? { credentials: node.credentials.map(c => ({ id: c.id, kind: c.kind, label: null, startsAt: c.startsAt, expiresAt: c.expiresAt, sourceEndpoint: c.sourceEndpoint })).sort((a, b) => compare(a.id, b.id)) } : {}),
    ...(node.federationTrust ? { federationTrust: { issuer: node.federationTrust.issuer, subject: node.federationTrust.subject, audiences: unique(node.federationTrust.audiences), unsupported: unique(node.federationTrust.unsupported) } } : {}),
    ...(node.conditionalAccess ? { conditionalAccess: JSON.parse(canonical(node.conditionalAccess)) as DirectoryNode["conditionalAccess"] } : {}),
  };
}

export function projectEdge(edge: RelationshipEdge): RelationshipEdge {
  return {
    id: edge.id, tenantId: edge.tenantId, type: edge.type,
    sourceId: edge.sourceId, targetId: edge.targetId, plainLabel: edge.type,
    permissions: unique(edge.permissions),
    ...(edge.permissionIds ? { permissionIds: unique(edge.permissionIds) } : {}),
    ...(edge.consent ? { consent: { audience: edge.consent.audience, principalId: edge.consent.principalId } } : {}),
    ...(edge.scope ? { scope: { directoryScopeId: edge.scope.directoryScopeId, objectId: edge.scope.objectId } } : {}),
    ...(edge.validity ? { validity: { startsAt: edge.validity.startsAt, endsAt: edge.validity.endsAt } } : {}),
    evidence: {
      configured: edge.evidence.configured,
      observed: edge.evidence.observed ? { lastSeenAt: edge.evidence.observed.lastSeenAt, windowStartsAt: edge.evidence.observed.windowStartsAt } : null,
      scannedAt: edge.evidence.scannedAt, sourceEndpoint: edge.evidence.sourceEndpoint,
      sourceRecordIds: unique(edge.evidence.sourceRecordIds), sourceObjectId: edge.evidence.sourceObjectId,
      targetObjectId: edge.evidence.targetObjectId, completeness: edge.evidence.completeness,
    },
  };
}

function deduplicate<T extends { id: string }>(values: T[], prefix: string, conflicts: Conflict[]): T[] {
  const records = new Map<string, Map<string, T>>();
  for (const value of values) {
    const variants = records.get(value.id) ?? new Map<string, T>();
    variants.set(canonical(value), value);
    records.set(value.id, variants);
  }
  return [...records].sort(([a], [b]) => compare(a, b)).map(([id, variants]) => {
    const keys = [...variants.keys()].sort(compare);
    if (keys.length > 1) conflicts.push({ factId: `${prefix}:${id}`, variants: keys });
    return variants.get(keys[0]!)!;
  });
}

export function compileSnapshot(snapshot: TenantSnapshot): EvidenceModel {
  if (!snapshot.tenant.tenantId || !snapshot.id) throw new Error("A tenant and snapshot are required.");
  timestamp(snapshot.scannedAt);
  if (snapshot.nodes.length > 100_000 || snapshot.edges.length > 500_000) throw new Error("Snapshot exceeds engine input limits.");
  for (const record of [...snapshot.nodes, ...snapshot.edges]) {
    if (record.tenantId !== snapshot.tenant.tenantId) throw new Error("Cross-tenant evidence rejected.");
    if (!record.id) throw new Error("Every fact requires an ID.");
  }
  const conflicts: Conflict[] = [];
  const nodes = deduplicate(snapshot.nodes.map(projectNode), "object", conflicts);
  const edges = deduplicate(snapshot.edges.map(projectEdge), "relationship", conflicts);
  const coverage = deduplicate((snapshot.completion.collectors ?? []).map(c => ({
    id: c.id, state: c.state, reason: "Recorded collection boundary.", collectedAt: c.collectedAt,
    endpoints: unique(c.endpoints), failedEndpoints: unique(c.failedEndpoints), itemCount: c.itemCount, scope: c.scope,
    ...(c.limits ? { limits: { ...c.limits } } : {}),
    ...(c.window ? { window: { ...c.window, eventClasses: unique(c.window.eventClasses) } } : {}),
  })), "coverage", conflicts);
  return immutable({ tenantId: snapshot.tenant.tenantId, snapshotIds: [snapshot.id], engineVersion: ENGINE_VERSION,
    ruleVersion: RULE_VERSION, collectedAt: [snapshot.scannedAt], nodes, edges, coverage, conflicts });
}

export function context(model: EngineContext): EngineContext {
  return { tenantId: model.tenantId, snapshotIds: [...model.snapshotIds], engineVersion: model.engineVersion, ruleVersion: model.ruleVersion, collectedAt: [...model.collectedAt] };
}

export function assertTenant(model: EngineContext, tenantId: string): void {
  if (tenantId !== model.tenantId) throw new Error("Cross-tenant query rejected.");
}

export function complete(model: EvidenceModel, collector: string): boolean {
  const coverage = model.coverage.find(c => c.id === collector);
  return coverage?.state === "complete" && coverage.failedEndpoints.length === 0 && !model.conflicts.some(c => c.factId === `coverage:${collector}`);
}
