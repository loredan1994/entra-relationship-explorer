import { assertTenantBoundary } from "./queries";
import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "./types";

export type SnapshotChangeKind = "added" | "removed" | "changed";
export type SnapshotChangeSubject = "object" | "relationship";

export interface SnapshotChange {
  id: string;
  kind: SnapshotChangeKind;
  subject: SnapshotChangeSubject;
  label: string;
  detail: string;
}

export interface SnapshotDiff {
  tenantId: string;
  beforeSnapshotId: string;
  afterSnapshotId: string;
  beforeScannedAt: string;
  afterScannedAt: string;
  changes: SnapshotChange[];
  counts: Record<SnapshotChangeKind, number>;
}

export function compareSnapshots(before: TenantSnapshot, after: TenantSnapshot): SnapshotDiff {
  assertTenantBoundary(before);
  assertTenantBoundary(after);
  if (before.tenant.tenantId !== after.tenant.tenantId) throw new Error("Snapshots from different tenants cannot be compared.");
  if (new Date(before.scannedAt).getTime() > new Date(after.scannedAt).getTime()) {
    throw new Error("The comparison snapshots must be ordered from older to newer.");
  }

  const changes = [
    ...compareRecords(before.nodes, after.nodes, "object", nodeLabel, nodeFingerprint),
    ...compareRecords(before.edges, after.edges, "relationship", edgeLabel, edgeFingerprint),
  ].sort((left, right) => `${left.subject}:${left.label}:${left.kind}`.localeCompare(`${right.subject}:${right.label}:${right.kind}`));

  return {
    tenantId: after.tenant.tenantId,
    beforeSnapshotId: before.id,
    afterSnapshotId: after.id,
    beforeScannedAt: before.scannedAt,
    afterScannedAt: after.scannedAt,
    changes,
    counts: {
      added: changes.filter((change) => change.kind === "added").length,
      removed: changes.filter((change) => change.kind === "removed").length,
      changed: changes.filter((change) => change.kind === "changed").length,
    },
  };
}

function compareRecords<T extends { id: string }>(
  before: T[],
  after: T[],
  subject: SnapshotChangeSubject,
  label: (record: T) => string,
  fingerprint: (record: T) => string,
): SnapshotChange[] {
  const previous = new Map(before.map((record) => [record.id, record]));
  const current = new Map(after.map((record) => [record.id, record]));
  const changes: SnapshotChange[] = [];
  for (const record of after) {
    const old = previous.get(record.id);
    if (!old) changes.push({ id: record.id, kind: "added", subject, label: label(record), detail: `${subject === "object" ? "Object" : "Relationship"} appeared in the newer snapshot.` });
    else if (fingerprint(old) !== fingerprint(record)) changes.push({ id: record.id, kind: "changed", subject, label: label(record), detail: `${subject === "object" ? "Object metadata" : "Configured relationship data"} changed.` });
  }
  for (const record of before) {
    if (!current.has(record.id)) changes.push({ id: record.id, kind: "removed", subject, label: label(record), detail: `${subject === "object" ? "Object" : "Relationship"} is absent from the newer snapshot.` });
  }
  return changes;
}

function nodeLabel(node: DirectoryNode): string {
  return node.label;
}

function nodeFingerprint(node: DirectoryNode): string {
  return JSON.stringify({ kind: node.kind, label: node.label, description: node.description, appId: node.appId, publisher: node.publisher, metadata: node.metadata, ownerIds: [...node.ownerIds].sort(), credential: node.credential, risk: node.risk });
}

function edgeLabel(edge: RelationshipEdge): string {
  return `${edge.type}: ${edge.sourceId} → ${edge.targetId}`;
}

function edgeFingerprint(edge: RelationshipEdge): string {
  return JSON.stringify({ type: edge.type, sourceId: edge.sourceId, targetId: edge.targetId, permissions: [...edge.permissions].sort(), scope: edge.scope, configured: edge.evidence.configured, sourceEndpoint: edge.evidence.sourceEndpoint, sourceRecordIds: [...edge.evidence.sourceRecordIds].sort(), completeness: edge.evidence.completeness });
}
