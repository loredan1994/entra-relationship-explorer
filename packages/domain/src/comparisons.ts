import { endpointWasCollected } from "./coverage";
import { assertTenantBoundary } from "./queries";
import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "./types";

export type SnapshotChangeKind = "added" | "removed" | "changed" | "unconfirmed";
export type SnapshotChangeSubject = "object" | "relationship";

export interface SnapshotChange {
  id: string;
  kind: SnapshotChangeKind;
  subject: SnapshotChangeSubject;
  label: string;
  detail: string;
  fields?: Array<{ field: string; before: string; after: string; state?: "confirmed" | "unconfirmed"; reason?: string }>;
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
  if (![before.scannedAt, after.scannedAt].every(value => Number.isFinite(Date.parse(value)))) throw new Error("Comparison timestamps must be valid.");
  if (new Date(before.scannedAt).getTime() > new Date(after.scannedAt).getTime()) {
    throw new Error("The comparison snapshots must be ordered from older to newer.");
  }

  const changes = [
    ...compareRecords(before.nodes, after.nodes, "object", nodeLabel, nodeFingerprint),
    ...compareRecords(before.edges, after.edges, "relationship", edgeLabel, edgeFingerprint),
  ].sort((left, right) => `${left.subject}:${left.label}:${left.kind}`.localeCompare(`${right.subject}:${right.label}:${right.kind}`));
  for (const change of changes) {
    if (change.subject === "relationship" && change.fields) {
      const old = before.edges.find(edge => edge.id === change.id)!;
      const current = after.edges.find(edge => edge.id === change.id)!;
      for (const field of change.fields) {
        if ((field.field === "consent" && (!old.consent || !current.consent)) || (field.field === "permissionIds" && (!old.permissionIds || !current.permissionIds))) {
          field.state = "unconfirmed";
          field.reason = "This metadata was not collected in both snapshots.";
        }
      }
      if (change.fields.every(field => field.state === "unconfirmed")) {
        change.kind = "unconfirmed";
        change.detail = "Relationship metadata was not collected in both snapshots.";
      }
    }
    else if (change.fields) {
      const old = before.nodes.find(node => node.id === change.id)!;
      const current = after.nodes.find(node => node.id === change.id)!;
      for (const field of change.fields) {
        if (!objectFieldIsCovered(before, old, field.field) || !objectFieldIsCovered(after, current, field.field)) {
          field.state = "unconfirmed";
          field.reason = "The source for this field was not fully collected in both snapshots; the displayed difference may reflect missing evidence.";
        }
      }
      if (change.fields.every(field => field.state === "unconfirmed")) {
        change.kind = "unconfirmed";
        change.detail = "Field differences are unconfirmed because their source evidence is incomplete.";
      } else if (change.fields.some(field => field.state === "unconfirmed")) {
        change.detail = "Object metadata changed; some field differences remain unconfirmed.";
      }
    }
    if (change.kind === "removed" && !absenceCovered(before, after)) {
      change.kind = "unconfirmed";
      change.detail = "Absent from this scan; incomplete or reduced coverage cannot establish removal.";
    }
  }

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
      unconfirmed: changes.filter((change) => change.kind === "unconfirmed").length,
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
    else if (fingerprint(old) !== fingerprint(record)) changes.push({ id: record.id, kind: "changed", subject, label: label(record), detail: `${subject === "object" ? "Object metadata" : "Configured relationship data"} changed.`, fields: changedFields(fingerprint(old), fingerprint(record)) });
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
  return canonicalJson({ ...profileFields(node), kind: node.kind, label: node.label, description: node.description, appId: node.appId, publisher: node.publisher, isExternal: node.isExternal, permissionDefinitions: node.permissionDefinitions?.slice().sort((a,b) => canonicalJson(a).localeCompare(canonicalJson(b))), metadata: node.metadata, ownerIds: [...node.ownerIds].sort(), credential: node.credential, credentials: node.credentials?.slice().sort((a,b) => a.id.localeCompare(b.id)), requestedPermissions: node.requestedPermissions?.slice().sort((a,b) => canonicalJson(a).localeCompare(canonicalJson(b))), risk: node.risk });
}

function profileFields(node: DirectoryNode): Record<string, unknown> {
  return Object.fromEntries(Object.entries(node.applicationProfile ?? {}).map(([key, value]) => [`applicationProfile.${key}`, value]));
}

function edgeLabel(edge: RelationshipEdge): string {
  return `${edge.type}: ${edge.sourceId} → ${edge.targetId}`;
}

function edgeFingerprint(edge: RelationshipEdge): string {
  return canonicalJson({ type: edge.type, sourceId: edge.sourceId, targetId: edge.targetId, permissions: [...edge.permissions].sort(), permissionIds: edge.permissionIds?.slice().sort(), consent: edge.consent, scope: edge.scope, configured: edge.evidence.configured, sourceEndpoint: edge.evidence.sourceEndpoint, sourceRecordIds: [...edge.evidence.sourceRecordIds].sort(), completeness: edge.evidence.completeness });
}

function absenceCovered(before: TenantSnapshot, after: TenantSnapshot): boolean {
  if (after.completion.status !== "complete") return false;
  return before.completion.collectedEndpoints.every((endpoint) => endpointWasCollected(after, endpoint));
}

function changedFields(before: string, after: string): NonNullable<SnapshotChange["fields"]> {
  const left = JSON.parse(before) as Record<string, unknown>;
  const right = JSON.parse(after) as Record<string, unknown>;
  return [...new Set([...Object.keys(left), ...Object.keys(right)])].flatMap((field) => JSON.stringify(left[field]) === JSON.stringify(right[field]) ? [] : [{ field, before: JSON.stringify(left[field]) ?? "Not collected", after: JSON.stringify(right[field]) ?? "Not collected" }]);
}

/** Owner-dependent risk cannot be confirmed when owner collection failed. */
export function objectFieldIsCovered(snapshot: TenantSnapshot, node: DirectoryNode, field: string): boolean {
  if ((field === "credentials" && node.credentials === undefined) || (field === "requestedPermissions" && node.requestedPermissions === undefined) || (field === "permissionDefinitions" && node.permissionDefinitions === undefined)) return false;
  if (field.startsWith("applicationProfile.") && profileFields(node)[field] == null) return false;
  const inventory = node.sourceEndpoint ?? (node.kind === "federatedCredential" ? snapshot.edges.find(edge => edge.type === "FEDERATES_AS" && edge.sourceId === node.id)?.evidence.sourceEndpoint : undefined);
  const ownerPath = node.kind === "application" ? `/applications/${node.id}/owners`
    : ["servicePrincipal", "managedIdentity"].includes(node.kind) ? `/servicePrincipals/${node.id}/owners` : null;
  const endpoints = [...(inventory ? [inventory] : []), ...((field === "ownerIds" || field === "risk") && ownerPath ? [ownerPath] : [])];
  if (!endpoints.length) return snapshot.completion.status === "complete";
  return endpoints.every(endpoint => endpointWasCollected(snapshot, endpoint));
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
}
