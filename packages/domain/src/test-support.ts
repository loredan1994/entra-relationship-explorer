import type { DirectoryNode, RelationshipEdge, RelationshipEvidence, RelationshipType, TenantSnapshot } from "./types";

/**
 * Test fixture builders. Excluded from mutation and coverage reports: this file
 * exists only to let tests assemble precise snapshots that exercise one branch
 * at a time, so a surviving mutant points at a real assertion gap rather than at
 * an unreachable combination of directory objects.
 */

export const TENANT = "c0000000-0000-4000-8000-000000000000";

let counter = 0;
const nextId = (prefix: string) => `${prefix}-${(counter += 1).toString(16).padStart(4, "0")}`;

export function node(partial: Partial<DirectoryNode> & Pick<DirectoryNode, "kind" | "label">): DirectoryNode {
  return {
    id: partial.id ?? nextId(partial.kind),
    tenantId: partial.tenantId ?? TENANT,
    description: partial.description ?? `${partial.label} description`,
    ownerIds: partial.ownerIds ?? [],
    risk: partial.risk ?? { level: "low", reason: "Test record." },
    ...partial,
  };
}

/**
 * `evidence` is accepted piecemeal; every field left out takes a stable default.
 * `type` is omitted deliberately: it comes from the positional argument, so allowing
 * it here would let an override be silently dropped.
 */
export type EdgeOverrides = Partial<Omit<RelationshipEdge, "evidence" | "type">> & { evidence?: Partial<RelationshipEvidence> };

export function edge(
  type: RelationshipType,
  source: DirectoryNode,
  target: DirectoryNode,
  partial: EdgeOverrides = {},
): RelationshipEdge {
  return {
    id: partial.id ?? nextId("edge"),
    tenantId: TENANT,
    type,
    sourceId: source.id,
    targetId: target.id,
    plainLabel: partial.plainLabel ?? type.replaceAll("_", " ").toLowerCase(),
    permissions: partial.permissions ?? [],
    evidence: {
      configured: true,
      observed: null,
      scannedAt: "2026-08-26T10:00:00.000Z",
      sourceEndpoint: partial.evidence?.sourceEndpoint ?? "/test-endpoint",
      sourceRecordIds: partial.evidence?.sourceRecordIds ?? [nextId("rec")],
      sourceObjectId: source.id,
      targetObjectId: target.id,
      completeness: partial.evidence?.completeness ?? "complete",
      ...partial.evidence,
    },
  };
}

export function snapshot(
  nodes: DirectoryNode[],
  edges: RelationshipEdge[],
  partial: Partial<TenantSnapshot> = {},
): TenantSnapshot {
  return {
    id: partial.id ?? "snapshot-test",
    tenant: partial.tenant ?? { tenantId: TENANT, tenantLabel: "Test tenant" },
    scannedAt: partial.scannedAt ?? "2026-08-26T10:00:00.000Z",
    mode: partial.mode ?? "tenant",
    completion: partial.completion ?? {
      status: "complete",
      collectedEndpoints: ["/applications", "/servicePrincipals"],
      skippedEndpoints: [],
      errors: [],
    },
    nodes,
    edges,
  };
}
