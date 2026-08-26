import { describe, expect, it } from "vitest";
import {
  assertTenantBoundary,
  boundedNeighborhood,
  cleanProjectFixture,
  compareSnapshots,
  filterRelationships,
  fixtureScannedAt,
  fixtureTenantId,
  relationships,
  type DirectoryNode,
  type RelationshipEdge,
  type TenantSnapshot,
} from "./index";

describe("fixture relationship contract", () => {
  it("keeps every record inside one tenant", () => {
    expect(() => assertTenantBoundary(cleanProjectFixture)).not.toThrow();
  });

  it("makes every relationship explainable", () => {
    for (const { edge } of relationships(cleanProjectFixture)) {
      expect(edge.evidence.sourceObjectId).toBe(edge.sourceId);
      expect(edge.evidence.targetObjectId).toBe(edge.targetId);
      expect(edge.evidence.sourceEndpoint).toBeTruthy();
      expect(edge.evidence.sourceRecordIds.length).toBeGreaterThan(0);
      expect(edge.evidence.scannedAt).toBe(cleanProjectFixture.scannedAt);
    }
  });

  it("does not imply that configured access was observed", () => {
    const configuredAccess = cleanProjectFixture.edges.filter((edge) => edge.evidence.configured);
    expect(configuredAccess.length).toBeGreaterThan(0);
    expect(configuredAccess.every((edge) => edge.evidence.observed === null)).toBe(true);
  });

  it("finds the Clean Project application permission edge", () => {
    const results = filterRelationships(cleanProjectFixture, { query: "Api.Write" });
    expect(results).toHaveLength(1);
    expect(results[0]?.edge.type).toBe("CAN_CALL_AS_APP");
  });
});

describe("snapshot comparison", () => {
  it("reports added, removed, and materially changed records without treating scan time as a change", () => {
    const before = structuredClone(cleanProjectFixture);
    const after = structuredClone(cleanProjectFixture);
    after.id = "newer";
    after.scannedAt = "2026-08-27T10:00:00.000Z";
    after.nodes[0]!.label = "Renamed API";
    after.nodes.pop();
    after.nodes.push({ ...structuredClone(before.nodes[0]!), id: "added-node", label: "Added identity" });
    after.edges = after.edges.filter((edge) => edge.sourceId !== before.nodes.at(-1)!.id && edge.targetId !== before.nodes.at(-1)!.id);
    const diff = compareSnapshots(before, after);
    expect(diff.counts.added).toBe(1);
    expect(diff.counts.removed).toBeGreaterThanOrEqual(1);
    expect(diff.counts.changed).toBe(1);
  });

  it("rejects cross-tenant comparison", () => {
    const other = structuredClone(cleanProjectFixture);
    other.tenant.tenantId = "22222222-2222-4222-8222-222222222222";
    other.nodes = other.nodes.map((node) => ({ ...node, tenantId: other.tenant.tenantId }));
    other.edges = other.edges.map((edge) => ({ ...edge, tenantId: other.tenant.tenantId }));
    expect(() => compareSnapshots(cleanProjectFixture, other)).toThrow(/different tenants/i);
  });
});

describe("large tenant safeguards", () => {
  it("bounds one-hop rendering for a 10,000-application tenant", () => {
    const nodeCount = 10_000;
    const nodes: DirectoryNode[] = Array.from({ length: nodeCount }, (_, index) => ({
      id: `node-${index}`,
      tenantId: fixtureTenantId,
      kind: "servicePrincipal",
      label: `Synthetic identity ${index}`,
      description: "Scale fixture",
      ownerIds: [],
      risk: { level: "low", reason: "Synthetic scale record." },
    }));
    const edges: RelationshipEdge[] = nodes.slice(1).map((node, index) => ({
      id: `edge-${index}`,
      tenantId: fixtureTenantId,
      type: "CAN_CALL_AS_APP",
      sourceId: node.id,
      targetId: nodes[0]!.id,
      plainLabel: "Can call",
      permissions: ["Synthetic.Read"],
      evidence: {
        configured: true,
        observed: null,
        scannedAt: fixtureScannedAt,
        sourceEndpoint: "/synthetic-scale-fixture",
        sourceRecordIds: [`edge-${index}`],
        sourceObjectId: node.id,
        targetObjectId: nodes[0]!.id,
        completeness: "complete",
      },
    }));
    const snapshot: TenantSnapshot = {
      id: "large-fixture",
      tenant: { tenantId: fixtureTenantId, tenantLabel: "Large fixture" },
      scannedAt: fixtureScannedAt,
      mode: "fixture",
      completion: { status: "complete", collectedEndpoints: ["/synthetic-scale-fixture"], skippedEndpoints: [], errors: [] },
      nodes,
      edges,
    };

    const startedAt = performance.now();
    const result = boundedNeighborhood(snapshot, nodes[0]!.id, 200);
    const elapsedMs = performance.now() - startedAt;
    expect(result.nodes).toHaveLength(200);
    expect(result.edges).toHaveLength(199);
    expect(result.truncated).toBe(true);
    expect(elapsedMs).toBeLessThan(2_000);
  });

  it("rejects an unbounded visible-node request", () => {
    expect(() => boundedNeighborhood(cleanProjectFixture, cleanProjectFixture.nodes[0]!.id, 501)).toThrow(RangeError);
  });
});
