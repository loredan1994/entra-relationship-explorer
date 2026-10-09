import { expect, it } from "vitest";
import { cleanProjectFixture, connectedNodes, filterRelationships, type TenantSnapshot } from "@entra-explorer/domain";
import { MAP_EDGE_LIMIT, MAP_NODE_LIMIT, relationshipMapScope } from "../components/relationship-map-scope";

function inventory(count: number, parallel = false): TenantSnapshot {
  const base = cleanProjectFixture.edges[0]!;
  const caller = cleanProjectFixture.nodes.find(node => node.id === base.sourceId)!;
  const resource = cleanProjectFixture.nodes.find(node => node.id === base.targetId)!;
  const nodes = [caller, ...Array.from({ length: parallel ? 1 : count }, (_, index) => ({ ...resource, id: `resource-${index}`, label: `Resource ${index}` }))];
  return {
    ...cleanProjectFixture, nodes,
    edges: Array.from({ length: count }, (_, index) => ({ ...base, id: `edge-${index}`, targetId: nodes[parallel ? 1 : index + 1]!.id, permissions: [`Synthetic.Permission.${index}`] })),
  };
}

it("bounds parallel relationship labels while preserving the requested late edge and complete input", () => {
  const snapshot = inventory(5000, true);
  const views = filterRelationships(snapshot, {});
  const scope = relationshipMapScope(views, snapshot.nodes[0]!.id, "edge-4999");
  expect(scope.views).toHaveLength(MAP_EDGE_LIMIT);
  expect(connectedNodes(scope.views)).toHaveLength(2);
  expect(scope.views.at(-1)?.edge.id).toBe("edge-4999");
  expect(scope.views[0]?.edge.id).toBe("edge-0");
  expect(scope.availableCount).toBe(5000);
  expect(scope.truncated).toBe(true);
  expect(views).toHaveLength(5000);
  expect(snapshot.edges).toHaveLength(5000);
});

it("keeps a selected relationship beyond the object budget without retaining unrelated edges", () => {
  const snapshot = inventory(100);
  const scope = relationshipMapScope(filterRelationships(snapshot, {}), snapshot.nodes[0]!.id, "edge-99");
  expect(connectedNodes(scope.views)).toHaveLength(MAP_NODE_LIMIT);
  expect(scope.views.map(view => view.edge.id)).toEqual([...Array.from({ length: 13 }, (_, index) => `edge-${index}`), "edge-99"]);
  expect(scope.availableCount).toBe(100);
  expect(scope.truncated).toBe(true);
});

it("searches the complete inventory before bounding the selected object's neighborhood", () => {
  const snapshot = inventory(100);
  const matching = filterRelationships(snapshot, { query: "Synthetic.Permission.99" });
  const scope = relationshipMapScope(matching, snapshot.nodes[0]!.id, "edge-99");
  expect(scope.views.map(view => view.edge.id)).toEqual(["edge-99"]);
  expect(connectedNodes(scope.views).map(node => node.id)).toEqual([snapshot.nodes[0]!.id, "resource-99"]);
  expect(scope.availableCount).toBe(1);
  expect(scope.truncated).toBe(false);
});

it("retains exact small inventories, handles self-relationships and rejects missing focus", () => {
  const views = filterRelationships(cleanProjectFixture, {});
  expect(relationshipMapScope(views, null)).toEqual({ views, availableCount: views.length, truncated: false });
  expect(relationshipMapScope(views, "absent", views[0]!.edge.id)).toEqual({ views: [], availableCount: 0, truncated: false });
  const view = views[0]!;
  const self = { ...view, target: view.source, edge: { ...view.edge, targetId: view.source.id } };
  expect(relationshipMapScope([self], view.source.id).views).toEqual([self]);
});
