import { cleanProjectFixture, relationships, type RelationshipView } from "@entra-explorer/domain";
import { expect, it } from "vitest";
import { layoutGraph, NODE_HEIGHT, NODE_WIDTH, type GraphLayout } from "../components/graph-layout";

function graph(nodeCount: number, connections: [number, number][]) {
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.nodes = Array.from({ length: nodeCount }, (_, index) => ({
    ...snapshot.nodes[0]!, id: `layout-node-${index}`, label: `Synthetic identity ${index}`,
  }));
  snapshot.edges = connections.map(([source, target], index) => ({
    ...snapshot.edges[0]!, id: `layout-edge-${index}`,
    sourceId: snapshot.nodes[source]!.id, targetId: snapshot.nodes[target]!.id,
  }));
  return { nodes: snapshot.nodes, views: relationships(snapshot) };
}

function expectComplete(layout: GraphLayout, views: RelationshipView[], nodeCount: number) {
  expect(layout.nodes).toHaveLength(nodeCount);
  expect(new Set(layout.nodes.map(({ node }) => node.id)).size).toBe(nodeCount);
  expect(layout.edges.map(({ view }) => view.edge.id)).toEqual(views.map(({ edge }) => edge.id));
  expect(Number.isFinite(layout.width)).toBe(true);
  expect(Number.isFinite(layout.height)).toBe(true);
  for (const { x, y } of layout.nodes) {
    expect(Number.isFinite(x) && Number.isFinite(y)).toBe(true);
    expect(x).toBeGreaterThanOrEqual(0);
    expect(y).toBeGreaterThanOrEqual(0);
    expect(x + NODE_WIDTH).toBeLessThanOrEqual(layout.width);
    expect(y + NODE_HEIGHT).toBeLessThanOrEqual(layout.height);
  }
  for (const { path, label } of layout.edges) {
    expect(path).toMatch(/^M /);
    expect(path).not.toMatch(/NaN|Infinity/);
    expect(Number.isFinite(label.x) && Number.isFinite(label.y)).toBe(true);
  }
}

it("keeps a bounded 15-node cycle in a compact column without losing relationships", () => {
  const { nodes, views } = graph(15, Array.from({ length: 15 }, (_, index) => [index, (index + 1) % 15]));
  const layout = layoutGraph(nodes, views);
  expectComplete(layout, views, nodes.length);
  expect(new Set(layout.nodes.map(({ x }) => x)).size).toBe(1);
  expect(layout.width).toBeLessThan(NODE_WIDTH * 2);
  expect(layout.height).toBeLessThan(nodes.length * NODE_HEIGHT * 2);
});

it("layers incoming and outgoing paths around separate cycles without empty columns", () => {
  const { nodes, views } = graph(8, [[0, 1], [1, 2], [2, 1], [2, 3], [0, 3], [3, 4], [4, 5], [5, 4], [5, 6]]);
  const layout = layoutGraph(nodes, views);
  expectComplete(layout, views, nodes.length);
  const x = layout.nodes.map(({ x }) => x);
  expect(x[1]).toBe(x[2]);
  expect(x[4]).toBe(x[5]);
  expect(x[7]).toBe(x[0]);
  const columns = [x[0]!, x[1]!, x[3]!, x[4]!, x[6]!];
  expect(columns).toEqual([...new Set(x)].sort((a, b) => a - b));
  const spacing = columns[1]! - columns[0]!;
  expect(spacing).toBeGreaterThan(NODE_WIDTH);
  for (let index = 2; index < columns.length; index += 1) {
    expect(columns[index]! - columns[index - 1]!).toBe(spacing);
  }
  expect(layout.width).toBeLessThan(NODE_WIDTH * 10);
  expect(layoutGraph(nodes, [...views].reverse()).nodes.map(({ x }) => x)).toEqual(x);
});

it("retains longest-path layering for a DAG with shortcuts, duplicate connections and disconnected objects", () => {
  const { nodes, views } = graph(10, [[0, 1], [0, 1], [0, 2], [1, 3], [2, 3], [3, 4], [0, 4], [5, 6], [8, 8], [4, 9], [9, 0]]);
  // The two connections through an excluded object must not turn the visible DAG into a cycle.
  const visible = nodes.slice(0, 9);
  const internal = views.slice(0, -2);
  const layout = layoutGraph(visible, [...views].reverse());
  expectComplete(layout, [...internal].reverse(), visible.length);
  const x = layout.nodes.map(({ x }) => x);
  expect(x[0]).toBe(x[5]);
  expect(x[0]).toBe(x[7]);
  expect(x[0]).toBe(x[8]);
  expect(x[1]).toBe(x[2]);
  expect(x[1]).toBe(x[6]);
  expect(x[1]).toBeGreaterThan(x[0]!);
  expect(x[3]).toBeGreaterThan(x[1]!);
  expect(x[4]).toBeGreaterThan(x[3]!);
  expect(new Set(x).size).toBe(4);
});

it("preserves isolated objects and self-connections without adding columns", () => {
  const { nodes, views } = graph(3, [[0, 0], [1, 1], [1, 1]]);
  const layout = layoutGraph(nodes, views);
  expectComplete(layout, views, nodes.length);
  expect(new Set(layout.nodes.map(({ x }) => x)).size).toBe(1);
  expect(new Set(layout.nodes.map(({ y }) => y)).size).toBe(3);
  expect(layout.width).toBeLessThan(NODE_WIDTH * 2);
  expect(layoutGraph([], views)).toEqual({ width: 72, height: 72, nodes: [], edges: [] });
});

it("keeps every three-object directed graph compact and preserves acyclic edge direction", () => {
  const possible: [number, number][] = [[0, 1], [0, 2], [1, 0], [1, 2], [2, 0], [2, 1]];
  for (let mask = 0; mask < 2 ** possible.length; mask += 1) {
    const connections = possible.filter((_, index) => mask & (1 << index));
    const { nodes, views } = graph(3, connections);
    const layout = layoutGraph(nodes, views);
    expectComplete(layout, views, nodes.length);
    // Independent reachability oracle: a mutually reachable pair belongs to one cycle.
    const reachable = Array.from({ length: 3 }, (_, source) =>
      Array.from({ length: 3 }, (_, target) => source === target || connections.some(([from, to]) => from === source && to === target)));
    for (let via = 0; via < 3; via += 1) {
      for (let from = 0; from < 3; from += 1) {
        for (let to = 0; to < 3; to += 1) {
          reachable[from]![to] ||= reachable[from]![via]! && reachable[via]![to]!;
        }
      }
    }
    for (const [from, to] of connections) {
      if (reachable[to]![from]) expect(layout.nodes[from]!.x).toBe(layout.nodes[to]!.x);
      else expect(layout.nodes[from]!.x).toBeLessThan(layout.nodes[to]!.x);
    }
    expect(layout.width).toBeLessThan(NODE_WIDTH * 6);
  }
});
