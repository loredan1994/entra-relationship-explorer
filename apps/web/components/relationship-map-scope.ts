import type { RelationshipView } from "@entra-explorer/domain";

export const MAP_NODE_LIMIT = 15;
export const MAP_EDGE_LIMIT = 50;

/** Bound visual work after filtering, retaining the relationship being opened. */
export function relationshipMapScope(views: RelationshipView[], focusNodeId: string | null, anchorEdgeId?: string) {
  const candidates = focusNodeId
    ? views.filter(({ source, target }) => source.id === focusNodeId || target.id === focusNodeId)
    : views;
  const selected = candidates.find(({ edge }) => edge.id === anchorEdgeId);
  const nodes = new Set<string>();
  const edges = new Set<string>();
  function include(view: RelationshipView) {
    const additionalNodes = Number(!nodes.has(view.source.id)) + Number(view.source.id !== view.target.id && !nodes.has(view.target.id));
    if (nodes.size + additionalNodes > MAP_NODE_LIMIT || edges.size >= MAP_EDGE_LIMIT) return;
    nodes.add(view.source.id);
    nodes.add(view.target.id);
    edges.add(view.edge.id);
  }
  if (selected) include(selected);
  for (const view of candidates) {
    if (edges.size >= MAP_EDGE_LIMIT) break;
    include(view);
  }
  return {
    views: candidates.filter(({ edge }) => edges.has(edge.id)),
    availableCount: candidates.length,
    truncated: edges.size < candidates.length,
  };
}
