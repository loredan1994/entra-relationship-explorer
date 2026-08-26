import type { DirectoryNode, NodeKind, RelationshipType, RelationshipView, TenantSnapshot } from "./types";

export interface RelationshipFilters {
  query?: string;
  nodeKinds?: NodeKind[];
  relationshipTypes?: RelationshipType[];
}

export function relationships(snapshot: TenantSnapshot): RelationshipView[] {
  const nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));

  return snapshot.edges.flatMap((edge) => {
    const source = nodes.get(edge.sourceId);
    const target = nodes.get(edge.targetId);
    if (!source || !target) return [];
    return [{ edge, source, target }];
  });
}

export function filterRelationships(snapshot: TenantSnapshot, filters: RelationshipFilters): RelationshipView[] {
  const query = filters.query?.trim().toLocaleLowerCase() ?? "";

  return relationships(snapshot).filter(({ edge, source, target }) => {
    const matchesKind =
      !filters.nodeKinds?.length || filters.nodeKinds.includes(source.kind) || filters.nodeKinds.includes(target.kind);
    const matchesRelationship = !filters.relationshipTypes?.length || filters.relationshipTypes.includes(edge.type);
    const haystack = [source.label, target.label, edge.plainLabel, ...edge.permissions].join(" ").toLocaleLowerCase();
    return matchesKind && matchesRelationship && (!query || haystack.includes(query));
  });
}

export function connectedNodes(views: RelationshipView[]): DirectoryNode[] {
  return Array.from(new Map(views.flatMap(({ source, target }) => [[source.id, source], [target.id, target]])).values());
}

export function nodeById(snapshot: TenantSnapshot, id: string): DirectoryNode | undefined {
  return snapshot.nodes.find((node) => node.id === id);
}

export function boundedNeighborhood(
  snapshot: TenantSnapshot,
  focusNodeId: string,
  maxNodes = 200,
): { nodes: DirectoryNode[]; edges: RelationshipView[]; truncated: boolean } {
  if (!Number.isInteger(maxNodes) || maxNodes < 1 || maxNodes > 500) {
    throw new RangeError("Visible graph node limit must be between 1 and 500.");
  }

  const nodeIndex = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const focus = nodeIndex.get(focusNodeId);
  if (!focus) return { nodes: [], edges: [], truncated: false };

  const connected = relationships(snapshot).filter(
    ({ source, target }) => source.id === focusNodeId || target.id === focusNodeId,
  );
  const visibleIds = new Set<string>([focusNodeId]);
  const visibleEdges: RelationshipView[] = [];

  for (const view of connected) {
    const neighborId = view.source.id === focusNodeId ? view.target.id : view.source.id;
    if (!visibleIds.has(neighborId) && visibleIds.size >= maxNodes) continue;
    visibleIds.add(neighborId);
    visibleEdges.push(view);
  }

  return {
    nodes: Array.from(visibleIds, (id) => nodeIndex.get(id)).filter((node): node is DirectoryNode => Boolean(node)),
    edges: visibleEdges,
    truncated: visibleEdges.length < connected.length,
  };
}

export function assertTenantBoundary(snapshot: TenantSnapshot): void {
  const tenantId = snapshot.tenant.tenantId;
  const invalidNode = snapshot.nodes.find((node) => node.tenantId !== tenantId);
  const invalidEdge = snapshot.edges.find((edge) => edge.tenantId !== tenantId);
  if (invalidNode || invalidEdge) {
    throw new Error("Snapshot records must belong to exactly one tenant.");
  }
}
