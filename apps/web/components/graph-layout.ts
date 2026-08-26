import type { DirectoryNode, RelationshipType, RelationshipView } from "@entra-explorer/domain";
import cytoscape from "cytoscape";

export const NODE_WIDTH = 190;
export const NODE_HEIGHT = 96;

const COLUMN_GAP = 176;
const ROW_GAP = 28;
const PADDING = 36;
const NODE_CLEARANCE = 6;
const LABEL_HEIGHT = 24;
const LABEL_CHAR_WIDTH = 5.9;
const LABEL_CHROME = 20;
const LABEL_MIN_WIDTH = 38;
const LABEL_MAX_WIDTH = 128;
const ORDERING_SWEEPS = 4;

const shortRelationshipLabel: Record<RelationshipType, string> = {
  INSTANTIATES_AS: "same appId",
  CAN_CALL_AS_APP: "can call as app",
  CAN_CALL_DELEGATED: "delegated",
  ASSIGNED_TO: "assigned",
  EXPOSES_APP_ROLE: "exposes role",
  GRANTED_APP_ROLE: "granted role",
  MEMBER_OF: "member of",
  ACTIVE_IN_ROLE: "active role",
  ELIGIBLE_FOR_ROLE: "eligible role",
  GOVERNED_BY: "governed by",
  CROSS_TENANT_ACCESS: "partner setting",
  OWNS: "owns",
  OBSERVED_CALL: "called recently",
};

export interface Point {
  x: number;
  y: number;
}

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface PlacedNode {
  node: DirectoryNode;
  x: number;
  y: number;
}

export interface PlacedEdge {
  view: RelationshipView;
  path: string;
  label: {
    text: string;
    full: string;
    x: number;
    y: number;
    width: number;
  };
}

export interface GraphLayout {
  width: number;
  height: number;
  nodes: PlacedNode[];
  edges: PlacedEdge[];
}

/**
 * Longest-path layering. Bounded by the node count so a cyclic graph
 * terminates instead of relaxing forever.
 */
function assignLayers(nodeIds: string[], views: RelationshipView[]): Map<string, number> {
  const layers = new Map(nodeIds.map((id) => [id, 0]));
  for (let pass = 0; pass < nodeIds.length; pass += 1) {
    let changed = false;
    for (const { source, target } of views) {
      if (source.id === target.id) continue;
      const candidate = (layers.get(source.id) ?? 0) + 1;
      if (candidate > (layers.get(target.id) ?? 0)) {
        layers.set(target.id, candidate);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return layers;
}

/** Median heuristic: reorder each column so edges cross as little as possible. */
function orderLayers(columns: string[][], views: RelationshipView[]): string[][] {
  const predecessors = new Map<string, string[]>();
  const successors = new Map<string, string[]>();
  for (const { source, target } of views) {
    if (source.id === target.id) continue;
    successors.set(source.id, [...(successors.get(source.id) ?? []), target.id]);
    predecessors.set(target.id, [...(predecessors.get(target.id) ?? []), source.id]);
  }

  let ordered = columns.map((column) => [...column]);
  for (let sweep = 0; sweep < ORDERING_SWEEPS; sweep += 1) {
    const useIncoming = sweep % 2 === 0;
    const rowOf = new Map<string, number>();
    for (const column of ordered) column.forEach((id, row) => rowOf.set(id, row));

    ordered = ordered.map((column) =>
      column
        .map((id, row) => {
          const neighbours = (useIncoming ? predecessors.get(id) : successors.get(id)) ?? [];
          const rows = neighbours
            .map((neighbour) => rowOf.get(neighbour))
            .filter((value): value is number => value !== undefined)
            .sort((a, b) => a - b);
          return { id, row, median: rows.length ? rows[Math.floor(rows.length / 2)]! : row };
        })
        .sort((a, b) => a.median - b.median || a.row - b.row)
        .map((entry) => entry.id),
    );
  }
  return ordered;
}

/** Where a straight run from `center` toward `toward` leaves the node's box. */
function borderPoint(center: Point, toward: Point): Point {
  const dx = toward.x - center.x;
  const dy = toward.y - center.y;
  if (dx === 0 && dy === 0) return center;
  const scaleX = dx === 0 ? Number.POSITIVE_INFINITY : (NODE_WIDTH / 2 + NODE_CLEARANCE) / Math.abs(dx);
  const scaleY = dy === 0 ? Number.POSITIVE_INFINITY : (NODE_HEIGHT / 2 + NODE_CLEARANCE) / Math.abs(dy);
  const scale = Math.min(scaleX, scaleY, 1);
  return { x: center.x + dx * scale, y: center.y + dy * scale };
}

function labelText(view: RelationshipView): { text: string; full: string } {
  const { permissions, plainLabel, type } = view.edge;
  const full = permissions.length ? permissions.join(" · ") : plainLabel;
  if (permissions.length === 1) return { text: permissions[0]!, full };
  if (permissions.length > 1) return { text: `${permissions[0]!} +${permissions.length - 1}`, full };
  return { text: shortRelationshipLabel[type], full };
}

function labelWidth(text: string): number {
  return Math.min(LABEL_MAX_WIDTH, Math.max(LABEL_MIN_WIDTH, Math.round(text.length * LABEL_CHAR_WIDTH + LABEL_CHROME)));
}

function overlaps(a: Box, b: Box): boolean {
  return a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
}

/** Points along the curve to try, nearest the middle first. */
const LABEL_POSITIONS = [0.5, 0.4, 0.6, 0.3, 0.7, 0.22, 0.78];

/** Vertical nudges, alternating above and below the curve. */
const LABEL_NUDGES = [0, 1, -1, 2, -2, 3, -3, 4, -4, 5, -5].map((step) => step * (LABEL_HEIGHT + 2));

/** Covering a node card hides an object name, so it costs far more than crowding another label. */
const NODE_OVERLAP_COST = 10;
const LABEL_OVERLAP_COST = 1;

function cubicAt(t: number, p0: Point, c1: Point, c2: Point, p3: Point): Point {
  const inverse = 1 - t;
  const a = inverse * inverse * inverse;
  const b = 3 * inverse * inverse * t;
  const c = 3 * inverse * t * t;
  const d = t * t * t;
  return {
    x: a * p0.x + b * c1.x + c * c2.x + d * p3.x,
    y: a * p0.y + b * c1.y + c * c2.y + d * p3.y,
  };
}

export function layoutGraph(nodes: DirectoryNode[], views: RelationshipView[]): GraphLayout {
  if (nodes.length === 0) return { width: PADDING * 2, height: PADDING * 2, nodes: [], edges: [] };

  const present = new Set(nodes.map((node) => node.id));
  const internal = views.filter(({ source, target }) => present.has(source.id) && present.has(target.id));
  const cy = cytoscape({
    headless: true,
    styleEnabled: false,
    elements: [
      ...nodes.map((node) => ({ data: { id: node.id } })),
      ...internal.map((view) => ({ data: { id: view.edge.id, source: view.source.id, target: view.target.id } })),
    ],
  });
  const componentRank = new Map<string, number>();
  cy.elements().components().forEach((component, rank) => component.nodes().forEach((node) => { componentRank.set(node.id(), rank); }));
  cy.destroy();

  const layerOf = assignLayers(nodes.map((node) => node.id), internal);
  const columnCount = Math.max(...nodes.map((node) => layerOf.get(node.id) ?? 0)) + 1;
  const columns: string[][] = Array.from({ length: columnCount }, () => []);
  for (const node of nodes) columns[layerOf.get(node.id) ?? 0]!.push(node.id);
  for (const column of columns) column.sort((a, b) => (componentRank.get(a) ?? 0) - (componentRank.get(b) ?? 0));
  const ordered = orderLayers(columns, internal);
  const columnHeights = ordered.map((column) => column.length ? column.length * NODE_HEIGHT + (column.length - 1) * ROW_GAP : 0);
  const tallest = Math.max(NODE_HEIGHT, ...columnHeights);
  const topLeft = new Map<string, Point>();
  ordered.forEach((column, columnIndex) => {
    const offset = (tallest - columnHeights[columnIndex]!) / 2;
    column.forEach((id, row) => topLeft.set(id, { x: PADDING + columnIndex * (NODE_WIDTH + COLUMN_GAP), y: PADDING + offset + row * (NODE_HEIGHT + ROW_GAP) }));
  });
  const width = PADDING * 2 + columnCount * NODE_WIDTH + (columnCount - 1) * COLUMN_GAP;
  const height = PADDING * 2 + tallest;

  const centerOf = (id: string): Point => {
    const corner = topLeft.get(id) ?? { x: PADDING, y: PADDING };
    return { x: corner.x + NODE_WIDTH / 2, y: corner.y + NODE_HEIGHT / 2 };
  };

  // Labels must clear every node card, and each other.
  const nodeBoxes: Box[] = nodes.map((node) => {
    const corner = topLeft.get(node.id) ?? { x: PADDING, y: PADDING };
    return {
      x: corner.x - NODE_CLEARANCE,
      y: corner.y - NODE_CLEARANCE,
      width: NODE_WIDTH + NODE_CLEARANCE * 2,
      height: NODE_HEIGHT + NODE_CLEARANCE * 2,
    };
  });
  const labelBoxes: Box[] = [];

  const edges: PlacedEdge[] = internal.map((view) => {
    const sourceCenter = centerOf(view.source.id);
    const targetCenter = centerOf(view.target.id);
    const start = borderPoint(sourceCenter, targetCenter);
    const end = borderPoint(targetCenter, sourceCenter);

    const direction = end.x >= start.x ? 1 : -1;
    const span = Math.max(48, Math.abs(end.x - start.x) * 0.5);
    const control1 = { x: start.x + direction * span, y: start.y };
    const control2 = { x: end.x - direction * span, y: end.y };
    const path = `M ${start.x} ${start.y} C ${control1.x} ${control1.y}, ${control2.x} ${control2.y}, ${end.x} ${end.y}`;

    const { text, full } = labelText(view);
    const boxWidth = labelWidth(text);
    const boxAt = (t: number, nudge: number): Box => {
      const point = cubicAt(t, start, control1, control2, end);
      return {
        x: point.x - boxWidth / 2,
        y: point.y - LABEL_HEIGHT / 2 + nudge,
        width: boxWidth,
        height: LABEL_HEIGHT,
      };
    };

    const cost = (box: Box) =>
      nodeBoxes.reduce((total, taken) => total + (overlaps(box, taken) ? NODE_OVERLAP_COST : 0), 0) +
      labelBoxes.reduce((total, taken) => total + (overlaps(box, taken) ? LABEL_OVERLAP_COST : 0), 0);

    const candidates = LABEL_POSITIONS.flatMap((t) => LABEL_NUDGES.map((nudge) => boxAt(t, nudge)));
    let chosen = candidates[0]!;
    let chosenCost = cost(chosen);
    for (const candidate of candidates) {
      if (chosenCost === 0) break;
      const candidateCost = cost(candidate);
      if (candidateCost < chosenCost) {
        chosen = candidate;
        chosenCost = candidateCost;
      }
    }
    labelBoxes.push(chosen);

    return {
      view,
      path,
      label: { text, full, x: chosen.x + boxWidth / 2, y: chosen.y + LABEL_HEIGHT / 2, width: boxWidth },
    };
  });

  return {
    width,
    height,
    nodes: nodes.map((node) => {
      const corner = topLeft.get(node.id) ?? { x: PADDING, y: PADDING };
      return { node, x: corner.x, y: corner.y };
    }),
    edges,
  };
}
