import type { RelationshipEdge } from "@entra-explorer/domain";
import { canonical, compare, timestamp, unique } from "./canonical";
import { evaluateAuthorization, pathMissing } from "./authorization";
import { assertTenant, context } from "./model";
import type { AuthorizationQuery, EvidenceModel, TimeWindow, WorkflowResult } from "./types";

export interface TemporalPath {
  edges: string[];
  snapshots: string[];
  collectedInstants: string[];
  sourceValidity: TimeWindow | null;
  validity: "overlap" | "disjoint" | "unknown";
  uncertainIntervals: TimeWindow[];
}
export interface TemporalResult extends WorkflowResult { paths: TemporalPath[]; auditContext: "not-used-to-infer-continuity" }

export function intersectWindows(windows: TimeWindow[]): TimeWindow | null {
  if (!windows.length) return null;
  const starts = windows.map(w => timestamp(w.startsAt));
  const ends = windows.map(w => timestamp(w.endsAt));
  if (windows.some((_, i) => starts[i]! >= ends[i]!)) throw new Error("Intervals must have a start before their exclusive end.");
  const start = Math.max(...starts), end = Math.min(...ends);
  return start < end ? { startsAt: new Date(start).toISOString(), endsAt: new Date(end).toISOString() } : null;
}

function validity(edges: RelationshipEdge[]): { sourceValidity: TimeWindow | null; validity: TemporalPath["validity"] } {
  let start = -Infinity, end = Infinity, complete = true;
  for (const edge of edges) {
    const lower = edge.validity?.startsAt == null ? -Infinity : timestamp(edge.validity.startsAt);
    const upper = edge.validity?.endsAt == null ? Infinity : timestamp(edge.validity.endsAt);
    if (lower >= upper) throw new Error("Intervals must have a start before their exclusive end.");
    start = Math.max(start, lower); end = Math.min(end, upper);
    complete &&= Number.isFinite(lower) && Number.isFinite(upper);
  }
  // A known start after another edge's exclusive end disproves coexistence,
  // even when the remaining bounds were not collected.
  if (start >= end) return { sourceValidity: null, validity: "disjoint" };
  const sourceValidity = Number.isFinite(start) && Number.isFinite(end)
    ? { startsAt: new Date(start).toISOString(), endsAt: new Date(end).toISOString() } : null;
  return { sourceValidity, validity: complete ? "overlap" : "unknown" };
}

/** Never union different snapshots to manufacture a path. No continuity is inferred between scans. */
export function reconstructPaths(history: EvidenceModel[], query: AuthorizationQuery): TemporalResult {
  if (!history.length || history.length > 100) throw new Error("Temporal analysis requires 1 to 100 snapshots.");
  history.forEach(m => assertTenant(m, query.tenantId));
  const ordered = [...history].sort((a, b) => timestamp(a.collectedAt[0]!) - timestamp(b.collectedAt[0]!) || compare(a.snapshotIds[0]!, b.snapshotIds[0]!));
  const groups = new Map<string, TemporalPath>();
  const missing: string[] = [];
  let steps = 0, exhausted = false, uncertain = false, completeWitness = false;
  for (const model of ordered) {
    const proof = evaluateAuthorization(model, query);
    steps += proof.limits.steps; exhausted ||= proof.limits.exhausted;
    missing.push(...proof.missing, ...proof.conflicts.map(c => c.factId));
    if (proof.verdict === "unknown" || proof.verdict === "conflicting") {
      uncertain = true;
    }
    const edgesById = new Map(model.edges.map(edge => [edge.id, edge]));
    for (const path of proof.paths) {
      const edges = path.map(id => edgesById.get(id)!);
      // Same IDs with changed semantics are distinct temporal paths.
      const key = canonical(edges.map(e => ({ id: e.id, type: e.type, source: e.sourceId, target: e.targetId, permissionIds: e.permissionIds, consent: e.consent, scope: e.scope, validity: e.validity })));
      const temporal = groups.get(key) ?? { edges: path, snapshots: [], collectedInstants: [], ...validity(edges), uncertainIntervals: [] };
      // Authorization can be supported by one complete path while returning
      // incomplete alternatives. Temporal compatibility needs its own complete
      // witness; a disjoint complete path cannot validate another path's source.
      const gaps = pathMissing(query, edges);
      completeWitness ||= gaps.length === 0 && temporal.validity !== "disjoint";
      temporal.snapshots.push(...model.snapshotIds);
      temporal.collectedInstants.push(...model.collectedAt);
      groups.set(key, temporal);
    }
  }
  const paths = [...groups.values()].map(p => {
    const instants = unique(p.collectedInstants.map(instant => new Date(timestamp(instant)).toISOString()));
    return { ...p, snapshots: unique(p.snapshots), collectedInstants: instants,
      uncertainIntervals: instants.slice(1).map((end, i) => ({ startsAt: instants[i]!, endsAt: end })) };
  }).sort((a, b) => compare(canonical(a.edges), canonical(b.edges)));
  return { ...context(ordered[0]!), snapshotIds: unique(ordered.flatMap(m => m.snapshotIds)), collectedAt: unique(ordered.flatMap(m => m.collectedAt)),
    verdict: exhausted || uncertain ? "unknown" : completeWitness ? "supported" : missing.length ? "unknown" : paths.length ? "refuted" : "unknown",
    paths, auditContext: "not-used-to-infer-continuity", missing: unique([...missing, ...(!paths.length ? ["path-coexistence-between-observations"] : [])]),
    assumptions: ["A collected-snapshot witness assumes consistency of that scan; collection is not an atomic transaction.", "Source-declared validity intersects as half-open intervals. Repeated observations, event ordering, and missing audit windows do not prove uninterrupted existence."],
    limits: { steps, maxSteps: history.length * 50_000, exhausted } };
}
