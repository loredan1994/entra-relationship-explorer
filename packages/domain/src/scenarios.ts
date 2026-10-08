import { analyzeTenantIntelligence } from "./intelligence";
import { assertTenantBoundary } from "./queries";
import type { TenantSnapshot } from "./types";

export const SCENARIO_EDGE_TYPES = ["OWNS", "FEDERATES_AS", "MEMBER_OF", "CAN_CALL_AS_APP", "CAN_CALL_DELEGATED", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as const;
export const SCENARIO_PLAN_MAX_BYTES = 100_000;

/** The exported analysis is a convenience; imported results are always recomputed. */
export function createScenarioPlan(snapshot: TenantSnapshot, excludedEdgeIds: readonly string[]) {
  const result = simulateRemoval(snapshot, excludedEdgeIds);
  return { schemaVersion: 1, kind: "local-access-scenario", tenantId: snapshot.tenant.tenantId, snapshotId: snapshot.id, scannedAt: snapshot.scannedAt,
    excludedEdgeIds: result.excludedEdgeIds, removedPathIds: result.removedPaths.map(p => p.id), remainingPathIds: result.remainingPaths.map(p => p.id), complete: result.complete,
    caveat: "Hypothetical configured access only. No tenant change was made. Missing evidence can hide paths." };
}

export function importScenarioPlan(text: string, snapshot: TenantSnapshot): string[] {
  assertTenantBoundary(snapshot);
  if (new TextEncoder().encode(text).length > SCENARIO_PLAN_MAX_BYTES) throw new Error("Scenario plans must be at most 100 KB.");
  let input: unknown;
  try { input = JSON.parse(text); } catch { throw new Error("Choose a valid JSON scenario plan."); }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Expected a scenario plan object.");
  const plan = input as Record<string, unknown>;
  if (Object.keys(plan).some(key => !["schemaVersion", "kind", "tenantId", "snapshotId", "scannedAt", "excludedEdgeIds", "removedPathIds", "remainingPathIds", "complete", "caveat"].includes(key)) || plan.schemaVersion !== 1 || plan.kind !== "local-access-scenario") throw new Error("Unsupported scenario plan schema.");
  if (plan.tenantId !== snapshot.tenant.tenantId) throw new Error("This plan belongs to a different tenant.");
  if (plan.snapshotId !== snapshot.id || plan.scannedAt !== snapshot.scannedAt) throw new Error("This plan belongs to a different snapshot. Recreate it against the current evidence.");
  if (!Array.isArray(plan.excludedEdgeIds) || plan.excludedEdgeIds.length > 100 || plan.excludedEdgeIds.some(id => typeof id !== "string")) throw new Error("A plan must contain at most 100 relationship IDs.");
  return simulateRemoval(snapshot, plan.excludedEdgeIds).excludedEdgeIds;
}
export function simulateRemoval(snapshot: TenantSnapshot, excludedEdgeIds: readonly string[]) {
  assertTenantBoundary(snapshot);
  if (excludedEdgeIds.length > 100) throw new Error("A scenario can exclude at most 100 relationships.");
  const excluded = new Set(excludedEdgeIds);
  for (const id of excluded) {
    const edge = snapshot.edges.find(e => e.id === id);
    if (!edge || !(SCENARIO_EDGE_TYPES as readonly string[]).includes(edge.type) || !edge.evidence.configured) throw new Error(`Relationship ${id} cannot be changed in a scenario.`);
  }
  const baseline = analyzeTenantIntelligence(snapshot);
  const scenarioSnapshot: TenantSnapshot = { ...snapshot, edges: snapshot.edges.filter(e => !excluded.has(e.id)) };
  const scenario = analyzeTenantIntelligence(scenarioSnapshot);
  const remaining = new Set(scenario.paths.map(p => p.id));
  const before = new Set(baseline.paths.map(p => p.id));
  return { baseline, scenario, excludedEdgeIds: [...excluded], removedPaths: baseline.paths.filter(p => !remaining.has(p.id)), remainingPaths: scenario.paths, newPaths: scenario.paths.filter(p => !before.has(p.id)), complete: !baseline.pathAnalysis.truncated && !scenario.pathAnalysis.truncated && snapshot.completion.status === "complete", baselineTargets: [...new Set(baseline.paths.map(p => p.target.id))], scenarioTargets: [...new Set(scenario.paths.map(p => p.target.id))] };
}

/** Bounded candidate ranking, not an optimal cut or assurance that access is revoked. */
export function rankScenarioCuts(snapshot: TenantSnapshot, limit = 10) {
  const baseline = analyzeTenantIntelligence(snapshot);
  const eligible = new Set(snapshot.edges.filter(e => e.evidence.configured && (SCENARIO_EDGE_TYPES as readonly string[]).includes(e.type)).map(e => e.id));
  const candidates = [...new Set(baseline.paths.flatMap(p => p.steps.map(s => s.edgeId)))].filter(id => eligible.has(id)).slice(0, 20);
  return { candidatesConsidered: candidates.length, bounded: true, cuts: candidates.map(edgeId => {
    const result = simulateRemoval(snapshot, [edgeId]);
    return { edgeId, removedPaths: result.removedPaths.length, remainingPaths: result.remainingPaths.length, newPaths: result.newPaths.length, complete: result.complete };
  }).sort((a,b) => b.removedPaths - a.removedPaths || a.newPaths - b.newPaths || a.edgeId.localeCompare(b.edgeId)).slice(0, Math.max(0, Math.min(20, limit))) };
}
