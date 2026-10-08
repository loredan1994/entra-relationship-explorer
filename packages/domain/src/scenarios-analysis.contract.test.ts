import { beforeEach, expect, it, vi } from "vitest";
import type { AttackPath, TenantIntelligence } from "./intelligence";
import { edge, node, snapshot } from "./test-support";
const engine = vi.hoisted(() => vi.fn());
vi.mock("./intelligence", () => ({ analyzeTenantIntelligence: engine }));
import { rankScenarioCuts, simulateRemoval } from "./scenarios";
const person = node({ id: "person", kind: "user", label: "Person" });
const role = node({ id: "role", kind: "directoryRole", label: "Role" });
const graph = () => snapshot([person, role], [edge("ACTIVE_IN_ROLE", person, role, { id: "z" }), edge("ACTIVE_IN_ROLE", person, role, { id: "a" })]);
function path(id: string, edgeIds: string[] = ["z", "a"]): AttackPath {
  return { id, title: id, severity: "high", confidence: "high", source: person, target: role, steps: edgeIds.map((edgeId, index) => ({ edgeId, index, source: person, target: role, relationship: "ACTIVE_IN_ROLE", permissions: [], evidenceClass: "configured", sourceEndpoint: "/roles", completeness: "complete", explanation: "Configured" })), prerequisites: [], attackMappings: [], mitigations: [], uncertainty: [] };
}
function analysis(paths: AttackPath[], truncated = false): TenantIntelligence {
  return { generatedAt: "2026-08-26", paths, pathAnalysis: { truncated, traversals: 0, limits: { maxPaths: 2000, maxTraversals: 10000 } }, findings: [], counts: { critical: 0, high: 0, medium: 0, low: 0 }, evidence: { configured: 0, observed: 0, inferred: 0, missing: 0 } };
}
beforeEach(() => { engine.mockReset(); });
it.each([[false, false, true], [true, false, false], [false, true, false], [true, true, false]])("reports completeness only when both bounded searches finish (%s, %s)", (before, after, complete) => {
  engine.mockReturnValueOnce(analysis([path("retained"), path("removed")], before)).mockReturnValueOnce(analysis([path("retained"), path("new")], after));
  const result = simulateRemoval(graph(), ["z"]);
  expect(result.complete).toBe(complete);
  expect(result.removedPaths.map(p => p.id)).toEqual(["removed"]);
  expect(result.newPaths.map(p => p.id)).toEqual(["new"]);
  expect(result.remainingPaths.map(p => p.id)).toEqual(["retained", "new"]);
  expect(result.baselineTargets).toEqual(["role"]); expect(result.scenarioTargets).toEqual(["role"]);
});
it("never offers unconfigured or unsupported relationships as cut candidates", () => {
  const s = graph(); s.edges[0]!.type = "INSTANTIATES_AS"; s.edges[1]!.evidence.configured = false;
  engine.mockReturnValue(analysis([path("baseline")]));
  expect(rankScenarioCuts(s)).toMatchObject({ candidatesConsidered: 0, cuts: [] });
});
it("breaks equally effective cut ties by newly visible paths, then stable relationship ID", () => {
  engine.mockImplementation(s => analysis(s.edges.length === 2 ? [path("baseline")] : [path("new")]));
  expect(rankScenarioCuts(graph()).cuts.map(c => [c.edgeId, c.removedPaths, c.newPaths])).toEqual([["a", 1, 1], ["z", 1, 1]]);
  engine.mockImplementation(s => analysis(s.edges.length === 2 ? [path("baseline")] : s.edges[0].id === "a" ? [] : [path("new")]));
  expect(rankScenarioCuts(graph()).cuts.map(c => c.edgeId)).toEqual(["z", "a"]);
});
