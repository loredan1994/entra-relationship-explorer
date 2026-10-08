import { expect, it } from "vitest";
import { createScenarioPlan, importScenarioPlan, rankScenarioCuts, simulateRemoval } from "./scenarios";
import { edge, node, snapshot } from "./test-support";
import type { RelationshipType } from "./types";
function graph() {
  const person = node({ id: "person", kind: "user", label: "Person" });
  const group = node({ id: "group", kind: "group", label: "Role group" });
  const role = node({ id: "role", kind: "directoryRole", label: "Global Administrator" });
  return snapshot([person, group, role], [edge("MEMBER_OF", person, group, { id: "member" }), edge("ACTIVE_IN_ROLE", group, role, { id: "role" })]);
}
it("exports an explainable hypothetical plan and recomputes untrusted analysis on import", () => {
  const s = graph(); const result = simulateRemoval(s, ["member", "member"]);
  expect(result.excludedEdgeIds).toEqual(["member"]);
  expect(result.removedPaths.map(p => p.source.id)).toEqual(["person"]);
  expect(result.remainingPaths.map(p => p.source.id)).toEqual(["group"]);
  expect(result.newPaths).toEqual([]);
  expect(result.baselineTargets).toEqual(["role"]); expect(result.scenarioTargets).toEqual(["role"]);
  expect(result.complete).toBe(true);
  const plan = createScenarioPlan(s, ["member"]);
  expect(plan).toEqual({ schemaVersion: 1, kind: "local-access-scenario", tenantId: s.tenant.tenantId, snapshotId: s.id, scannedAt: s.scannedAt, excludedEdgeIds: ["member"], removedPathIds: result.removedPaths.map(p => p.id), remainingPathIds: result.remainingPaths.map(p => p.id), complete: true, caveat: "Hypothetical configured access only. No tenant change was made. Missing evidence can hide paths." });
  expect(importScenarioPlan(JSON.stringify({ ...plan, complete: false, removedPathIds: ["invented"] }), s)).toEqual(["member"]);
  expect(simulateRemoval(s, ["role"]).scenarioTargets).toEqual([]);
});
it.each([null, false, 1, "plan", []])("rejects non-object plan %j", input => {
  expect(() => importScenarioPlan(JSON.stringify(input), graph())).toThrow("Expected a scenario plan object.");
});
it.each([
  [{ extra: true }, "Unsupported scenario plan schema."], [{ schemaVersion: 2 }, "Unsupported scenario plan schema."],
  [{ kind: "tenant-export" }, "Unsupported scenario plan schema."], [{ tenantId: "other" }, "This plan belongs to a different tenant."],
  [{ snapshotId: "other" }, "This plan belongs to a different snapshot. Recreate it against the current evidence."],
  [{ scannedAt: "other" }, "This plan belongs to a different snapshot. Recreate it against the current evidence."],
  [{ excludedEdgeIds: null }, "A plan must contain at most 100 relationship IDs."], [{ excludedEdgeIds: [1] }, "A plan must contain at most 100 relationship IDs."],
  [{ excludedEdgeIds: Array(101).fill("member") }, "A plan must contain at most 100 relationship IDs."],
])("rejects unsafe plan fields (%#)", (patch, message) => {
  const s = graph(); expect(() => importScenarioPlan(JSON.stringify({ ...createScenarioPlan(s, []), ...patch }), s)).toThrow(message);
});
it("enforces byte and relationship limits at the exact boundary", () => {
  const s = graph(); const plan = JSON.stringify(createScenarioPlan(s, Array(100).fill("member")));
  expect(importScenarioPlan(plan.padEnd(100000, " "), s)).toEqual(["member"]);
  expect(() => importScenarioPlan(plan.padEnd(100001, " "), s)).toThrow("Scenario plans must be at most 100 KB.");
  expect(() => importScenarioPlan(JSON.stringify({ ...createScenarioPlan(s, []), caveat: "é".repeat(60000) }), s)).toThrow("Scenario plans must be at most 100 KB.");
  expect(() => importScenarioPlan("{", s)).toThrow("Choose a valid JSON scenario plan.");
  expect(() => simulateRemoval(s, Array(101).fill("member"))).toThrow("A scenario can exclude at most 100 relationships.");
  expect(() => simulateRemoval(s, ["unknown"])).toThrow("Relationship unknown cannot be changed in a scenario.");
  s.edges[0]!.evidence.configured = false;
  expect(() => simulateRemoval(s, ["member"])).toThrow("Relationship member cannot be changed in a scenario.");
  s.nodes[0]!.tenantId = "other";
  expect(() => importScenarioPlan(plan, s)).toThrow();
});
it.each(["OWNS", "FEDERATES_AS", "MEMBER_OF", "CAN_CALL_AS_APP", "CAN_CALL_DELEGATED", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as RelationshipType[])("supports configured %s exclusions", type => {
  const s = graph(); s.edges[0]!.type = type;
  expect(simulateRemoval(s, ["member"]).excludedEdgeIds).toEqual(["member"]);
});
it("rejects relationships outside the local scenario contract", () => {
  const s = graph(); s.edges[0]!.type = "INSTANTIATES_AS";
  expect(() => simulateRemoval(s, ["member"])).toThrow("Relationship member cannot be changed in a scenario.");
});
it("ranks cuts by removed paths and then ID, with bounded non-negative result counts", () => {
  const s = graph();
  expect(rankScenarioCuts(s)).toEqual({ bounded: true, candidatesConsidered: 2, cuts: [
    { edgeId: "role", removedPaths: 2, remainingPaths: 0, newPaths: 0, complete: true },
    { edgeId: "member", removedPaths: 1, remainingPaths: 1, newPaths: 0, complete: true },
  ] });
  expect(rankScenarioCuts(s, 1).cuts.map(c => c.edgeId)).toEqual(["role"]);
  expect(rankScenarioCuts(s, 0).cuts).toEqual([]); expect(rankScenarioCuts(s, -1).cuts).toEqual([]);
  s.completion.status = "partial";
  expect(rankScenarioCuts(s).cuts.every(c => !c.complete)).toBe(true);
  const role = s.nodes[2]!;
  s.nodes = [role]; s.edges = [];
  for (let i = 25; i >= 0; i--) {
    const user = node({ kind: "user", label: `Person ${i}` }); s.nodes.push(user);
    s.edges.push(edge("ACTIVE_IN_ROLE", user, role, { id: `edge-${i.toString().padStart(2, "0")}` }));
  }
  const ranked = rankScenarioCuts(s, 30);
  expect(ranked.candidatesConsidered).toBe(20); expect(ranked.cuts).toHaveLength(20);
  expect(rankScenarioCuts(s).cuts).toHaveLength(10);
  const ids = ranked.cuts.map(c => c.edgeId); expect(ids).toEqual([...ids].sort());
});

it("accepts 100 exclusions before deduplication and rejects mixed ID types", () => {
  const s = graph(); const plan = createScenarioPlan(s, []);
  expect(importScenarioPlan(JSON.stringify({ ...plan, excludedEdgeIds: Array(100).fill("member") }), s)).toEqual(["member"]);
  expect(() => importScenarioPlan(JSON.stringify({ ...plan, excludedEdgeIds: ["member", 1] }), s)).toThrow("A plan must contain at most 100 relationship IDs.");
  s.nodes[0]!.tenantId = "other";
  expect(() => importScenarioPlan("not json", s)).not.toThrow("Choose a valid JSON scenario plan.");
});
