import { expect, it } from "vitest";
import { compileSnapshot, evaluateAuthorization, planEvidenceGaps, solveChanges, type ChangeProblem } from "./index";
import { suggestReads } from "./gaps";
import { query, snapshot } from "./test-support";
const base: ChangeProblem = { context: compileSnapshot(snapshot()), candidates: [], paths: [], protectedIntegrations: [], evidenceComplete: true };
function allMinimalPlans(p: ChangeProblem) {
  const covers = (chosen: typeof p.candidates) => p.paths.every(path => path.dependencies.some(d => chosen.some(c => c.removes.includes(d))));
  const solutions = [];
  for (let mask = 0; mask < 2 ** p.candidates.length; mask++) {
    const selected = p.candidates.filter((_, i) => (mask & 2 ** i) !== 0);
    if (!covers(selected) || selected.some(c => covers(selected.filter(other => c !== other)))) continue;
    if (p.protectedIntegrations.some(integration => integration.alternatives.every(path => path.dependencies.some(d => selected.some(c => c.removes.includes(d)))))) continue;
    solutions.push({ changes: selected.map(c => c.id).sort(), cost: selected.reduce((sum, c) => sum + c.cost, 0), brokenPaths: p.paths.map(p => p.id).sort(), residualPaths: [], preservedIntegrations: p.protectedIntegrations.map(i => i.id).sort() });
  }
  return solutions.sort((a, b) => a.cost - b.cost || a.changes.length - b.changes.length || (JSON.stringify(a.changes) < JSON.stringify(b.changes) ? -1 : 1)).slice(0, p.maxPlans ?? 3);
}
it.each(Array.from({ length: 60 }, (_, i) => i))("returns the top minimal plans, including multi-edge changes and protections, seed %d", seed => {
  const p: ChangeProblem = { ...base, maxPlans: seed % 4 + 1,
    candidates: Array.from({ length: 6 }, (_, i) => ({ id: `c${i}`, description: "", cost: (i * 3 + seed) % 6, removes: [`d${i}`, `d${(i + seed) % 6}`] })).reverse(),
    paths: Array.from({ length: 3 }, (_, i) => ({ id: `p${i}`, dependencies: [`d${(i + seed) % 6}`, `d${(i * 3 + seed) % 6}`] })),
    protectedIntegrations: seed % 2 ? [{ id: "production", alternatives: [{ id: "primary", dependencies: ["d0", "d1"] }, { id: "secondary", dependencies: ["d4"] }] }] : [],
  };
  expect(solveChanges(p).plans).toEqual(allMinimalPlans(p));
});
it("bounded greedy search reports a valid lower bound and a cost/coverage upper bound", () => {
  const p: ChangeProblem = { ...base, maxSteps: 1, paths: [{ id: "p1", dependencies: ["a", "b"] }, { id: "p2", dependencies: ["b", "c"] }], candidates: [
    { id: "unused", cost: 0, removes: ["unused"], description: "" }, { id: "c", cost: 3, removes: ["c"], description: "" },
    { id: "a", cost: 3, removes: ["a"], description: "" }, { id: "b", cost: 4, removes: ["b"], description: "" },
  ] };
  const result = solveChanges(p);
  expect(result).toMatchObject({ status: "bounded", verdict: "unknown", lowerBound: 3, upperBound: 4, limits: { steps: 1, maxSteps: 1, exhausted: true } });
  expect(result.plans).toEqual([{ changes: ["b"], cost: 4, brokenPaths: ["p1", "p2"], residualPaths: [], preservedIntegrations: [] }]);
  expect(solveChanges({ ...p, paths: [{ id: "impossible", dependencies: [] }] }).lowerBound).toBe(0);
});
it("cannot promise a protected integration with no surviving alternative, even with no targets", () => {
  const p = { ...base, candidates: [{ id: "unused", cost: 1, removes: ["x"], description: "" }], protectedIntegrations: [{ id: "offline", alternatives: [] }] };
  expect(solveChanges(p)).toMatchObject({ verdict: "refuted", status: "infeasible", plans: [], upperBound: null });
});
it("validates exact problem, plan and cost boundaries before searching", () => {
  const sizes = { paths: 10_000, candidates: 1000, protectedIntegrations: 1000 };
  for (const [key, max] of Object.entries(sizes)) {
    const rows = Array.from({ length: max }, (_, i) => key === "paths" ? { id: `p${i}`, dependencies: ["a"] } : key === "candidates" ? { id: `c${i}`, cost: 0, removes: [], description: "" } : { id: `keep${i}`, alternatives: [{ id: "ok", dependencies: [] }] });
    const p = { ...base, [key]: rows, maxSteps: 1 };
    expect(() => solveChanges(p)).not.toThrow();
    expect(() => solveChanges({ ...p, [key]: [...rows, rows[0]] })).toThrow("Planning problem exceeds input limits.");
  }
  expect(() => solveChanges({ ...base, paths: [{ id: "p", dependencies: [] }, { id: "p", dependencies: [] }] })).toThrow("Path IDs must be unique.");
  expect(() => solveChanges({ ...base, candidates: [{ id: "", cost: 0, removes: [], description: "" }] })).toThrow("Candidate IDs must be unique and nonempty.");
  expect(solveChanges({ ...base, candidates: [{ id: "cap", cost: 1_000_000, removes: ["d"], description: "" }], paths: [{ id: "p", dependencies: ["d"] }] }).upperBound).toBe(1_000_000);
  expect(() => solveChanges({ ...base, maxSteps: 0 })).toThrow("Invalid planner steps budget.");
  for (const maxPlans of [0, 21, 1.5]) expect(() => solveChanges({ ...base, maxPlans })).toThrow("Invalid plans budget.");
  expect(solveChanges({ ...base, maxPlans: 20 }).plans).toHaveLength(1);
});
it("publishes read-only prerequisites for every supported collector", () => {
  const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
  proof.missing = ["applications", "servicePrincipals", "appRoleAssignments", "delegatedPermissionGrants", "usersAndGroups", "groupMemberships", "owners", "roles", "federatedIdentityCredentials", "conditionalAccess", "devices"].map(c => `coverage:${c}`);
  const reads = suggestReads(proof);
  expect(reads.map(r => r.id).sort()).toEqual(["appRoleAssignments", "applications", "conditionalAccess", "delegatedPermissionGrants", "federatedIdentityCredentials", "groupMemberships", "owners", "roles", "servicePrincipals", "usersAndGroups"]);
  expect(reads).toMatchSnapshot();
  const result = planEvidenceGaps(proof, reads, ["Application.Read.All"]);
  expect(result.unresolved).toEqual(["coverage:devices"]); expect(result.verdict).toBe("unknown");
  expect(result.plans[0]!.cost).toBe(reads.reduce((sum, r) => sum + r.cost, 0));
  expect(result.plans[0]!.mayResolve).toEqual(reads.flatMap(r => r.resolves).sort());
  expect(result.plans[0]!.unavailableScopes).not.toContain("Application.Read.All");
});
it("deduplicates shared read endpoints, scopes and prerequisites under a bounded plan", () => {
  const proof = { ...evaluateAuthorization(compileSnapshot(snapshot()), query), missing: ["a", "b"] };
  const reads = [
    { id: "one", resolves: ["a", "not-missing"], endpoints: ["/same"], scopes: ["Directory.Read.All"], cost: 2, requirement: "Read" },
    { id: "two", resolves: ["b"], endpoints: ["/same"], scopes: ["Directory.Read.All"], cost: 2, requirement: "Read" },
  ];
  const result = planEvidenceGaps(proof, reads, [], 1);
  expect(result).toMatchObject({ optimal: false, verdict: "unknown", unresolved: [], lowerBound: 2, limits: { steps: 1, maxSteps: 1, exhausted: true } });
  expect(result.plans[0]).toEqual({ reads: ["one", "two"], endpoints: ["/same"], requiredScopes: ["Directory.Read.All"], unavailableScopes: ["Directory.Read.All"], cost: 4, mayResolve: ["a", "b"] });
});
it.each(["Directory.ReadWrite.All", "Directory.Read.All ", "xDirectory.Read.All!", "DirectoryXReadXAll", "Read.All", "Directory.Read.1", "Directory.ReadWrite", ".Directory.Read.All", "Directory..Read.All", "Directory.Read.All."])("rejects scope outside the read-only grammar: %s", scope => {
  expect(() => planEvidenceGaps(evaluateAuthorization(compileSnapshot(snapshot()), query), [{ id: "r", cost: 1, resolves: [], endpoints: ["/users"], scopes: [scope], requirement: "" }])).toThrow("read scopes only");
});
it("bounds scope parsing and handles repeated Read segments without backtracking", () => {
  const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
  const plan = (scope: string) => planEvidenceGaps(proof, [{ id: "r", cost: 1, resolves: [], endpoints: ["/users"], scopes: [scope], requirement: "" }]);
  expect(() => plan("A".repeat(247) + ".Read.All")).not.toThrow();
  expect(() => plan("A".repeat(248) + ".Read.All")).toThrow("read scopes only");
  expect(() => plan("..Read" + ".A.Read".repeat(10_000) + "!")).toThrow("read scopes only");
  expect(() => plan("Multi.Namespace.Read.All")).not.toThrow();
});
it("rejects an unsafe read among safe reads, endpoints and scopes", () => {
  const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
  const read = { id: "good", resolves: [], endpoints: ["/users"], scopes: ["Directory.Read.All"], cost: 1, requirement: "" };
  for (const bad of [{ ...read, id: "bad", endpoints: ["/users", "https://elsewhere.test"] }, { ...read, id: "bad", scopes: ["Directory.Read.All", "Directory.ReadWrite.All"] }]) expect(() => planEvidenceGaps(proof, [read, bad])).toThrow("read scopes only");
  expect(() => planEvidenceGaps(proof, [{ ...read, scopes: ["!Directory.Read.All"] }])).toThrow("read scopes only");
  expect(() => planEvidenceGaps(proof, [{ ...read, scopes: ["Application.Read"] }])).not.toThrow();
});
it("read alternatives do not add unselected scopes and endpoints to the cheapest plan", () => {
  const proof = { ...evaluateAuthorization(compileSnapshot(snapshot()), query), missing: ["a"] };
  const result = planEvidenceGaps(proof, [{ id: "cheap", resolves: ["a"], endpoints: ["/a"], scopes: ["Application.Read.All"], cost: 1, requirement: "" }, { id: "expensive", resolves: ["a"], endpoints: ["/b"], scopes: ["Directory.Read.All"], cost: 2, requirement: "" }]);
  expect(result.plans[0]).toEqual({ reads: ["cheap"], endpoints: ["/a"], requiredScopes: ["Application.Read.All"], unavailableScopes: ["Application.Read.All"], cost: 1, mayResolve: ["a"] });
});
// A small solver must finish these 10-candidate problems within declared search
// budgets. The independent subset oracle still verifies every returned plan.
it.each([40, 40, 30, 60, 40, 30, 40, 30, 30, 40, 20, 70].map((budget, seed) => [seed, budget] as const))("solves overlapping 10-candidate problem %i within %i states", (seed, maxSteps) => {
  const p: ChangeProblem = { ...base, maxSteps, maxPlans: 3,
    candidates: Array.from({ length: 10 }, (_, i) => ({ id: `c${i}`, cost: (i * 3 + seed) % 7, removes: [`d${i}`, `d${(i + seed + 2) % 10}`], description: "" })).reverse(),
    paths: Array.from({ length: 7 }, (_, i) => ({ id: `p${i}`, dependencies: [`d${(i + seed) % 10}`, `d${(i * 3 + seed) % 10}`] })),
  };
  const r = solveChanges(p); expect(r.status).toBe("optimal"); expect(r.limits.exhausted).toBe(false); expect(r.plans).toEqual(allMinimalPlans(p));
});
it("removes redundant zero-cost exclusions from a bounded greedy plan", () => {
  const p: ChangeProblem = { ...base, maxSteps: 1, paths: [{ id: "p1", dependencies: ["a", "c"] }, { id: "p2", dependencies: ["b"] }, { id: "p3", dependencies: ["c"] }], candidates: [
    { id: "a", cost: 0, removes: ["a"], description: "" }, { id: "b", cost: 0, removes: ["b"], description: "" }, { id: "c", cost: 1, removes: ["c"], description: "" },
  ] };
  expect(solveChanges(p).plans).toEqual([{ changes: ["b", "c"], cost: 1, brokenPaths: ["p1", "p2", "p3"], residualPaths: [], preservedIntegrations: [] }]);
});
it("a bounded seed preserves integration alternatives and breaks ties by stable IDs", () => {
  const candidates = ["z", "a"].map(id => ({ id, cost: 2, removes: [id], description: "" }));
  const p: ChangeProblem = { ...base, maxSteps: 1, candidates, paths: [{ id: "p", dependencies: ["z", "a"] }], protectedIntegrations: [{ id: "production", alternatives: [{ id: "first", dependencies: ["a"] }, { id: "backup", dependencies: ["other"] }] }] };
  expect(solveChanges(p).plans[0]!.changes).toEqual(["a"]);
  p.protectedIntegrations[0]!.alternatives.pop();
  expect(solveChanges(p).plans[0]!.changes).toEqual(["z"]);
});
