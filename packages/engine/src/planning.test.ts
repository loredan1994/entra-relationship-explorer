import { describe, expect, it } from "vitest";
import { solveChanges, type ChangeProblem } from "./solver";
import { compileSnapshot } from "./model";
import { evaluateAuthorization } from "./authorization";
import { planEvidenceGaps } from "./gaps";
import { query, snapshot } from "./test-support";

function problem(): ChangeProblem {
  return { context: compileSnapshot(snapshot()), evidenceComplete: true,
    paths: [{ id: "first", dependencies: ["a", "shared"] }, { id: "alternate", dependencies: ["b", "shared"] }],
    candidates: [{ id: "remove-a", cost: 2, removes: ["a"], description: "First branch" }, { id: "remove-b", cost: 2, removes: ["b"], description: "Second branch" }, { id: "remove-shared", cost: 3, removes: ["shared"], description: "Shared dependency" }],
    protectedIntegrations: [] };
}
// Independent oracle enumerates every subset; it does not share solver traversal or pruning.
function exhaustive(p: ChangeProblem): number | null {
  let best = Infinity;
  for (let mask = 0; mask < 2 ** p.candidates.length; mask++) {
    const selected = p.candidates.filter((_, i) => mask & (1 << i));
    const removed = selected.flatMap(c => c.removes);
    if (!p.paths.every(path => path.dependencies.some(d => removed.includes(d)))) continue;
    if (!p.protectedIntegrations.every(integration => integration.alternatives.some(path => path.dependencies.every(d => !removed.includes(d))))) continue;
    best = Math.min(best, selected.reduce((n, c) => n + c.cost, 0));
  }
  return Number.isFinite(best) ? best : null;
}

describe("weighted change planning", () => {
  it("breaks every alternative and ranks cheaper shared changes", () => {
    const result = solveChanges(problem()); expect(result.status).toBe("optimal"); expect(result.lowerBound).toBe(3); expect(result.upperBound).toBe(3);
    expect(result.plans[0]).toEqual({ changes: ["remove-shared"], cost: 3, brokenPaths: ["alternate", "first"], residualPaths: [], preservedIntegrations: [] });
    expect(result.plans[1]!.changes).toEqual(["remove-a", "remove-b"]);
  });
  it("preserves required integrations, including one surviving alternative", () => {
    const p = problem(); p.protectedIntegrations = [{ id: "billing", alternatives: [{ id: "live", dependencies: ["shared"] }] }];
    expect(solveChanges(p).plans[0]!.changes).toEqual(["remove-a", "remove-b"]);
    p.protectedIntegrations[0]!.alternatives.push({ id: "fallback", dependencies: ["untouched"] });
    expect(solveChanges(p).plans[0]!.changes).toEqual(["remove-shared"]);
    p.protectedIntegrations.push({ id: "cannot-break", alternatives: [p.paths[0]!] });
    expect(solveChanges(p).status).toBe("infeasible");
  });
  it("a bounded heuristic result is never called optimal", () => {
    const result = solveChanges({ ...problem(), maxSteps: 1 });
    expect(result.status).toBe("bounded"); expect(result.verdict).toBe("unknown"); expect(result.limits.exhausted).toBe(true);
    expect(result.lowerBound).toBeLessThanOrEqual(result.upperBound!);
    expect(solveChanges({ ...problem(), evidenceComplete: false }).missing).toContain("complete-path-inventory");
  });
  it.each(Array.from({ length: 60 }, (_, i) => i))("matches exhaustive subsets for generated graph %i", seed => {
    const candidates = Array.from({ length: 7 }, (_, i) => ({ id: `c${i}`, cost: (seed * (i + 3) + i) % 7, removes: [`d${i}`], description: "Synthetic" }));
    const paths = Array.from({ length: 4 }, (_, i) => ({ id: `p${i}`, dependencies: candidates.filter((_, j) => ((seed + 1) * (i + 2) + j * 3) % 5 < 2).map(c => c.removes[0]!) }));
    const p: ChangeProblem = { ...problem(), candidates, paths, protectedIntegrations: seed % 2 ? [{ id: "protected", alternatives: [{ id: "primary", dependencies: ["d1", "d3"] }, { id: "secondary", dependencies: ["d2", "d4"] }] }] : [] };
    const expected = exhaustive(p), actual = solveChanges(p);
    expect(actual.upperBound).toBe(expected); expect(actual.status).toBe(expected === null ? "infeasible" : "optimal");
  });
  it("handles no targets, unbreakable paths and invalid costs", () => {
    expect(solveChanges({ ...problem(), paths: [], candidates: [] }).plans[0]!.cost).toBe(0);
    expect(solveChanges({ ...problem(), paths: [{ id: "unbreakable", dependencies: [] }] }).status).toBe("infeasible");
    for (const cost of [-1, Infinity, NaN, 1_000_001]) expect(() => solveChanges({ ...problem(), candidates: [{ id: "bad", cost, removes: [], description: "" }] })).toThrow("Costs");
    expect(() => solveChanges({ ...problem(), maxSteps: 0 })).toThrow("budget");
    expect(() => solveChanges({ ...problem(), candidates: [problem().candidates[0]!, problem().candidates[0]!] })).toThrow("unique");
  });
});

describe("question-specific evidence gaps", () => {
  it("deduplicates shared prerequisites and reports missing permissions without granting them", () => {
    const s = snapshot([]); s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "denied";
    const proof = evaluateAuthorization(compileSnapshot(s), query), result = planEvidenceGaps(proof);
    expect(result.plans[0]!.reads).toEqual(["appRoleAssignments"]);
    expect(result.plans[0]!.unavailableScopes).toEqual(["Application.Read.All"]);
    expect(result.plans[0]!.endpoints).toEqual(["/servicePrincipals/{resource-id}/appRoleAssignedTo"]);
    expect(proof.verdict).toBe("unknown");
    expect(planEvidenceGaps(proof, undefined, ["Application.Read.All"]).plans[0]!.unavailableScopes).toEqual([]);
  });
  it("finds cheaper shared reads and leaves semantic gaps unresolved", () => {
    const proof = { ...evaluateAuthorization(compileSnapshot(snapshot()), query), missing: ["a", "b", "query:user-context"] };
    const result = planEvidenceGaps(proof, [
      { id: "one", resolves: ["a"], endpoints: ["/a"], scopes: ["Directory.Read.All"], cost: 2, requirement: "" },
      { id: "two", resolves: ["b"], endpoints: ["/b"], scopes: ["Directory.Read.All"], cost: 2, requirement: "" },
      { id: "both", resolves: ["a", "b"], endpoints: ["/ab"], scopes: ["Directory.Read.All"], cost: 3, requirement: "" },
    ]);
    expect(result.plans[0]!.reads).toEqual(["both"]); expect(result.unresolved).toEqual(["query:user-context"]); expect(result.verdict).toBe("unknown");
  });
  it("rejects write permissions and absolute or scheme-relative endpoints", () => {
    const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
    for (const endpoint of ["https://example.com", "//example.com"]) expect(() => planEvidenceGaps(proof, [{ id: "read", resolves: [], endpoints: [endpoint], scopes: ["Directory.Read.All"], cost: 1, requirement: "" }])).toThrow("GET");
    expect(() => planEvidenceGaps(proof, [{ id: "write", resolves: [], endpoints: ["/users"], scopes: ["Directory.ReadWrite.All"], cost: 1, requirement: "" }])).toThrow("read scopes");
  });
});
