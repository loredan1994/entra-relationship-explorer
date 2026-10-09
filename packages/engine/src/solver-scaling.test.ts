import { describe, expect, it } from "vitest";
import { solveChanges, type ChangeProblem } from "./solver";

const context = { tenantId: "synthetic", snapshotIds: ["snapshot"], collectedAt: [], engineVersion: "test", ruleVersion: "test" };
const base: ChangeProblem = { context, candidates: [], paths: [], protectedIntegrations: [], evidenceComplete: true };
function independent(size: number): ChangeProblem {
  return { ...base,
    paths: Array.from({ length: size }, (_, i) => ({ id: `p${i}`, dependencies: [`d${i}`] })),
    candidates: Array.from({ length: size }, (_, i) => ({ id: `c${i}`, cost: i % 4, removes: [`d${i}`], description: "" })),
  };
}
// Deliberately use subsets and raw dependency comparisons, independent of the
// solver's incidence counts, branch selection, greedy heuristic and reduction.
function oracle(problem: ChangeProblem) {
  const plans = [];
  const hits = (mask: number, dependencies: string[]) => problem.candidates.some((candidate, i) => Boolean(mask & (1 << i)) && candidate.removes.some(id => dependencies.includes(id)));
  const covers = (mask: number) => problem.paths.every(path => hits(mask, path.dependencies));
  for (let mask = 0; mask < 2 ** problem.candidates.length; mask++) {
    if (!covers(mask)) continue;
    if (problem.protectedIntegrations.some(integration => integration.alternatives.every(path => hits(mask, path.dependencies)))) continue;
    if (problem.candidates.some((_, i) => Boolean(mask & (1 << i)) && covers(mask & ~(1 << i)))) continue;
    const selected = problem.candidates.filter((_, i) => Boolean(mask & (1 << i)));
    plans.push({ changes: selected.map(c => c.id).sort(), cost: selected.reduce((sum, c) => sum + c.cost, 0) });
  }
  return plans.sort((a, b) => a.cost - b.cost || a.changes.length - b.changes.length || (JSON.stringify(a.changes) < JSON.stringify(b.changes) ? -1 : 1)).slice(0, problem.maxPlans ?? 3);
}

describe("bounded incidence-based change planning", () => {
  it.each(Array.from({ length: 50 }, (_, seed) => seed))("matches exhaustive minimal sets with duplicate dependencies and shared protected alternatives, seed %i", seed => {
    const problem: ChangeProblem = { ...base, maxPlans: seed % 5 + 1,
      candidates: Array.from({ length: 8 }, (_, i) => ({ id: `c${i}`, cost: (seed + i * 3) % 5, removes: [`d${i}`, `d${i}`, `d${(i + seed) % 8}`], description: "" })),
      paths: Array.from({ length: 5 }, (_, i) => ({ id: `p${i}`, dependencies: [`d${(i + seed) % 8}`, `d${i}`, `d${i}`] })),
      protectedIntegrations: Array.from({ length: seed % 3 }, (_, i) => ({ id: `integration${i}`, alternatives: [{ id: "primary", dependencies: ["d0", `d${i + 2}`, "d0"] }, { id: "fallback", dependencies: ["d5", "d7"] }] })),
    };
    const result = solveChanges(problem), expected = oracle(problem);
    expect(result.status).toBe(expected.length ? "optimal" : "infeasible");
    expect(result.plans.map(({ changes, cost }) => ({ changes, cost }))).toEqual(expected);
    expect(result.limits.work).toBeLessThanOrEqual(result.limits.maxWork);
  });
  it.each([80, 200])("interrupts a %i-path greedy seed within its separately declared work budget", size => {
    const result = solveChanges({ ...independent(size), maxSteps: 1 });
    expect(result).toMatchObject({ status: "bounded", verdict: "unknown", plans: [], upperBound: null, limits: { steps: 0, maxSteps: 1, exhausted: true, work: 10_000, maxWork: 10_000 } });
    expect(result.lowerBound).toBe(3);
  });
  it("finishes a large independent instance without constructing candidate/path cross-products", () => {
    const problem = independent(300), result = solveChanges(problem);
    expect(result.status).toBe("optimal");
    expect(result.plans).toEqual([{ changes: problem.candidates.map(c => c.id).sort(), cost: 450, brokenPaths: problem.paths.map(p => p.id).sort(), residualPaths: [], preservedIntegrations: [] }]);
    expect(result.limits.steps).toBe(301);
    expect(result.limits.work).toBeLessThan(750_000);
  });
  it("charges repeated input dependencies before reading an unbounded nested array", () => {
    let reads = 0;
    const dependencies = new Proxy(Array<string>(100_000).fill("shared"), { get(target, key, receiver) { if (typeof key === "string" && /^\d+$/.test(key)) reads++; return Reflect.get(target, key, receiver); } });
    const result = solveChanges({ ...base, maxSteps: 1, paths: [{ id: "p", dependencies }] });
    expect(result).toMatchObject({ status: "bounded", verdict: "unknown", lowerBound: 0, upperBound: null, limits: { steps: 0, exhausted: true, work: 10_000, maxWork: 10_000 } });
    expect(reads).toBe(10_000);
  });
  it("also bounds empty protected alternatives that have no dependencies to index", () => {
    let reads = 0;
    const alternatives = new Proxy(Array.from({ length: 100_000 }, (_, i) => ({ id: `a${i}`, dependencies: [] })), { get(target, key, receiver) { if (typeof key === "string" && /^\d+$/.test(key)) reads++; return Reflect.get(target, key, receiver); } });
    const result = solveChanges({ ...base, maxSteps: 1, protectedIntegrations: [{ id: "integration", alternatives }] });
    expect(result).toMatchObject({ status: "bounded", verdict: "unknown", plans: [], limits: { work: 10_000, maxWork: 10_000, exhausted: true } });
    expect(reads).toBe(10_000);
  });
  it("bounds a dense incidence expansion before greedy evaluation", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: Array.from({ length: 500 }, (_, i) => ({ id: `p${i}`, dependencies: ["shared"] })),
      candidates: Array.from({ length: 500 }, (_, i) => ({ id: `c${i}`, cost: i, removes: ["shared"], description: "" })),
    });
    expect(result).toMatchObject({ status: "bounded", verdict: "unknown", plans: [], lowerBound: 0, limits: { steps: 0, work: 10_000, maxWork: 10_000, exhausted: true } });
  });
  it("does not convert unrelated input errors into a bounded answer", () => {
    const path = { id: "p", get dependencies(): string[] { throw new Error("input getter failed"); } };
    expect(() => solveChanges({ ...base, paths: [path] })).toThrow("input getter failed");
  });
  it("does not count an already broken protected alternative twice while seeding", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: [{ id: "first", dependencies: ["a"] }, { id: "second", dependencies: ["b"] }],
      candidates: [{ id: "a", cost: 1, removes: ["a", "shared"], description: "" }, { id: "b", cost: 2, removes: ["b", "shared", "backup"], description: "" }],
      protectedIntegrations: [{ id: "integration", alternatives: [{ id: "original", dependencies: ["shared"] }, { id: "backup", dependencies: ["backup"] }, { id: "survivor", dependencies: ["safe"] }] }],
    });
    expect(result.plans[0]).toMatchObject({ changes: ["a", "b"], cost: 3, preservedIntegrations: ["integration"] });
    expect(result.status).toBe("bounded");
  });
  it("breaks equal cost-per-path ties by ID even when candidates have different costs", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: [{ id: "first", dependencies: ["a", "z"] }, { id: "second", dependencies: ["a"] }],
      candidates: [{ id: "a", cost: 2, removes: ["a"], description: "" }, { id: "z", cost: 1, removes: ["z"], description: "" }],
      protectedIntegrations: [{ id: "integration", alternatives: [{ id: "first", dependencies: ["a"] }, { id: "second", dependencies: ["z"] }] }],
    });
    expect(result.plans[0]).toMatchObject({ changes: ["a"], cost: 2 });
  });
  it("rejects a greedy candidate that would remove every remaining protected alternative", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: [{ id: "path", dependencies: ["target"] }],
      candidates: [{ id: "unsafe", cost: 1, removes: ["target", "first", "second"], description: "" }],
      protectedIntegrations: [{ id: "integration", alternatives: [{ id: "first", dependencies: ["first"] }, { id: "second", dependencies: ["second"] }] }],
    });
    expect(result.plans).toEqual([]);
    expect(result.verdict).toBe("unknown");
  });
  it("keeps search states with multi-digit candidate indices distinct", () => {
    const candidates = Array.from({ length: 24 }, (_, i) => ({ id: `c${String(i).padStart(2, "0")}`, cost: i === 23 ? 3 : 1, removes: [`d${i}`], description: "" }));
    const result = solveChanges({ ...base, candidates,
      paths: [{ id: "01", dependencies: ["d1"] }, { id: "02", dependencies: ["d2", "d23"] }, { id: "03", dependencies: ["d3", "d23"] }],
      protectedIntegrations: [{ id: "integration", alternatives: [{ id: "left", dependencies: ["d2"] }, { id: "right", dependencies: ["d23"] }] }],
    });
    expect(result.status).toBe("optimal");
    expect(result.plans.map(({ changes, cost }) => ({ changes, cost }))).toEqual([{ changes: ["c01", "c02", "c03"], cost: 3 }, { changes: ["c01", "c23"], cost: 4 }]);
  });
  it("a bounded seed chooses lower cost before a lexically earlier expensive exclusion", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: [{ id: "target", dependencies: ["cheap", "expensive"] }],
      candidates: [{ id: "a-expensive", cost: 100, removes: ["expensive"], description: "" }, { id: "z-cheap", cost: 1, removes: ["cheap"], description: "" }],
    });
    expect(result).toMatchObject({ status: "bounded", upperBound: 1, plans: [{ changes: ["z-cheap"], cost: 1 }] });
  });
  it("minimizes a bounded seed by discarding the more expensive redundant exclusion first", () => {
    const result = solveChanges({ ...base, maxSteps: 1,
      paths: ["one", "two", "three", "four"].map(id => ({ id, dependencies: [id] })),
      candidates: [
        { id: "a", cost: 1, removes: ["one", "two"], description: "" },
        { id: "b", cost: 2, removes: ["two", "three"], description: "" },
        { id: "c", cost: 5, removes: ["one", "three", "four"], description: "" },
      ],
    });
    expect(result).toMatchObject({ status: "bounded", upperBound: 6, plans: [{ changes: ["a", "c"], cost: 6 }] });
  });
  it("discards lower-ranked plans instead of accumulating an unbounded history of alternatives", () => {
    const result = solveChanges({ ...base, maxPlans: 1, maxSteps: 1000,
      paths: [{ id: "target", dependencies: ["shared"] }],
      candidates: Array.from({ length: 700 }, (_, i) => ({ id: `c${String(i).padStart(3, "0")}`, cost: 1, removes: ["shared"], description: "" })),
    });
    expect(result.status).toBe("optimal");
    expect(result.limits.exhausted).toBe(false);
    expect(result.plans).toEqual([{ changes: ["c000"], cost: 1, brokenPaths: ["target"], residualPaths: [], preservedIntegrations: [] }]);
  });
  it("caps total work even when the requested search-state budget is maximal", () => {
    const result = solveChanges({ ...base, maxSteps: 1_000_000 });
    expect(result.limits.maxWork).toBe(10_000_000);
    expect(result.status).toBe("optimal");
  });
});
