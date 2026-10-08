import { bound, canonical, compare, unique } from "./canonical";
import { context } from "./model";
import type { EngineContext, WorkflowResult } from "./types";

export interface ChangeCandidate { id: string; cost: number; removes: string[]; description: string }
export interface ModeledPath { id: string; dependencies: string[] }
export interface ProtectedIntegration { id: string; alternatives: ModeledPath[] }
export interface ChangeProblem {
  context: EngineContext;
  paths: ModeledPath[];
  candidates: ChangeCandidate[];
  protectedIntegrations: ProtectedIntegration[];
  evidenceComplete: boolean;
  maxSteps?: number;
  maxPlans?: number;
}
export interface ChangePlan { changes: string[]; cost: number; brokenPaths: string[]; residualPaths: string[]; preservedIntegrations: string[] }
export interface ChangeSolution extends WorkflowResult {
  status: "optimal" | "bounded" | "infeasible";
  plans: ChangePlan[];
  lowerBound: number;
  upperBound: number | null;
}

function assertProblem(problem: ChangeProblem): void {
  if (problem.paths.length > 10_000 || problem.candidates.length > 1_000 || problem.protectedIntegrations.length > 1_000) throw new Error("Planning problem exceeds input limits.");
  const ids = problem.candidates.map(c => c.id);
  if (new Set(ids).size !== ids.length || ids.some(id => !id)) throw new Error("Candidate IDs must be unique and nonempty.");
  if (problem.candidates.some(c => !Number.isFinite(c.cost) || c.cost < 0 || c.cost > 1_000_000)) throw new Error("Costs must be finite, nonnegative, and at most 1000000.");
  if (new Set(problem.paths.map(p => p.id)).size !== problem.paths.length) throw new Error("Path IDs must be unique.");
}

/** Weighted hitting set with monotone protection constraints and a declared exploration bound. */
export function solveChanges(problem: ChangeProblem): ChangeSolution {
  assertProblem(problem);
  const maxSteps = bound(problem.maxSteps ?? 100_000, 1_000_000, "planner steps");
  const maxPlans = bound(problem.maxPlans ?? 3, 20, "plans");
  const candidates = [...problem.candidates].sort((a, b) => a.cost - b.cost || compare(a.id, b.id));
  const removes = (chosen: ChangeCandidate[]) => new Set(chosen.flatMap(c => c.removes));
  const broken = (path: ModeledPath, removed: Set<string>) => path.dependencies.some(id => removed.has(id));
  const safe = (removed: Set<string>) => problem.protectedIntegrations.every(i => i.alternatives.some(p => !broken(p, removed)));
  const options = (path: ModeledPath) => candidates.filter(c => c.removes.some(id => path.dependencies.includes(id)));
  const rootBound = Math.max(0, ...problem.paths.map(p => Math.min(...options(p).map(c => c.cost))));
  const plans: ChangePlan[] = [];
  const visited = new Set<string>();
  let steps = 0;
  let exhausted = false;
  function save(chosen: ChangeCandidate[]) {
    if (!safe(removes(chosen))) return;
    // A returned review plan must not contain an exclusion unnecessary to break
    // its paths. Removing a redundant exclusion also preserves protection.
    let minimal = [...chosen];
    for (const candidate of [...chosen].sort((a, b) => b.cost - a.cost || compare(a.id, b.id))) {
      const without = minimal.filter(c => c.id !== candidate.id);
      if (problem.paths.every(p => broken(p, removes(without)))) minimal = without;
    }
    chosen = minimal;
    const plan: ChangePlan = { changes: unique(chosen.map(c => c.id)), cost: chosen.reduce((sum, c) => sum + c.cost, 0),
      brokenPaths: unique(problem.paths.map(p => p.id)), residualPaths: [],
      preservedIntegrations: unique(problem.protectedIntegrations.map(i => i.id)) };
    if (!plans.some(p => canonical(p.changes) === canonical(plan.changes))) plans.push(plan);
    plans.sort((a, b) => a.cost - b.cost || a.changes.length - b.changes.length || compare(canonical(a.changes), canonical(b.changes)));
    plans.splice(maxPlans);
  }
  // Seed a feasible bound with a deterministic cost/coverage heuristic. Never label it optimal alone.
  const greedy: ChangeCandidate[] = [];
  // Each iteration breaks a previously unbroken path. Already chosen candidates
  // have zero remaining coverage, so the positive-hit filter also prevents reuse.
  while (true) {
    const remaining = problem.paths.filter(p => !broken(p, removes(greedy)));
    if (!remaining.length) { save(greedy); break; }
    const ranked = candidates.filter(c => safe(removes([...greedy, c])))
      .map(c => ({ c, hits: remaining.filter(p => broken(p, new Set(c.removes))).length }))
      .filter(x => x.hits > 0).sort((a, b) => a.c.cost / a.hits - b.c.cost / b.hits || compare(a.c.id, b.c.id));
    if (!ranked.length) break;
    greedy.push(ranked[0]!.c);
  }
  function search(chosen: ChangeCandidate[]) {
    if (steps >= maxSteps) { exhausted = true; return; }
    steps++;
    const key = canonical(unique(chosen.map(c => c.id)));
    if (visited.has(key)) return;
    visited.add(key);
    const removed = removes(chosen);
    if (!safe(removed)) return;
    const cost = chosen.reduce((sum, c) => sum + c.cost, 0);
    if (plans.length === maxPlans && cost > plans.at(-1)!.cost) return;
    const remaining = problem.paths.filter(p => !broken(p, removed)).sort((a, b) => options(a).length - options(b).length || compare(a.id, b.id));
    if (!remaining.length) { save(chosen); return; }
    for (const candidate of options(remaining[0]!)) {
      if (exhausted) return;
      search([...chosen, candidate]);
    }
  }
  search([]);
  return { ...context(problem.context), verdict: !problem.evidenceComplete || exhausted ? "unknown" : plans.length ? "supported" : "refuted",
    status: exhausted ? "bounded" : plans.length ? "optimal" : "infeasible", plans,
    lowerBound: !exhausted && plans.length ? plans[0]!.cost : Number.isFinite(rootBound) ? rootBound : 0,
    upperBound: plans[0]?.cost ?? null, limits: { steps, maxSteps, exhausted },
    assumptions: ["Costs and protected integrations are operator-supplied. Proposed exclusions remain local and are not applied to Entra.", "The solver covers supplied modeled paths; incomplete evidence can hide additional paths."],
    missing: problem.evidenceComplete ? [] : ["complete-path-inventory"] };
}
