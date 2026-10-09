import { bound, canonical, compare } from "./canonical";
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
  limits: WorkflowResult["limits"] & { work: number; maxWork: number };
}

function assertProblem(problem: ChangeProblem): void {
  if (problem.paths.length > 10_000 || problem.candidates.length > 1_000 || problem.protectedIntegrations.length > 1_000) throw new Error("Planning problem exceeds input limits.");
  const ids = problem.candidates.map(c => c.id);
  if (new Set(ids).size !== ids.length || ids.some(id => !id)) throw new Error("Candidate IDs must be unique and nonempty.");
  if (problem.candidates.some(c => !Number.isFinite(c.cost) || c.cost < 0 || c.cost > 1_000_000)) throw new Error("Costs must be finite, nonnegative, and at most 1000000.");
  if (new Set(problem.paths.map(p => p.id)).size !== problem.paths.length) throw new Error("Path IDs must be unique.");
}

const WORK_EXHAUSTED = Symbol("planner work exhausted");
class WorkBudget {
  work = 0;
  constructor(readonly maxWork: number) {}
  spend(amount = 1): void {
    if (amount > this.maxWork - this.work) { this.work = this.maxWork; throw WORK_EXHAUSTED; }
    this.work += amount;
  }
}
function sortedIds(values: string[], budget: WorkBudget): string[] {
  budget.spend(values.length);
  return [...new Set(values)].sort((a, b) => { budget.spend(); return compare(a, b); });
}
interface Incidence {
  hits: number[][];
  protectedHits: number[][];
  options: number[][];
  alternativeGroups: number[];
  groupSizes: number[];
  pathOrder: number[];
  rootBound: number;
}
interface Dependency { paths: Set<number>; alternatives: Set<number> }

/** Index each dependency once; candidate/path cross-products are never materialized blindly. */
function indexProblem(problem: ChangeProblem, candidates: ChangeCandidate[], budget: WorkBudget): Incidence {
  const dependencies = new Map<string, Dependency>();
  function dependency(id: string): Dependency {
    budget.spend();
    let entry = dependencies.get(id);
    if (!entry) { entry = { paths: new Set(), alternatives: new Set() }; dependencies.set(id, entry); }
    return entry;
  }
  const options = problem.paths.map((path, i) => {
    budget.spend();
    for (const id of path.dependencies) dependency(id).paths.add(i);
    return [] as number[];
  });
  const alternativeGroups: number[] = [];
  const groupSizes = problem.protectedIntegrations.map((integration, group) => {
    budget.spend();
    for (const path of integration.alternatives) {
      budget.spend();
      const alternative = alternativeGroups.length;
      alternativeGroups.push(group);
      for (const id of path.dependencies) dependency(id).alternatives.add(alternative);
    }
    return integration.alternatives.length;
  });
  const hits: number[][] = [], protectedHits: number[][] = [];
  for (const [candidate, change] of candidates.entries()) {
    budget.spend();
    const targets = new Set<number>(), protections = new Set<number>();
    for (const id of change.removes) {
      budget.spend();
      const entry = dependencies.get(id);
      if (!entry) continue;
      for (const path of entry.paths) { budget.spend(); targets.add(path); }
      for (const alternative of entry.alternatives) { budget.spend(); protections.add(alternative); }
    }
    hits.push([...targets]); protectedHits.push([...protections]);
    for (const path of targets) { budget.spend(); options[path]!.push(candidate); }
  }
  let rootBound = 0;
  for (const pathOptions of options) {
    budget.spend();
    // Candidates are cost-sorted, so the first incident candidate is cheapest.
    rootBound = Math.max(rootBound, pathOptions.length ? candidates[pathOptions[0]!]!.cost : Infinity);
  }
  const pathOrder = problem.paths.map((_, i) => i).sort((a, b) => {
    budget.spend();
    return options[a]!.length - options[b]!.length || compare(problem.paths[a]!.id, problem.paths[b]!.id);
  });
  return { hits, protectedHits, options, alternativeGroups, groupSizes, pathOrder, rootBound };
}

/** Counts allow adding/undoing a candidate without rebuilding every removal set. */
class PlanState {
  readonly covered: Int32Array;
  readonly brokenAlternatives: Int32Array;
  readonly liveAlternatives: Int32Array;
  uncovered: number;
  violations: number;
  constructor(readonly index: Incidence, readonly budget: WorkBudget) {
    budget.spend(index.options.length + index.alternativeGroups.length + index.groupSizes.length);
    this.covered = new Int32Array(index.options.length);
    this.brokenAlternatives = new Int32Array(index.alternativeGroups.length);
    this.liveAlternatives = Int32Array.from(index.groupSizes);
    this.uncovered = index.options.length;
    this.violations = index.groupSizes.filter(size => size === 0).length;
  }
  change(candidate: number, delta: 1 | -1): void {
    for (const path of this.index.hits[candidate]!) {
      this.budget.spend();
      if (this.covered[path] === 0) this.uncovered--;
      this.covered[path]! += delta;
      if (this.covered[path] === 0) this.uncovered++;
    }
    for (const alternative of this.index.protectedHits[candidate]!) {
      this.budget.spend();
      const group = this.index.alternativeGroups[alternative]!;
      if (this.liveAlternatives[group] === 0) this.violations--;
      if (this.brokenAlternatives[alternative] === 0) this.liveAlternatives[group] = this.liveAlternatives[group]! - 1;
      this.brokenAlternatives[alternative]! += delta;
      if (this.brokenAlternatives[alternative] === 0) this.liveAlternatives[group] = this.liveAlternatives[group]! + 1;
      if (this.liveAlternatives[group] === 0) this.violations++;
    }
  }
  allows(candidate: number): boolean {
    const lost = new Map<number, number>();
    for (const alternative of this.index.protectedHits[candidate]!) {
      this.budget.spend();
      if (this.brokenAlternatives[alternative] !== 0) continue;
      const group = this.index.alternativeGroups[alternative]!;
      const count = (lost.get(group) ?? 0) + 1;
      if (count === this.liveAlternatives[group]) return false;
      lost.set(group, count);
    }
    return this.violations === 0;
  }
  remainingHits(candidate: number): number {
    let hits = 0;
    for (const path of this.index.hits[candidate]!) { this.budget.spend(); if (this.covered[path] === 0) hits++; }
    return hits;
  }
}

function minimalChanges(chosen: number[], state: PlanState, candidates: ChangeCandidate[], budget: WorkBudget): number[] {
  budget.spend(state.covered.length + chosen.length);
  const counts = state.covered.slice();
  const redundant = new Set<number>();
  const ordered = [...chosen].sort((a, b) => { budget.spend(); return candidates[b]!.cost - candidates[a]!.cost || compare(candidates[a]!.id, candidates[b]!.id); });
  for (const candidate of ordered) {
    budget.spend();
    const needed = state.index.hits[candidate]!.some(path => { budget.spend(); return counts[path] === 1; });
    if (needed) continue;
    redundant.add(candidate);
    for (const path of state.index.hits[candidate]!) { budget.spend(); counts[path] = counts[path]! - 1; }
  }
  return chosen.filter(candidate => !redundant.has(candidate));
}

function seedPlan(state: PlanState, candidates: ChangeCandidate[], budget: WorkBudget, save: (chosen: number[], state: PlanState) => void): void {
  const chosen: number[] = [];
  while (!state.violations) {
    if (!state.uncovered) { save(chosen, state); return; }
    let best = -1, bestRatio = Infinity;
    for (const [candidate, change] of candidates.entries()) {
      budget.spend();
      const hits = state.remainingHits(candidate);
      if (!hits || !state.allows(candidate)) continue;
      const ratio = change.cost / hits;
      if (ratio < bestRatio || (ratio === bestRatio && compare(change.id, candidates[best]!.id) < 0)) { best = candidate; bestRatio = ratio; }
    }
    if (best === -1) return;
    chosen.push(best); state.change(best, 1);
  }
}

/** Weighted hitting set with both search-state and total incidence-work bounds. */
export function solveChanges(problem: ChangeProblem): ChangeSolution {
  assertProblem(problem);
  const maxSteps = bound(problem.maxSteps ?? 100_000, 1_000_000, "planner steps");
  const maxPlans = bound(problem.maxPlans ?? 3, 20, "plans");
  // Preserve useful small greedy seeds while bounding preprocessing and heuristic
  // work as well as search states. One work unit inspects an indexed incidence,
  // input entry, candidate, or sort comparison; array copies reserve their length.
  const budget = new WorkBudget(Math.max(10_000, Math.min(10_000_000, maxSteps * 256)));
  const plans: ChangePlan[] = [];
  let steps = 0, exhausted = false, rootBound = 0;
  try {
    const candidates = [...problem.candidates].sort((a, b) => { budget.spend(); return a.cost - b.cost || compare(a.id, b.id); });
    const index = indexProblem(problem, candidates, budget);
    rootBound = index.rootBound;
    budget.spend(problem.paths.length + problem.protectedIntegrations.length);
    const brokenPaths = sortedIds(problem.paths.map(p => p.id), budget);
    const preservedIntegrations = sortedIds(problem.protectedIntegrations.map(i => i.id), budget);
    const keys = new Map<ChangePlan, string>();
    function save(chosen: number[], state: PlanState): void {
      const minimal = minimalChanges(chosen, state, candidates, budget);
      budget.spend(minimal.length);
      const changes = sortedIds(minimal.map(i => candidates[i]!.id), budget);
      const key = canonical(changes);
      budget.spend(keys.size);
      if ([...keys.values()].includes(key)) return;
      budget.spend(minimal.length + brokenPaths.length + preservedIntegrations.length);
      const plan: ChangePlan = { changes, cost: minimal.reduce((sum, i) => sum + candidates[i]!.cost, 0), brokenPaths: [...brokenPaths], residualPaths: [], preservedIntegrations: [...preservedIntegrations] };
      // Reserve the small (at most 21-plan) sort before publishing a plan.
      // Exhaustion must never expose a partially sorted or over-limit result.
      budget.spend((plans.length + 1) ** 2);
      plans.push(plan); keys.set(plan, key);
      plans.sort((a, b) => a.cost - b.cost || a.changes.length - b.changes.length || compare(keys.get(a)!, keys.get(b)!));
      for (const removed of plans.splice(maxPlans)) keys.delete(removed);
    }
    seedPlan(new PlanState(index, budget), candidates, budget, save);
    const state = new PlanState(index, budget), visited = new Set<string>(), chosen: number[] = [];
    function search(cost: number): void {
      if (steps >= maxSteps) { exhausted = true; return; }
      steps++; budget.spend(chosen.length + 1);
      const key = [...chosen].sort((a, b) => { budget.spend(); return a - b; }).join(",");
      if (visited.has(key)) return;
      visited.add(key);
      if (state.violations || (plans.length === maxPlans && cost > plans.at(-1)!.cost)) return;
      const remaining = index.pathOrder.find(path => { budget.spend(); return state.covered[path] === 0; });
      if (remaining === undefined) { save(chosen, state); return; }
      for (const candidate of index.options[remaining]!) {
        if (exhausted) return;
        budget.spend();
        chosen.push(candidate); state.change(candidate, 1);
        search(cost + candidates[candidate]!.cost);
        state.change(candidate, -1); chosen.pop();
      }
    }
    search(0);
  } catch (error) {
    if (error !== WORK_EXHAUSTED) throw error;
    exhausted = true;
  }
  return { ...context(problem.context), verdict: !problem.evidenceComplete || exhausted ? "unknown" : plans.length ? "supported" : "refuted",
    status: exhausted ? "bounded" : plans.length ? "optimal" : "infeasible", plans,
    lowerBound: !exhausted && plans.length ? plans[0]!.cost : Number.isFinite(rootBound) ? rootBound : 0,
    upperBound: plans[0]?.cost ?? null, limits: { steps, maxSteps, exhausted, work: budget.work, maxWork: budget.maxWork },
    assumptions: ["Costs and protected integrations are operator-supplied. Proposed exclusions remain local and are not applied to Entra.", "The solver covers supplied modeled paths; incomplete evidence can hide additional paths."],
    missing: problem.evidenceComplete ? [] : ["complete-path-inventory"] };
}
