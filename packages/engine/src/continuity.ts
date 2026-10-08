import type { CredentialMetadata } from "@entra-explorer/domain";
import { bound, canonical, compare, timestamp, unique } from "./canonical";
import { context } from "./model";
import type { EvidenceModel, TimeWindow, Verdict, WorkflowResult } from "./types";

export interface DeploymentStage {
  credentialKey: string;
  availableFrom: string | null;
  /** Omitted: declared available through the horizon. Null: retirement time unknown. */
  unavailableFrom?: string | null;
}
export interface WorkloadDependency { id: string; credentialKeys: string[]; requires: string[] }
export interface ContinuityPlan {
  tenantId: string;
  horizon: TimeWindow;
  clockSkewSeconds: number;
  deployments: DeploymentStage[];
  workloads: WorkloadDependency[];
}
export interface ContinuityInterval extends TimeWindow { workloadId: string; verdict: Verdict; credentials: string[]; rollbackAvailable: boolean }

function validatePlan(plan: ContinuityPlan): { start: number; end: number } {
  const start = timestamp(plan.horizon.startsAt), end = timestamp(plan.horizon.endsAt);
  if (start >= end) throw new Error("Rotation horizon must have a start before its end.");
  if (!Number.isFinite(plan.clockSkewSeconds) || plan.clockSkewSeconds < 0 || plan.clockSkewSeconds > 86_400) throw new Error("Invalid clock skew budget.");
  if (plan.deployments.length > 1_000 || plan.workloads.length > 200) throw new Error("Rotation plan exceeds input limits.");
  if (new Set(plan.deployments.map(s => s.credentialKey)).size !== plan.deployments.length || new Set(plan.workloads.map(w => w.id)).size !== plan.workloads.length) throw new Error("Duplicate rotation inputs.");
  return { start, end };
}

function timeBoundaries(plan: ContinuityPlan, metadata: Map<string, CredentialMetadata>, stages: Map<string, DeploymentStage>, missing: Set<string>, start: number, end: number, skew: number): number[] {
  const bounds = new Set([start, end]);
  for (const key of unique(plan.workloads.flatMap(w => w.credentialKeys))) {
    const c = metadata.get(key), d = stages.get(key);
    if (!c?.startsAt || !c.expiresAt) missing.add(`credential:${key}:validity`);
    if (!d?.availableFrom || d.unavailableFrom === null) missing.add(`deployment:${key}`);
    const times = [c?.startsAt ? timestamp(c.startsAt) + skew : null, c?.expiresAt ? timestamp(c.expiresAt) - skew : null,
      d?.availableFrom ? timestamp(d.availableFrom) + skew : null, d?.unavailableFrom ? timestamp(d.unavailableFrom) - skew : null];
    times.forEach(t => { if (t !== null && t > start && t < end) bounds.add(t); });
  }
  return [...bounds].sort((a, b) => a - b);
}

export function simulateContinuity(model: EvidenceModel, plan: ContinuityPlan, maxSteps = 1_000_000): WorkflowResult & { intervals: ContinuityInterval[]; affectedByCredential: Record<string, string[]> } {
  if (plan.tenantId !== model.tenantId) throw new Error("Cross-tenant plan rejected.");
  bound(maxSteps, 1_000_000, "continuity steps");
  const { start, end } = validatePlan(plan);
  const metadata = new Map<string, CredentialMetadata>(model.nodes.flatMap(n => (n.credentials ?? []).map(c => [`${n.id}/${c.id}`, c] as const)));
  const stages = new Map(plan.deployments.map(d => [d.credentialKey, d]));
  const keys = plan.workloads.flatMap(w => w.credentialKeys);
  const conflicts = model.conflicts.filter(c => c.factId.startsWith("object:") && keys.some(key => key.startsWith(`${c.factId.slice(7)}/`)));
  const missing = new Set<string>(conflicts.map(c => c.factId));
  const skew = plan.clockSkewSeconds * 1_000;
  const times = timeBoundaries(plan, metadata, stages, missing, start, end, skew);
  function credentialState(key: string, at: number): Verdict {
    if (conflicts.some(c => key.startsWith(`${c.factId.slice(7)}/`))) return "unknown";
    const c = metadata.get(key), d = stages.get(key);
    if ((c?.startsAt && at < timestamp(c.startsAt) + skew) || (c?.expiresAt && at >= timestamp(c.expiresAt) - skew)) return "refuted";
    if ((d?.availableFrom && at < timestamp(d.availableFrom) + skew) || (d?.unavailableFrom && at >= timestamp(d.unavailableFrom) - skew)) return "refuted";
    return c?.startsAt && c.expiresAt && d?.availableFrom && d.unavailableFrom !== null ? "supported" : "unknown";
  }
  const intervals: ContinuityInterval[] = [];
  let steps = 0;
  let exhausted = false;
  for (let i = 0; i < times.length - 1; i++) {
    const at = times[i]!;
    const cache = new Map<string, Verdict>();
    function workloadState(id: string, active: Set<string>): Verdict {
      if (steps === maxSteps) { exhausted = true; return "unknown"; }
      steps++;
      if (active.has(id)) { missing.add(`dependency-cycle:${id}`); return "unknown"; }
      if (cache.has(id)) return cache.get(id)!;
      const w = plan.workloads.find(w => w.id === id);
      if (!w) { missing.add(`workload:${id}`); return "unknown"; }
      const states = w.credentialKeys.map(k => credentialState(k, at));
      const own = states.includes("supported") ? "supported" : states.includes("unknown") || !states.length ? "unknown" : "refuted";
      const dependencies = w.requires.map(dep => workloadState(dep, new Set([...active, id])));
      const all = [own, ...dependencies];
      const verdict = all.includes("refuted") ? "refuted" : all.includes("unknown") ? "unknown" : "supported";
      cache.set(id, verdict);
      return verdict;
    }
    for (const w of [...plan.workloads].sort((a, b) => compare(a.id, b.id))) {
      const verdict = workloadState(w.id, new Set());
      const credentials = unique(w.credentialKeys.filter(k => credentialState(k, at) === "supported"));
      intervals.push({ workloadId: w.id, startsAt: new Date(at).toISOString(), endsAt: new Date(times[i + 1]!).toISOString(), verdict,
        credentials, rollbackAvailable: verdict === "supported" && credentials.length > 1 });
    }
    if (exhausted) break;
  }
  const merged: ContinuityInterval[] = [];
  for (const item of intervals.sort((a, b) => compare(a.workloadId, b.workloadId) || compare(a.startsAt, b.startsAt))) {
    const prior = merged.at(-1);
    if (prior && prior.workloadId === item.workloadId && prior.endsAt === item.startsAt && prior.verdict === item.verdict && canonical(prior.credentials) === canonical(item.credentials)) prior.endsAt = item.endsAt;
    else merged.push({ ...item });
  }
  const affectedByCredential: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  for (const key of unique(plan.workloads.flatMap(w => w.credentialKeys))) {
    const affected = new Set(plan.workloads.filter(w => w.credentialKeys.includes(key)).map(w => w.id));
    for (let i = 0; i < plan.workloads.length; i++) for (const w of plan.workloads) if (w.requires.some(id => affected.has(id))) affected.add(w.id);
    affectedByCredential[key] = unique([...affected]);
  }
  return { ...context(model), verdict: exhausted || !merged.length ? "unknown" : merged.some(i => i.verdict === "refuted") ? "refuted" : merged.some(i => i.verdict === "unknown") ? "unknown" : "supported",
    intervals: merged, affectedByCredential, missing: unique([...missing]), limits: { steps, maxSteps, exhausted },
    assumptions: ["Deployment stages and workload dependencies are operator-supplied assumptions, not observed use or proof of secret possession.", "Validity and declared deployment intervals are half-open and conservatively shortened by the clock-skew budget. Rollback indicates overlapping declared availability only."] };
}
