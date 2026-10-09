import { evaluateAuthorization, pathMissing, QUERY_COLLECTORS } from "./authorization";
import { bound, canonical, compare, unique } from "./canonical";
import { assertTenant, context } from "./model";
import type { AuthorizationQuery, EvidenceModel, EvidenceProof, WorkflowResult } from "./types";

export type AccessContract =
  | { version: 1; tenantId: string; id: string; kind: "only-principals"; resourceId: string; permissionId: string; allowedPrincipalIds: string[] }
  | { version: 1; tenantId: string; id: string; kind: "no-control-path"; sourceIds: string[]; resourceIds: string[] }
  | { version: 1; tenantId: string; id: string; kind: "require-grant"; principalId: string; resourceId: string; permissionId: string };
export interface ContractResult extends WorkflowResult {
  contractId: string; status: "pass" | "fail" | "unknown"; witnesses: EvidenceProof[]; queries: number;
  limits: WorkflowResult["limits"] & { work: number; maxWork: number };
}

export function parseContract(text: string): AccessContract {
  if (new TextEncoder().encode(text).length > 100_000) throw new Error("Contract exceeds 100 KB.");
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Contract must be an object.");
  const c = value as Record<string, unknown>;
  const fields: Record<string, string[]> = { "only-principals": ["resourceId", "permissionId", "allowedPrincipalIds"], "no-control-path": ["sourceIds", "resourceIds"], "require-grant": ["principalId", "resourceId", "permissionId"] };
  if (c.version !== 1 || typeof c.kind !== "string" || !Object.hasOwn(fields, c.kind)) throw new Error("Unsupported contract schema.");
  const allowed = ["version", "tenantId", "id", "kind", ...fields[c.kind]!];
  if (Object.keys(c).some(k => !allowed.includes(k)) || allowed.some(k => !Object.hasOwn(c, k))) throw new Error("Unknown or missing contract fields.");
  for (const key of allowed.filter(k => k !== "version")) {
    const v = c[key];
    if (key.endsWith("Ids")) {
      if (!Array.isArray(v) || v.length > 100 || v.some(id => typeof id !== "string" || !id || id.length > 500) || new Set(v).size !== v.length) throw new Error("Invalid contract ID list.");
      if (key !== "allowedPrincipalIds" && !v.length) throw new Error("Contract requires targets.");
    } else if (typeof v !== "string" || !v || v.length > 500) throw new Error("Invalid contract identifier.");
  }
  return c as unknown as AccessContract;
}

const WORK_EXHAUSTED = Symbol("contract work exhausted");
class ContractWork {
  work = 0;
  constructor(readonly maxWork: number) {}
  spend(amount = 1): void {
    if (amount > this.maxWork - this.work) { this.work = this.maxWork; throw WORK_EXHAUSTED; }
    this.work += amount;
  }
}
interface ContractIndex {
  nodes: Map<string, EvidenceModel["nodes"][number]>;
  edges: Map<string, EvidenceModel["edges"][number]>;
  conflicts: Map<string, EvidenceModel["conflicts"][number]>;
  conflictOrder: Map<string, number>;
  coverageConflicts: EvidenceModel["conflicts"];
  callers: Map<string, EvidenceModel["edges"]>;
  missingCoverage: string[];
  edgeWork: Map<string, number>;
  conflictWork: Map<string, number>;
  coverageWork: number;
  metadataWork: number;
}

function indexContract(model: EvidenceModel, contract: AccessContract, budget: ContractWork): ContractIndex {
  const nodes: ContractIndex["nodes"] = new Map(), edges: ContractIndex["edges"] = new Map(), conflicts: ContractIndex["conflicts"] = new Map();
  const coverageConflicts: EvidenceModel["conflicts"] = [], callers: ContractIndex["callers"] = new Map(), conflictOrder = new Map<string, number>();
  const edgeWork = new Map<string, number>(), conflictWork = new Map<string, number>();
  let metadataWork = 0;
  for (const n of model.nodes) { budget.spend(); nodes.set(n.id, n); }
  for (const c of model.conflicts) {
    budget.spend(1 + c.variants.length); conflicts.set(c.factId, c);
    let size = 0;
    for (const variant of c.variants) { budget.spend(variant.length); size += variant.length; }
    conflictWork.set(c.factId, size); metadataWork += size;
    conflictOrder.set(c.factId, conflictOrder.size);
    if (c.factId.startsWith("coverage:")) coverageConflicts.push(c);
  }
  for (const edge of model.edges) {
    budget.spend(); edges.set(edge.id, edge);
    // Source IDs are checked for completeness, copied into facts and checked
    // again when choosing a witness. Permission IDs are searched at terminals.
    const size = edge.evidence.sourceRecordIds.length * 4 + (edge.permissionIds?.length ?? 0);
    edgeWork.set(edge.id, size);
    metadataWork += size * (contract.kind === "no-control-path" ? 128 : 1);
    if (contract.kind === "no-control-path") continue;
    const variants = conflicts.get(`relationship:${edge.id}`)?.variants ?? [];
    budget.spend(variants.length);
    const records = [edge, ...variants.map(v => JSON.parse(v) as typeof edge)];
    const sources = new Set(records.filter(e => e.type === "CAN_CALL_AS_APP" && e.targetId === contract.resourceId).map(e => e.sourceId));
    for (const source of sources) {
      budget.spend();
      const bucket = callers.get(source);
      if (bucket) bucket.push(edge);
      else callers.set(source, [edge]);
    }
  }
  const collectors = QUERY_COLLECTORS[contract.kind === "no-control-path" ? "control-path" : "application-permission"];
  budget.spend(collectors.length * model.coverage.length);
  const coverageWork = model.coverage.reduce((sum, c) => sum + (collectors.includes(c.id) ? c.endpoints.length : 0), 0);
  const missingCoverage = collectors.filter(id => {
    const coverage = model.coverage.find(c => c.id === id);
    return coverage?.state !== "complete" || coverage.failedEndpoints.length > 0 || conflicts.has(`coverage:${id}`);
  }).map(id => `coverage:${id}`);
  return { nodes, edges, conflicts, conflictOrder, coverageConflicts, callers, missingCoverage, edgeWork, conflictWork, coverageWork, metadataWork: metadataWork + coverageWork };
}

function queriesFor(model: EvidenceModel, contract: AccessContract, index: ContractIndex, budget: ContractWork): AuthorizationQuery[] {
  const base = { tenantId: model.tenantId };
  if (contract.kind === "require-grant") return [{ ...base, kind: "application-permission", principalId: contract.principalId, resourceId: contract.resourceId, permissionId: contract.permissionId }];
  if (contract.kind === "no-control-path") {
    budget.spend(contract.sourceIds.length * contract.resourceIds.length);
    return unique(contract.sourceIds).flatMap(principalId => unique(contract.resourceIds).map(resourceId => ({ ...base, kind: "control-path" as const, principalId, resourceId })));
  }
  budget.spend(index.callers.size);
  const allowed = new Set(contract.allowedPrincipalIds);
  return unique([...index.callers.keys()].filter(id => !allowed.has(id)))
    .map(principalId => ({ ...base, kind: "application-permission" as const, principalId, resourceId: contract.resourceId, permissionId: contract.permissionId }));
}

function directModel(model: EvidenceModel, query: AuthorizationQuery, index: ContractIndex, budget: ContractWork) {
  const edges = index.callers.get(query.principalId) ?? [];
  budget.spend(edges.length);
  const ids = new Set([query.principalId, query.resourceId, ...edges.flatMap(e => [e.sourceId, e.targetId])]);
  const nodes: EvidenceModel["nodes"] = [], conflicts = [...index.coverageConflicts];
  let metadataWork = index.coverageWork;
  for (const id of ids) {
    budget.spend();
    const node = index.nodes.get(id), conflict = index.conflicts.get(`object:${id}`);
    if (node) nodes.push(node);
    if (conflict) conflicts.push(conflict);
  }
  for (const edge of edges) {
    budget.spend();
    metadataWork += index.edgeWork.get(edge.id)!;
    const conflict = index.conflicts.get(`relationship:${edge.id}`);
    if (conflict) conflicts.push(conflict);
  }
  // Retain input ordering so projection does not reorder public proof evidence.
  conflicts.sort((a, b) => { budget.spend(); return index.conflictOrder.get(a.factId)! - index.conflictOrder.get(b.factId)!; });
  budget.spend(conflicts.length);
  for (const conflict of conflicts) metadataWork += index.conflictWork.get(conflict.factId)!;
  return { model: { ...model, edges, nodes, conflicts }, metadataWork };
}

function preprocessingCost(model: EvidenceModel, query: AuthorizationQuery): number {
  const collectors = QUERY_COLLECTORS[query.kind].length;
  const variants = model.conflicts.reduce((sum, c) => sum + c.variants.length + 1, 0);
  return 1 + model.nodes.length + model.edges.length * (query.kind === "control-path" ? 4 : 1)
    + variants * (collectors + 2) + model.coverage.length * collectors * 2;
}

function pathSignatures(proof: EvidenceProof, index: ContractIndex, budget: ContractWork): string[] {
  return proof.paths.map(path => {
    budget.spend(1 + path.length);
    return canonical(path.map(id => {
      const e = index.edges.get(id)!;
      budget.spend(e.permissionIds?.length ?? 0);
      return { type: e.type, sourceId: e.sourceId, targetId: e.targetId, permissionIds: e.permissionIds, consent: e.consent, scope: e.scope };
    }));
  });
}

function evaluateQueries(model: EvidenceModel, contract: AccessContract, maxSteps: number) {
  bound(maxSteps, 250_000, "contract steps");
  const budget = new ContractWork(Math.max(10_000, Math.min(10_000_000, maxSteps * 256)));
  const results: EvidenceProof[] = [], signatures: string[] = [];
  let steps = 0, exhausted = false, index: ContractIndex | undefined;
  try {
    index = indexContract(model, contract, budget);
    for (const query of queriesFor(model, contract, index, budget)) {
      if (maxSteps - steps < 2) { exhausted = true; break; }
      const selected = contract.kind === "no-control-path" ? { model, metadataWork: index.metadataWork } : directModel(model, query, index, budget);
      budget.spend(preprocessingCost(selected.model, query) + selected.metadataWork);
      const proof = evaluateAuthorization(selected.model, query, { maxSteps: Math.min(50_000, maxSteps - steps - 1), maxDepth: 12, maxPaths: 128 });
      steps += proof.limits.steps + 1;
      exhausted ||= proof.limits.exhausted;
      results.push(proof);
      signatures.push(...pathSignatures(proof, index, budget));
    }
  } catch (error) {
    if (error !== WORK_EXHAUSTED) throw error;
    exhausted = true;
  }
  return { results, signatures, index, steps, exhausted, work: budget.work, maxWork: budget.maxWork };
}

function shortestWitness(proof: EvidenceProof, edges: Map<string, EvidenceModel["edges"][number]>): EvidenceProof {
  // Refuting a required grant has no positive path. For prohibitions, select a
  // complete witness: shorter unresolved alternatives do not prove a violation.
  if (!proof.paths.length) return proof;
  const chosen = proof.paths.map((path, index) => ({ path, index }))
    .filter(item => pathMissing(proof.query, item.path.map(id => edges.get(id)!)).length === 0)
    .sort((a, b) => a.path.length - b.path.length || compare(canonical(a.path), canonical(b.path)))[0]!;
  const prefix = `path:${chosen.index}:`;
  const renumber = (id: string) => id.startsWith(prefix) ? `path:0:${id.slice(prefix.length)}` : id;
  return { ...proof, paths: [chosen.path], derivation: proof.derivation
    .filter(step => step.id === "query" || step.id.startsWith(prefix))
    .map(step => ({ ...step, id: renumber(step.id), inputs: step.inputs
      .filter(id => !id.startsWith("path:") || id.startsWith(prefix)).map(renumber) })) };
}

function evaluatedContract(model: EvidenceModel, input: AccessContract, maxSteps: number) {
  const contract = parseContract(canonical(input));
  assertTenant(model, contract.tenantId);
  const { results, signatures, index, steps, exhausted, work, maxWork } = evaluateQueries(model, contract, maxSteps);
  const violations = results.filter(r => contract.kind === "require-grant" ? r.verdict === "refuted" : r.verdict === "supported");
  const missing = unique([...(index?.missingCoverage ?? []), ...results.flatMap(r => r.missing),
    ...results.flatMap(r => r.conflicts.map(c => c.factId)), ...(exhausted ? ["budget:contract"] : [])]);
  // An allowlist may generate no authorization queries. Its target still needs
  // one unambiguous identity; contradictory records cannot establish absence.
  const identityIds = contract.kind === "no-control-path" ? [...contract.sourceIds, ...contract.resourceIds]
    : contract.kind === "require-grant" ? [contract.principalId, contract.resourceId] : [contract.resourceId];
  // An interrupted index cannot establish an absent object. Its budget gap
  // already keeps the contract unknown until indexing can finish.
  if (index) for (const id of identityIds) if (!index.nodes.has(id) || index.conflicts.has(`object:${id}`)) missing.push(`object:${id}`);
  const status = violations.length ? "fail" : missing.length || results.some(r => ["unknown", "conflicting"].includes(r.verdict)) ? "unknown" : "pass";
  const witnesses = violations.map(proof => shortestWitness(proof, index!.edges));
  const result: ContractResult = { ...context(model), contractId: contract.id, status, verdict: status === "pass" ? "supported" : status === "fail" ? "refuted" : "unknown", witnesses, queries: results.length,
    missing: unique(missing), limits: { steps, maxSteps, exhausted, work, maxWork }, assumptions: ["Contract pass concerns only recorded configuration and supported control semantics. It requires complete relevant collection.", "Each violation displays a shortest recorded witness. No imported code runs and no tenant change is applied."] };
  return { result, signatures: unique(signatures) };
}

export function evaluateContract(model: EvidenceModel, input: AccessContract, maxSteps = 250_000): ContractResult {
  return evaluatedContract(model, input, maxSteps).result;
}

export function compareContract(modelBefore: EvidenceModel, modelAfter: EvidenceModel, contract: AccessContract, maxSteps = 250_000) {
  assertTenant(modelBefore, modelAfter.tenantId);
  const a = evaluatedContract(modelBefore, contract, maxSteps), b = evaluatedContract(modelAfter, contract, maxSteps);
  const before = a.result, after = b.result, beforePaths = new Set(a.signatures), afterPaths = new Set(b.signatures);
  return { before, after, addedPaths: b.signatures.filter(s => !beforePaths.has(s)), removedPaths: a.signatures.filter(s => !afterPaths.has(s)),
    complete: before.status !== "unknown" && after.status !== "unknown" && !before.missing.length && !after.missing.length && !before.limits.exhausted && !after.limits.exhausted,
    explanation: "Display names, timestamps and input ordering do not create semantic drift. Added alternative derivations do. Missing evidence leaves removals unconfirmed." };
}
