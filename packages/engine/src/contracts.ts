import { evaluateAuthorization, QUERY_COLLECTORS } from "./authorization";
import { bound, canonical, compare, unique } from "./canonical";
import { assertTenant, complete, context } from "./model";
import type { AuthorizationQuery, EvidenceModel, EvidenceProof, WorkflowResult } from "./types";

export type AccessContract =
  | { version: 1; tenantId: string; id: string; kind: "only-principals"; resourceId: string; permissionId: string; allowedPrincipalIds: string[] }
  | { version: 1; tenantId: string; id: string; kind: "no-control-path"; sourceIds: string[]; resourceIds: string[] }
  | { version: 1; tenantId: string; id: string; kind: "require-grant"; principalId: string; resourceId: string; permissionId: string };
export interface ContractResult extends WorkflowResult { contractId: string; status: "pass" | "fail" | "unknown"; witnesses: EvidenceProof[]; queries: number }

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

function queriesFor(model: EvidenceModel, contract: AccessContract): AuthorizationQuery[] {
  const base = { tenantId: model.tenantId };
  if (contract.kind === "require-grant") return [{ ...base, kind: "application-permission", principalId: contract.principalId, resourceId: contract.resourceId, permissionId: contract.permissionId }];
  if (contract.kind === "no-control-path") return unique(contract.sourceIds).flatMap(principalId => unique(contract.resourceIds).map(resourceId => ({ ...base, kind: "control-path" as const, principalId, resourceId })));
  const variants = model.conflicts.filter(c => c.factId.startsWith("relationship:")).flatMap(c => c.variants.map(v => JSON.parse(v) as EvidenceModel["edges"][number]));
  return unique([...model.edges, ...variants].filter(e => e.type === "CAN_CALL_AS_APP" && e.targetId === contract.resourceId && !contract.allowedPrincipalIds.includes(e.sourceId)).map(e => e.sourceId))
    .map(principalId => ({ ...base, kind: "application-permission" as const, principalId, resourceId: contract.resourceId, permissionId: contract.permissionId }));
}

function evaluateQueries(model: EvidenceModel, contract: AccessContract, maxSteps: number) {
  bound(maxSteps, 250_000, "contract steps");
  const queries = queriesFor(model, contract);
  const results: EvidenceProof[] = [];
  let steps = 0, exhausted = false;
  for (const query of queries) {
    // Reserve one operation for this query in addition to relationship traversal.
    if (maxSteps - steps < 2) { exhausted = true; break; }
    const proof = evaluateAuthorization(model, query, { maxSteps: Math.min(50_000, maxSteps - steps - 1), maxDepth: 12, maxPaths: 128 });
    steps += proof.limits.steps + 1;
    exhausted ||= proof.limits.exhausted;
    results.push(proof);
  }
  return { results, steps, exhausted };
}

export function evaluateContract(model: EvidenceModel, input: AccessContract, maxSteps = 250_000): ContractResult {
  const contract = parseContract(canonical(input));
  assertTenant(model, contract.tenantId);
  const { results, steps, exhausted } = evaluateQueries(model, contract, maxSteps);
  const violations = results.filter(r => contract.kind === "require-grant" ? r.verdict === "refuted" : r.verdict === "supported");
  const collectors = QUERY_COLLECTORS[contract.kind === "no-control-path" ? "control-path" : "application-permission"];
  const missing = unique([...collectors.filter(c => !complete(model, c)).map(c => `coverage:${c}`), ...results.flatMap(r => r.missing),
    ...results.flatMap(r => r.conflicts.map(c => c.factId)), ...(exhausted ? ["budget:contract"] : [])]);
  const targetIds = contract.kind === "no-control-path" ? [...contract.sourceIds, ...contract.resourceIds] : [contract.resourceId];
  for (const id of targetIds) if (!model.nodes.some(n => n.id === id)) missing.push(`object:${id}`);
  const status = violations.length ? "fail" : missing.length || results.some(r => ["unknown", "conflicting"].includes(r.verdict)) ? "unknown" : "pass";
  const witnesses = violations.map(r => ({ ...r, paths: [...r.paths].sort((a, b) => a.length - b.length || compare(canonical(a), canonical(b))).slice(0, 1) }));
  return { ...context(model), contractId: contract.id, status, verdict: status === "pass" ? "supported" : status === "fail" ? "refuted" : "unknown", witnesses, queries: results.length,
    missing: unique(missing), limits: { steps, maxSteps, exhausted }, assumptions: ["Contract pass concerns only recorded configuration and supported control semantics. It requires complete relevant collection.", "Each violation displays a shortest recorded witness. No imported code runs and no tenant change is applied."] };
}

function semanticPaths(model: EvidenceModel, contract: AccessContract, maxSteps: number): { signatures: string[]; limited: boolean } {
  const signatures: string[] = [];
  const { results, exhausted } = evaluateQueries(model, contract, maxSteps);
  for (const proof of results) {
    for (const path of proof.paths) signatures.push(canonical(path.map(id => {
      const e = model.edges.find(e => e.id === id)!;
      return { type: e.type, sourceId: e.sourceId, targetId: e.targetId, permissionIds: e.permissionIds, consent: e.consent, scope: e.scope };
    })));
  }
  return { signatures: unique(signatures), limited: exhausted };
}

export function compareContract(modelBefore: EvidenceModel, modelAfter: EvidenceModel, contract: AccessContract, maxSteps = 250_000) {
  assertTenant(modelBefore, modelAfter.tenantId);
  const before = evaluateContract(modelBefore, contract, maxSteps), after = evaluateContract(modelAfter, contract, maxSteps);
  const a = semanticPaths(modelBefore, contract, maxSteps), b = semanticPaths(modelAfter, contract, maxSteps);
  return { before, after, addedPaths: b.signatures.filter(s => !a.signatures.includes(s)), removedPaths: a.signatures.filter(s => !b.signatures.includes(s)),
    complete: before.status !== "unknown" && after.status !== "unknown" && !before.missing.length && !after.missing.length && !a.limited && !b.limited,
    explanation: "Display names, timestamps and input ordering do not create semantic drift. Added alternative derivations do. Missing evidence leaves removals unconfirmed." };
}
