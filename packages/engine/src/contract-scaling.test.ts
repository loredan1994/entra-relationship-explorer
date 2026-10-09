import { expect, it } from "vitest";
import { evaluateAuthorization } from "./authorization";
import { canonical } from "./canonical";
import { compareContract, evaluateContract, type AccessContract } from "./contracts";
import { compileSnapshot } from "./model";
import type { EvidenceModel } from "./types";
import { edge, node, query, snapshot } from "./test-support";

const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "callers", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: [] };

function counted(model: EvidenceModel) {
  let reads = 0;
  const observe = <T,>(values: T[]) => new Proxy(values, {
    get(target, key, receiver) {
      if (typeof key === "string" && /^\d+$/.test(key)) reads++;
      return Reflect.get(target, key, receiver);
    },
  });
  return { model: { ...model, nodes: observe(model.nodes), edges: observe(model.edges) }, reads: () => reads };
}

it("indexes a large allowlist once while preserving every violating caller", () => {
  const callers = 80;
  const s = snapshot(Array.from({ length: callers }, (_, i) => edge(`grant-${i}`, `caller-${i}`, "resource")));
  s.nodes.push(...Array.from({ length: callers }, (_, i) => node(`caller-${i}`)));
  const observed = counted(compileSnapshot(s));
  const result = evaluateContract(observed.model, only);
  expect(result).toMatchObject({ status: "fail", queries: callers, missing: [], limits: { exhausted: false } });
  expect(result.witnesses.map(w => w.query.principalId).sort()).toEqual(s.edges.map(e => e.sourceId).sort());
  expect(result.witnesses.every(w => w.paths.length === 1 && w.paths[0]!.length === 1 && w.verdict === "supported")).toBe(true);
  expect(observed.reads()).toBeLessThan(12 * (s.nodes.length + s.edges.length));
});

it.each(["supported", "refuted", "partial", "conflicting-source", "conflicting-target", "conflicting-kind"] as const)("preserves the complete authorization proof for a required grant: %s", scenario => {
  const s = snapshot();
  s.nodes.push(node("z-other"));
  if (scenario === "refuted") s.edges[0]!.permissionIds = ["different-id"];
  if (scenario === "partial") s.edges[0]!.evidence.completeness = "partial";
  if (scenario.startsWith("conflicting")) {
    const other = edge("grant", scenario === "conflicting-source" ? "z-other" : "client", scenario === "conflicting-target" ? "z-other" : "resource");
    if (scenario === "conflicting-kind") other.type = "OWNS";
    s.edges.push(other);
  }
  const model = compileSnapshot(s);
  const proof = evaluateAuthorization(model, query, { maxSteps: 50_000, maxDepth: 12, maxPaths: 128 });
  const required: AccessContract = { version: 1, tenantId: query.tenantId, id: "required", kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" };
  const result = evaluateContract(model, required);
  const expectedStatus = proof.verdict === "supported" ? "pass" : proof.verdict === "refuted" ? "fail" : "unknown";
  expect(result.status).toBe(expectedStatus);
  expect(result.missing).toEqual([...new Set([...proof.missing, ...proof.conflicts.map(c => c.factId)])].sort());
  if (proof.verdict === "refuted") expect(result.witnesses).toEqual([proof]);
  if (proof.verdict === "supported") expect(evaluateContract(model, only).witnesses).toEqual([proof]);
});

it("retains an unapproved conflicting variant when its canonical edge belongs to an approved caller", () => {
  const s = snapshot([edge("grant", "client", "resource"), edge("grant", "z-other", "resource")]);
  s.nodes.push(node("z-other"));
  expect(evaluateContract(compileSnapshot(s), { ...only, allowedPrincipalIds: ["client"] })).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: ["relationship:grant"] });
});

it("compares complete semantic additions and removals without repeated full-model queries", () => {
  const beforeSource = snapshot(Array.from({ length: 40 }, (_, i) => edge(`grant-${i}`, `caller-${i}`, "resource")));
  beforeSource.nodes.push(...Array.from({ length: 41 }, (_, i) => node(`caller-${i}`)));
  const afterSource = structuredClone(beforeSource);
  afterSource.edges = afterSource.edges.slice(1);
  afterSource.edges.push(edge("grant-40", "caller-40", "resource"));
  const before = counted(compileSnapshot(beforeSource)), after = counted(compileSnapshot(afterSource));
  const diff = compareContract(before.model, after.model, only);
  const signature = (id: string) => canonical([{ type: "CAN_CALL_AS_APP", sourceId: id, targetId: "resource", permissionIds: ["read-id"] }]);
  expect(diff).toMatchObject({ before: { status: "fail", queries: 40 }, after: { status: "fail", queries: 40 }, complete: true, addedPaths: [signature("caller-40")], removedPaths: [signature("caller-0")] });
  expect(before.reads() + after.reads()).toBeLessThan(12 * (beforeSource.nodes.length + beforeSource.edges.length + afterSource.nodes.length + afterSource.edges.length));
});

it("bounds repeated control-query preprocessing before claiming an absent path", () => {
  const s = snapshot([]);
  const sources = Array.from({ length: 10 }, (_, i) => `source-${i}`), targets = Array.from({ length: 10 }, (_, i) => `target-${i}`);
  s.nodes.push(...sources.map(id => node(id, "user")), ...targets.map(id => node(id)), ...Array.from({ length: 1000 }, (_, i) => node(`unrelated-${i}`)));
  const observed = counted(compileSnapshot(s));
  const contract: AccessContract = { version: 1, tenantId: query.tenantId, id: "control", kind: "no-control-path", sourceIds: sources, resourceIds: targets };
  const result = evaluateContract(observed.model, contract, 200);
  expect(result).toMatchObject({ status: "unknown", missing: ["budget:contract"], limits: { maxSteps: 200, exhausted: true } });
  expect(result.limits.work).toBe(result.limits.maxWork);
  expect(result.limits.maxWork).toBe(200 * 256);
  expect(result.queries).toBeLessThan(100);
  expect(observed.reads()).toBeLessThan(200 * 256 + 3 * s.nodes.length);
});

it("reports interrupted initial indexing instead of treating an unseen resource as absent", () => {
  const s = snapshot([]);
  s.nodes.push(...Array.from({ length: 10_100 }, (_, i) => node(`a-unrelated-${i}`)));
  const observed = counted(compileSnapshot(s));
  expect(evaluateContract(observed.model, only, 1)).toMatchObject({ status: "unknown", queries: 0, witnesses: [], missing: ["budget:contract"], limits: { steps: 0, exhausted: true, work: 10_000, maxWork: 10_000 } });
  expect(observed.reads()).toBeLessThanOrEqual(10_001);
});

it("bounds repeated coverage endpoint copies while retaining proven contract violations", () => {
  const callers = 80;
  const s = snapshot(Array.from({ length: callers }, (_, i) => edge(`grant-${i}`, `caller-${i}`, "resource")));
  s.nodes.push(...Array.from({ length: callers }, (_, i) => node(`caller-${i}`)));
  s.completion.collectors!.find(c => c.id === "servicePrincipals")!.endpoints = Array.from({ length: 2000 }, (_, i) => `/servicePrincipals/page-${i}`);
  const compiled = compileSnapshot(s);
  let endpointReads = 0;
  const model = { ...compiled, coverage: compiled.coverage.map(c => c.id !== "servicePrincipals" ? c : { ...c, endpoints: new Proxy(c.endpoints, {
    get(target, key, receiver) {
      if (typeof key === "string" && /^\d+$/.test(key)) endpointReads++;
      return Reflect.get(target, key, receiver);
    },
  }) }) };
  const result = evaluateContract(model, only, 200);
  expect(result).toMatchObject({ status: "fail", missing: ["budget:contract"], limits: { exhausted: true, work: 51_200, maxWork: 51_200 } });
  expect(result.queries).toBeGreaterThan(0);
  expect(result.queries).toBeLessThan(callers);
  expect(result.witnesses).toHaveLength(result.queries);
  expect(result.witnesses.every(w => w.verdict === "supported" && w.paths.length === 1)).toBe(true);
  const emittedEndpoints = result.witnesses.flatMap(w => w.facts).reduce((sum, f) => sum + (f.sourceEndpoints?.length ?? 0), 0);
  expect(emittedEndpoints).toBeLessThan(result.limits.maxWork);
  expect(endpointReads).toBeLessThan(result.limits.maxWork);
});
