import { expect, it } from "vitest";
import { compareContract, evaluateContract, type AccessContract } from "./contracts";
import { compileSnapshot } from "./model";
import { edge, node, query, snapshot } from "./test-support";

const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "allowlist", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: [] };
const control: AccessContract = { version: 1, tenantId: query.tenantId, id: "control", kind: "no-control-path", sourceIds: ["person"], resourceIds: ["resource"] };

it("accepts an exactly fitting index and leaves the next fact for a larger budget", () => {
  const contract = { ...only, allowedPrincipalIds: ["client"] };
  const s = snapshot();
  const initial = evaluateContract(compileSnapshot(s), contract, 1);
  expect(initial).toMatchObject({ status: "pass", queries: 0, limits: { exhausted: false } });
  // One new isolated identity is one indexed input fact. This probes the
  // published remaining capacity without duplicating the budget formula.
  s.nodes.push(...Array.from({ length: initial.limits.maxWork - initial.limits.work }, (_, i) => node(`unrelated-${i}`)));
  const exact = evaluateContract(compileSnapshot(s), contract, 1);
  expect(exact).toMatchObject({ status: "pass", queries: 0, missing: [], limits: { exhausted: false } });
  expect(exact.limits.work).toBe(exact.limits.maxWork);
  s.nodes.push(node("one-more"));
  expect(evaluateContract(compileSnapshot(s), contract, 1)).toMatchObject({ status: "unknown", missing: ["budget:contract"], limits: { exhausted: true } });
  expect(evaluateContract(compileSnapshot(s), contract, 100)).toMatchObject({ status: "pass", missing: [], limits: { exhausted: false } });
});

it("charges imported conflict text before evaluating an otherwise empty allowlist", () => {
  const s = snapshot([]);
  for (let i = 0; i < 40; i++) {
    s.nodes.push(node(`unrelated-${i}`, "user"), node(`unrelated-${i}`, "servicePrincipal"));
  }
  const model = compileSnapshot(s);
  const importedEntries = model.nodes.length + model.edges.length + model.conflicts.length + model.conflicts.reduce((sum, c) => sum + c.variants.length, 0);
  const serializedCharacters = model.conflicts.flatMap(c => c.variants).reduce((sum, v) => sum + v.length, 0);
  const complete = evaluateContract(model, only);
  expect(complete).toMatchObject({ status: "pass", queries: 0, missing: [], limits: { exhausted: false } });
  // The index must account for each incoming record and each character it
  // accepts for possible JSON parsing, even if no authorization query follows.
  expect(complete.limits.work).toBeGreaterThanOrEqual(importedEntries + serializedCharacters);
  const bounded = evaluateContract(model, only, 2);
  expect(bounded).toMatchObject({ status: "unknown", queries: 0, witnesses: [], missing: ["budget:contract"], limits: { exhausted: true } });
  expect(bounded.limits.work).toBe(bounded.limits.maxWork);
});

it.each(["direct", "control"] as const)("bounds repeated conflicting coverage metadata in %s queries and resumes with more work", kind => {
  const s = snapshot(Array.from({ length: 80 }, (_, i) => edge(`grant-${i}`, `caller-${i}`, "resource")));
  s.nodes.push(...Array.from({ length: 80 }, (_, i) => node(`caller-${i}`)));
  const coverage = s.completion.collectors!.find(c => c.id === "servicePrincipals")!;
  coverage.endpoints = Array.from({ length: 70 }, (_, i) => `/servicePrincipals/page-${i}`);
  s.completion.collectors!.push({ ...coverage, state: "partial" });
  const sourceIds = s.edges.map(e => e.sourceId);
  if (kind === "control") s.edges = [];
  const model = compileSnapshot(s);
  const contract = kind === "direct" ? only : { ...control, sourceIds };
  const bounded = evaluateContract(model, contract, 200), complete = evaluateContract(model, contract, 20_000);
  expect(bounded.status).toBe("unknown");
  expect(bounded.limits.exhausted).toBe(true);
  expect(bounded.missing).toEqual(["budget:contract", "coverage:servicePrincipals"]);
  expect(bounded.queries).toBeGreaterThan(0);
  expect(bounded.queries).toBeLessThan(80);
  expect(Number.isFinite(bounded.limits.work)).toBe(true);
  expect(bounded.limits.work).toBe(bounded.limits.maxWork);
  expect(complete).toMatchObject({ status: "unknown", queries: 80, missing: ["coverage:servicePrincipals"], limits: { exhausted: false } });
  expect(complete.limits.work).toBeGreaterThan(bounded.limits.work);
});

it("bounds provenance rereads across alternative control paths before issuing a negative result", () => {
  const grant = edge("grant", "client", "resource");
  grant.evidence.sourceRecordIds = Array.from({ length: 1000 }, (_, i) => `source-record-${i}`);
  const s = snapshot([grant]);
  for (let i = 0; i < 8; i++) {
    s.nodes.push(node(`blueprint-${i}`, "application"));
    s.edges.push(edge(`owner-${i}`, "person", `blueprint-${i}`, "OWNS"), edge(`instance-${i}`, `blueprint-${i}`, "client", "INSTANTIATES_AS"));
  }
  const compiled = compileSnapshot(s);
  let provenanceReads = 0;
  const model = { ...compiled, edges: compiled.edges.map(e => e.id !== "grant" ? e : { ...e, evidence: { ...e.evidence, sourceRecordIds: new Proxy(e.evidence.sourceRecordIds, {
    get(target, key, receiver) {
      if (typeof key === "string" && /^\d+$/.test(key)) provenanceReads++;
      return Reflect.get(target, key, receiver);
    },
  }) } }) };
  expect(evaluateContract(model, control, 200)).toMatchObject({ status: "unknown", queries: 0, missing: ["budget:contract"], limits: { exhausted: true } });
  expect(provenanceReads).toBe(0);
  const complete = evaluateContract(model, control, 3000);
  expect(complete).toMatchObject({ status: "fail", queries: 1, missing: [], limits: { exhausted: false } });
  expect(complete.witnesses).toHaveLength(1);
  expect(complete.witnesses[0]!.paths).toEqual([["owner-0", "instance-0", "grant"]]);
  expect(complete.witnesses[0]!.facts.find(f => f.id === "relationship:grant")!.sourceRecordIds).toEqual([...grant.evidence.sourceRecordIds].sort());
  expect(provenanceReads).toBeGreaterThan(grant.evidence.sourceRecordIds.length);
  expect(provenanceReads).toBeLessThanOrEqual(complete.limits.work);
});

it("counts control preprocessing visits even when every source is disconnected", () => {
  const s = snapshot(Array.from({ length: 1500 }, (_, i) => {
    const e = edge(`irrelevant-${i}`, "client", "resource"); e.permissionIds = []; e.evidence.sourceRecordIds = []; return e;
  }));
  const sources = Array.from({ length: 10 }, (_, i) => `source-${i}`), targets = Array.from({ length: 10 }, (_, i) => `target-${i}`);
  s.nodes.push(...sources.map(id => node(id, "user")), ...targets.map(id => node(id)));
  const compiled = compileSnapshot(s);
  let relationshipVisits = 0;
  const model = { ...compiled, edges: compiled.edges.map(e => new Proxy(e, {
    get(target, key, receiver) {
      if (key === "type" || key === "id") relationshipVisits++;
      return Reflect.get(target, key, receiver);
    },
  })) };
  const contract = { ...control, sourceIds: sources, resourceIds: targets };
  const result = evaluateContract(model, contract, 200);
  expect(result).toMatchObject({ status: "unknown", missing: ["budget:contract"], limits: { exhausted: true } });
  expect(result.queries).toBeGreaterThan(0);
  expect(relationshipVisits).toBeLessThanOrEqual(result.limits.maxWork);
  expect(evaluateContract(compiled, contract, 5000)).toMatchObject({ status: "pass", queries: 100, missing: [], limits: { exhausted: false } });
});

it("bounds source-by-target query materialization before claiming no control path", () => {
  const s = snapshot([]);
  const sources = Array.from({ length: 100 }, (_, i) => `source-${i}`), targets = Array.from({ length: 100 }, (_, i) => `target-${i}`);
  s.nodes.push(...sources.map(id => node(id, "user")), ...targets.map(id => node(id)));
  const model = compileSnapshot(s), contract = { ...control, sourceIds: sources, resourceIds: targets };
  expect(evaluateContract(model, contract, 40)).toMatchObject({ status: "unknown", queries: 0, missing: ["budget:contract"], limits: { exhausted: true } });
  const larger = evaluateContract(model, contract, 80);
  expect(larger.queries).toBeGreaterThan(0);
  expect(larger.status).toBe("unknown");
});

it("retains early control violations while endpoint metadata bounds the remaining drift comparison", () => {
  const s = snapshot(Array.from({ length: 30 }, (_, i) => edge(`grant-${i}`, `caller-${i}`, "resource")));
  s.nodes.push(...Array.from({ length: 30 }, (_, i) => node(`caller-${i}`)));
  s.completion.collectors!.find(c => c.id === "servicePrincipals")!.endpoints = Array.from({ length: 3000 }, (_, i) => `/servicePrincipals/page-${i}`);
  const model = compileSnapshot(s), contract = { ...control, sourceIds: s.edges.map(e => e.sourceId) };
  const bounded = compareContract(model, model, contract, 200);
  expect(bounded).toMatchObject({ before: { status: "fail", limits: { exhausted: true } }, after: { status: "fail", limits: { exhausted: true } }, complete: false, addedPaths: [], removedPaths: [] });
  expect(bounded.before.witnesses.length).toBeGreaterThan(0);
  expect(bounded.before.witnesses).toHaveLength(bounded.before.queries);
  const complete = compareContract(model, model, contract, 20_000);
  expect(complete).toMatchObject({ before: { status: "fail", queries: 30 }, after: { status: "fail", queries: 30 }, complete: true, addedPaths: [], removedPaths: [] });
  expect(complete.before.witnesses.length).toBeGreaterThan(bounded.before.witnesses.length);
});

it("requires enough work to prove disconnected control paths absent across endpoint-heavy coverage", () => {
  const s = snapshot([]);
  const sources = Array.from({ length: 30 }, (_, i) => `source-${i}`);
  s.nodes.push(...sources.map(id => node(id, "user")));
  s.completion.collectors!.find(c => c.id === "servicePrincipals")!.endpoints = Array.from({ length: 3000 }, (_, i) => `/servicePrincipals/page-${i}`);
  const model = compileSnapshot(s), contract = { ...control, sourceIds: sources };

  // No recorded relationships exist, but a negative claim still needs the
  // complete coverage evidence for every requested source-to-resource query.
  const bounded = evaluateContract(model, contract, 200);
  expect(bounded).toMatchObject({ status: "unknown", witnesses: [], missing: ["budget:contract"], limits: { exhausted: true } });
  expect(bounded.queries).toBeGreaterThan(0);
  expect(bounded.queries).toBeLessThan(sources.length);
  expect(bounded.limits.work).toBe(bounded.limits.maxWork);

  const complete = evaluateContract(model, contract, 2000);
  expect(complete).toMatchObject({ status: "pass", queries: 30, witnesses: [], missing: [], limits: { exhausted: false } });
  expect(complete.limits.work).toBeGreaterThan(bounded.limits.work);
});
