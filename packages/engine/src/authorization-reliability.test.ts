import { expect, it } from "vitest";
import { createEvaluator, evaluateAuthorization } from "./authorization";
import { evaluateContract } from "./contracts";
import { compileSnapshot } from "./model";
import { edge, node, query, snapshot } from "./test-support";

const controlQuery = { tenantId: query.tenantId, kind: "control-path" as const, principalId: "person", resourceId: "resource" };
const contract = { version: 1 as const, tenantId: query.tenantId, id: "no-control", kind: "no-control-path" as const, sourceIds: ["person"], resourceIds: ["resource"] };
const controlSnapshot = () => snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")]);

it("cannot refute a path or pass its prohibition when an intermediate object is missing", () => {
  const source = controlSnapshot();
  source.nodes = source.nodes.filter(n => n.id !== "client");
  const model = compileSnapshot(source);
  const proof = evaluateAuthorization(model, controlQuery);
  expect(proof).toMatchObject({ verdict: "unknown", paths: [], missing: ["object:client"] });
  expect(evaluateContract(model, contract)).toMatchObject({ status: "unknown", witnesses: [], missing: ["object:client"] });
});

it("retains an intermediate object conflict even when its canonical type rejects the path", () => {
  const source = controlSnapshot();
  source.nodes.push(node("client", "application"));
  const model = compileSnapshot(source);
  expect(model.nodes.find(n => n.id === "client")?.kind).toBe("application");
  const proof = evaluateAuthorization(model, controlQuery);
  expect(proof).toMatchObject({ verdict: "conflicting", paths: [] });
  expect(proof.conflicts.map(c => c.factId)).toEqual(["object:client"]);
  expect(proof.dependencies).toContain("object:client");
  expect(evaluateContract(model, contract)).toMatchObject({ status: "unknown", missing: ["object:client"] });
});

it("checks an intermediate membership object without treating disconnected object conflicts as relevant", () => {
  const source = snapshot([edge("member", "person", "team", "MEMBER_OF"), edge("assign", "team", "resource", "ASSIGNED_TO")]);
  source.nodes.push(node("team", "application"));
  const q = { ...controlQuery, kind: "assignment" as const };
  expect(evaluateAuthorization(compileSnapshot(source), q).verdict).toBe("conflicting");
  source.edges = [];
  const proof = evaluateAuthorization(compileSnapshot(source), q);
  expect(proof).toMatchObject({ verdict: "refuted", conflicts: [], missing: [] });
});

it("preserves exact traversal bounds for a high-fanout source", () => {
  const source = snapshot(Array.from({ length: 10_000 }, (_, index) => edge(`grant-${index.toString().padStart(5, "0")}`, "client", "resource")));
  const proof = evaluateAuthorization(compileSnapshot(source), query, { maxSteps: 1, maxDepth: 1, maxPaths: 1 });
  expect(proof).toMatchObject({ verdict: "unknown", paths: [["grant-00000"]], missing: ["budget:search"], limits: { steps: 1, exhausted: true } });
});

it("invalidates cached results when an external mutable model changes without replace", () => {
  const model = structuredClone(compileSnapshot(snapshot()));
  const evaluator = createEvaluator(model);
  expect(evaluator.evaluate(query)).toMatchObject({ reused: false, proof: { verdict: "supported" } });
  expect(evaluator.evaluate(query)).toMatchObject({ reused: true, proof: { verdict: "supported" } });
  model.edges = [];
  expect(evaluator.evaluate(query)).toMatchObject({ reused: false, proof: { verdict: "refuted" } });
  const refreshed = { ...compileSnapshot(snapshot()), snapshotIds: ["new-snapshot"] };
  expect(evaluator.replace(refreshed)).toEqual({ invalidated: 1, retained: 0 });
  expect(evaluator.evaluate(query)).toMatchObject({ reused: false, proof: { verdict: "supported", snapshotIds: ["new-snapshot"] } });
});
