import { expect, it } from "vitest";
import { evaluateAuthorization } from "./authorization";
import { compareContract, evaluateContract, type AccessContract } from "./contracts";
import { compileSnapshot } from "./model";
import { edge, node, query, snapshot } from "./test-support";

const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "unapproved-callers", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: [] };
const required: AccessContract = { version: 1, tenantId: query.tenantId, id: "required-grant", kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" };

it.each(["missing", "failed-endpoint", "contradictory"] as const)("an empty caller inventory cannot pass an allowlist with %s assignment coverage", state => {
  const source = snapshot([]);
  const assignments = source.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  if (state === "missing") source.completion.collectors = source.completion.collectors!.filter(c => c !== assignments);
  if (state === "failed-endpoint") assignments.failedEndpoints = ["/servicePrincipals/resource/appRoleAssignedTo"];
  // Both records claim complete collection, but disagree on what was collected.
  if (state === "contradictory") source.completion.collectors!.push({ ...assignments, endpoints: ["/a-different-assignment-collection"] });
  const result = evaluateContract(compileSnapshot(source), only);
  expect(result).toMatchObject({ status: "unknown", queries: 0, witnesses: [], missing: ["coverage:appRoleAssignments"], limits: { exhausted: false } });
});

it.each(["servicePrincipals", "appRoleAssignments"] as const)("a grant cannot become an allowlist violation by discarding contradictory %s coverage", collector => {
  const source = snapshot();
  const original = source.completion.collectors!.find(c => c.id === collector)!;
  source.completion.collectors!.push({ ...original, endpoints: [`/${collector}/different-source`] });
  const model = compileSnapshot(source);
  const direct = evaluateAuthorization(model, query);
  expect(direct.verdict).toBe("conflicting");
  expect(direct.conflicts.map(c => c.factId)).toEqual([`coverage:${collector}`]);
  expect(evaluateContract(model, only)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: [`coverage:${collector}`], limits: { exhausted: false } });
  expect(evaluateContract(model, required)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: [`coverage:${collector}`] });
});

it.each(["client", "resource"])("preserves contradictory %s identities while projecting an otherwise complete grant", id => {
  const source = snapshot();
  source.nodes.push({ ...node(id), appId: "a-different-application-identity" });
  const model = compileSnapshot(source);
  const direct = evaluateAuthorization(model, query);
  expect(direct.verdict).toBe("conflicting");
  expect(direct.conflicts.map(c => c.factId)).toEqual([`object:${id}`]);
  expect(evaluateContract(model, only)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: [`object:${id}`] });
  expect(evaluateContract(model, required)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: [`object:${id}`] });
});

it("keeps the recorded endpoint of a canonical conflicting edge instead of inventing a missing object", () => {
  const source = snapshot([
    edge("grant", "client", "resource"),
    edge("grant", "client", "a-alternate-resource"),
  ]);
  source.nodes.push(node("a-alternate-resource"));
  const model = compileSnapshot(source);
  expect(model.edges[0]!.targetId).toBe("a-alternate-resource");
  const direct = evaluateAuthorization(model, query);
  expect(direct.verdict).toBe("conflicting");
  expect(direct.missing).toEqual([]);
  expect(direct.conflicts.map(c => c.factId)).toEqual(["relationship:grant"]);
  expect(evaluateContract(model, required)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: ["relationship:grant"] });
});

it("retains a conflicting canonical endpoint's identity evidence along with the conflicting grant", () => {
  const source = snapshot([
    edge("grant", "client", "resource"),
    edge("grant", "client", "a-alternate-resource"),
  ]);
  source.nodes.push(node("a-alternate-resource"), { ...node("a-alternate-resource"), appId: "another-app" });
  const model = compileSnapshot(source);
  const direct = evaluateAuthorization(model, query);
  expect(direct.conflicts.map(c => c.factId)).toEqual(["object:a-alternate-resource", "relationship:grant"]);
  expect(evaluateContract(model, required)).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: ["object:a-alternate-resource", "relationship:grant"] });
});

it("a required grant with no caller bucket returns the same negative evidence as direct authorization", () => {
  const model = compileSnapshot(snapshot([edge("elsewhere", "other", "blueprint")]));
  const direct = evaluateAuthorization(model, query, { maxSteps: 50_000, maxDepth: 12, maxPaths: 128 });
  expect(direct.verdict).toBe("refuted");
  expect(direct.paths).toEqual([]);
  const result = evaluateContract(model, required);
  expect(result).toMatchObject({ status: "fail", queries: 1, missing: [], limits: { exhausted: false } });
  expect(result.witnesses).toEqual([direct]);
  expect(evaluateContract(model, only)).toMatchObject({ status: "pass", queries: 0, missing: [], witnesses: [] });
});

it.each(["client", "resource"])("a required grant with no callers reports the missing %s instead of inventing a negative witness", id => {
  const source = snapshot([]);
  source.nodes = source.nodes.filter(n => n.id !== id);
  expect(evaluateContract(compileSnapshot(source), required)).toMatchObject({ status: "unknown", queries: 1, missing: [`object:${id}`], witnesses: [] });
});

it.each(["before", "after"] as const)("does not certify a contract comparison when the %s empty inventory lacks assignment coverage", side => {
  const complete = compileSnapshot(snapshot([]));
  const source = snapshot([]);
  source.completion.collectors = source.completion.collectors!.filter(c => c.id !== "appRoleAssignments");
  const incomplete = compileSnapshot(source);
  const result = side === "before" ? compareContract(incomplete, complete, required) : compareContract(complete, incomplete, required);
  expect(result).toMatchObject({ complete: false, addedPaths: [], removedPaths: [] });
  expect(result[side]).toMatchObject({ status: "unknown", queries: 1, witnesses: [], missing: ["coverage:appRoleAssignments"] });
  expect(result[side === "before" ? "after" : "before"]).toMatchObject({ status: "fail", queries: 1, missing: [] });
});

it("input ordering cannot hide simultaneous coverage, object and grant contradictions", () => {
  const source = snapshot([edge("grant", "client", "resource"), edge("grant", "client", "a-alternate-resource")]);
  source.nodes.push(node("a-alternate-resource"), { ...node("client"), appId: "another-identity" });
  const coverage = source.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  source.completion.collectors!.push({ ...coverage, endpoints: ["/another-assignment-collection"] });
  const reversed = structuredClone(source);
  reversed.edges.reverse(); reversed.nodes.reverse(); reversed.completion.collectors!.reverse();
  const before = compileSnapshot(source), after = compileSnapshot(reversed);
  const expectedMissing = ["coverage:appRoleAssignments", "object:client", "relationship:grant"];
  expect(evaluateContract(before, required)).toMatchObject({ status: "unknown", missing: expectedMissing, witnesses: [] });
  expect(evaluateContract(after, required)).toEqual(evaluateContract(before, required));
  expect(compareContract(before, after, required)).toMatchObject({ complete: false, addedPaths: [], removedPaths: [] });
});

it("propagates corrupt relationship evidence errors rather than misreporting them as budget exhaustion", () => {
  const model = compileSnapshot(snapshot());
  const corrupt = { ...model, conflicts: [{ factId: "relationship:grant", variants: ["{invalid evidence"] }] };
  expect(() => evaluateContract(corrupt, required)).toThrow(SyntaxError);
});
