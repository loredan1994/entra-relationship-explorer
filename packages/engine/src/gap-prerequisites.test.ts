import { expect, it } from "vitest";
import { evaluateAuthorization } from "./authorization";
import { planEvidenceGaps, suggestReads } from "./gaps";
import { compileSnapshot } from "./model";
import { node, query, snapshot } from "./test-support";

it("keeps a contradictory identity unresolved even when no collection is missing", () => {
  const source = snapshot();
  source.nodes.push(node("client", "user"));
  const proof = evaluateAuthorization(compileSnapshot(source), query);
  expect(proof).toMatchObject({ verdict: "conflicting", missing: [] });
  expect(planEvidenceGaps(proof)).toMatchObject({ verdict: "unknown", unresolved: ["object:client"], missing: ["object:client"] });
});

it("does not let a proposed collection read hide a separate contradictory identity", () => {
  const source = snapshot();
  source.nodes.push(node("client", "user"));
  source.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "partial";
  const result = planEvidenceGaps(evaluateAuthorization(compileSnapshot(source), query));
  expect(result).toMatchObject({ verdict: "unknown", unresolved: ["object:client"] });
  expect(result.plans[0]!.mayResolve).toEqual(["coverage:appRoleAssignments"]);
});

it("can propose recollection for contradictory collector records without calling the proof resolved", () => {
  const source = snapshot();
  const original = source.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  source.completion.collectors!.push({ ...original, state: "partial" });
  const proof = evaluateAuthorization(compileSnapshot(source), query);
  const result = planEvidenceGaps(proof);
  expect(proof.verdict).toBe("conflicting");
  expect(result.plans[0]!.mayResolve).toEqual(["coverage:appRoleAssignments"]);
  expect(result.unresolved).toEqual([]);
  expect(proof.verdict).toBe("conflicting");
});

it("federation collection plans include both application and managed-identity sources", () => {
  const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
  proof.missing = ["coverage:federatedIdentityCredentials"];
  const read = suggestReads(proof)[0]!;
  expect(read.endpoints).toEqual([
    "/applications/{id}/federatedIdentityCredentials",
    "/servicePrincipals?$select=id,servicePrincipalType&$expand=federatedIdentityCredentials($select=id,name,issuer,subject,audiences,description)",
  ]);
  expect(read.cost).toBe(2);
  expect(planEvidenceGaps(proof).plans[0]!.endpoints).toEqual([...read.endpoints].sort());
});

it("administrative role collection plans include role identities as well as assignments", () => {
  const proof = evaluateAuthorization(compileSnapshot(snapshot()), query);
  proof.missing = ["coverage:roles"];
  const read = suggestReads(proof)[0]!;
  expect(read.endpoints).toEqual([
    "/roleManagement/directory/roleDefinitions",
    "/roleManagement/directory/roleAssignments",
    "/roleManagement/directory/roleEligibilitySchedules",
  ]);
  expect(read.cost).toBe(3);
});
