import { expect, it } from "vitest";
import { compareContract, evaluateContract, parseContract, type AccessContract } from "./contracts";
import { compileSnapshot } from "./model";
import { edge, node, query, snapshot } from "./test-support";

const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "unapproved-callers", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: [] };
const control: AccessContract = { version: 1, tenantId: query.tenantId, id: "control", kind: "no-control-path", sourceIds: ["person"], resourceIds: ["resource"] };

it.each(["only-principals", "no-control-path", "require-grant"])("rejects a selector array masquerading as the %s contract kind", kind => {
  expect(() => parseContract(JSON.stringify({ ...only, kind: [kind] }))).toThrow("Unsupported contract schema.");
});

it("shares the remaining traversal budget across multiple unapproved callers", () => {
  const s = snapshot([
    edge("client-read-a", "client", "resource"), edge("client-read-b", "client", "resource"),
    edge("other-read-a", "other", "resource"), edge("other-read-b", "other", "resource"),
  ]);
  s.nodes.find(n => n.id === "other")!.kind = "servicePrincipal";
  const result = evaluateContract(compileSnapshot(s), only, 5);
  expect(result).toMatchObject({
    status: "fail", queries: 2,
    missing: ["budget:contract", "budget:search"],
    limits: { steps: 5, maxSteps: 5, exhausted: true },
  });
  expect(result.witnesses.map(w => w.query.principalId)).toEqual(["client"]);
  expect(result.witnesses[0]!.paths).toEqual([["client-read-a"]]);
});

it("reports control-specific collection gaps even when its budget prevents the first query", () => {
  const s = snapshot([]); s.completion.collectors!.find(c => c.id === "owners")!.state = "denied";
  expect(evaluateContract(compileSnapshot(s), control, 1)).toMatchObject({
    status: "unknown", queries: 0, missing: ["budget:contract", "coverage:owners"],
    limits: { steps: 0, maxSteps: 1, exhausted: true },
  });
});

it("does not require owner inventory to accept an application-permission allowlist", () => {
  const s = snapshot(); s.completion.collectors!.find(c => c.id === "owners")!.state = "denied";
  expect(evaluateContract(compileSnapshot(s), { ...only, allowedPrincipalIds: ["client"] })).toMatchObject({
    status: "pass", verdict: "supported", queries: 0, missing: [], witnesses: [],
  });
});

it("reports absent contract endpoints even if no authorization query fits the budget", () => {
  expect(evaluateContract(compileSnapshot(snapshot([])), {
    ...control, sourceIds: ["missing-source"], resourceIds: ["missing-target"],
  }, 1)).toMatchObject({
    status: "unknown", queries: 0,
    missing: ["budget:contract", "object:missing-source", "object:missing-target"],
  });
});

it("chooses the shortest violation even when a longer path sorts first by relationship ID", () => {
  const s = snapshot([
    edge("a-long-owner", "person", "blueprint", "OWNS"),
    edge("instance", "blueprint", "client", "INSTANTIATES_AS"),
    edge("z-short-owner", "person", "client", "OWNS"),
    edge("grant", "client", "resource"),
  ]);
  const result = evaluateContract(compileSnapshot(s), control);
  expect(result.status).toBe("fail");
  expect(result.witnesses).toHaveLength(1);
  expect(result.witnesses[0]!.paths).toEqual([["z-short-owner", "grant"]]);
});

it.each(["before", "after"] as const)("does not call semantic drift complete when the %s inventory is partial despite a certain violation", side => {
  const complete = compileSnapshot(snapshot());
  const partialSource = snapshot(); partialSource.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "partial";
  const partial = compileSnapshot(partialSource);
  const result = side === "before" ? compareContract(partial, complete, only) : compareContract(complete, partial, only);
  expect(result).toMatchObject({ before: { status: "fail" }, after: { status: "fail" }, complete: false, addedPaths: [], removedPaths: [] });
  expect(result[side].missing).toEqual(["coverage:appRoleAssignments"]);
});

it.each([false, true])("does not pass an allowlist with contradictory resource identities when allowed grants exist=%s", hasAllowedGrant => {
  const s = snapshot(hasAllowedGrant ? [edge("allowed", "client", "resource")] : []);
  s.nodes.push(node("resource", "user"));
  const result = evaluateContract(compileSnapshot(s), { ...only, allowedPrincipalIds: ["client"] });
  expect(result).toMatchObject({ status: "unknown", verdict: "unknown", queries: 0, witnesses: [], missing: ["object:resource"] });
});

it.each(["before", "after"] as const)("does not confirm complete drift when the %s target is contradictory and neither scan generates a query", side => {
  const clean = compileSnapshot(snapshot([]));
  const s = snapshot([]); s.nodes.push(node("resource", "user"));
  const conflicting = compileSnapshot(s);
  const result = side === "before" ? compareContract(conflicting, clean, only) : compareContract(clean, conflicting, only);
  expect(result).toMatchObject({ complete: false, addedPaths: [], removedPaths: [] });
  expect(result[side]).toMatchObject({ status: "unknown", queries: 0, missing: ["object:resource"] });
  expect(result[side === "before" ? "after" : "before"]).toMatchObject({ status: "pass", queries: 0, missing: [] });
});

it.each([false, true])("accepts an unambiguous resource with no unapproved callers when allowed grants exist=%s", hasAllowedGrant => {
  const s = snapshot(hasAllowedGrant ? [edge("allowed", "client", "resource")] : []);
  s.nodes.push(node("unrelated", "user"), node("unrelated", "servicePrincipal"));
  const model = compileSnapshot(s);
  const contract = { ...only, allowedPrincipalIds: ["client", "future-approved-caller"] };
  expect(evaluateContract(model, contract)).toMatchObject({ status: "pass", queries: 0, missing: [], witnesses: [] });
  expect(compareContract(model, model, contract)).toMatchObject({ complete: true, addedPaths: [], removedPaths: [] });
});

it("checks conflicting control source identities before a budget allows any query", () => {
  const s = snapshot([]); s.nodes.push(node("person", "servicePrincipal"));
  expect(evaluateContract(compileSnapshot(s), control, 1)).toMatchObject({ status: "unknown", queries: 0, missing: ["budget:contract", "object:person"] });
});

it.each(["missing", "conflicting"] as const)("checks a required grant's %s principal before a budget allows any query", state => {
  const s = snapshot([]);
  if (state === "missing") s.nodes = s.nodes.filter(n => n.id !== "client");
  else s.nodes.push(node("client", "user"));
  const required: AccessContract = { version: 1, tenantId: query.tenantId, id: "required", kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" };
  expect(evaluateContract(compileSnapshot(s), required, 1)).toMatchObject({ status: "unknown", queries: 0, missing: ["budget:contract", "object:client"] });
});
