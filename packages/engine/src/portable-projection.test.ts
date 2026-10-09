import { expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot, exportInvestigation, verifyInvestigation } from "./index";
import { edge, node, query, snapshot } from "./test-support";

it("does not use unrelated conflicting relationship types to expand a membership export", async () => {
  const owner = edge("unrelated-owner", "person", "client", "OWNS");
  const s = snapshot([
    edge("membership", "person", "team", "MEMBER_OF"),
    edge("private-membership", "client", "nested", "MEMBER_OF"),
    owner, { ...owner, evidence: { ...owner.evidence, configured: false } },
  ]);
  const q = { ...query, kind: "membership" as const, principalId: "person", resourceId: "team", permissionId: undefined };
  const result = await exportInvestigation(compileSnapshot(s), q);
  expect(result.package.snapshot.edges.map(e => e.id)).toEqual(["membership"]);
  expect(result.package.snapshot.nodes.map(n => n.id)).toEqual(["person", "team"]);
  const replay = await verifyInvestigation(canonical(result.package));
  expect(replay.proof.verdict).toBe("supported");
  expect(replay.proof.paths).toEqual([["membership"]]);
});

it("omits disconnected conflicting objects and unrelated collector families", async () => {
  const s = snapshot();
  s.nodes.push(node("private-object", "user"), node("private-object", "group"));
  const roles = s.completion.collectors!.find(c => c.id === "roles")!;
  s.completion.collectors!.push({ ...roles, state: "denied" });
  const result = await exportInvestigation(compileSnapshot(s), query);
  expect(result.package.snapshot.nodes.map(n => n.id)).toEqual(["client", "resource"]);
  expect(result.package.snapshot.completion.collectors!.map(c => c.id)).toEqual(["appRoleAssignments", "servicePrincipals"]);
  expect(canonical(result.package)).not.toContain("private-object");
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
});

it("preserves collection-level and other-family evidence endpoints for a delegated query", async () => {
  const consent = edge("consent", "client", "resource", "CAN_CALL_DELEGATED");
  consent.consent = { audience: "all-users", principalId: null };
  const s = snapshot([consent]);
  const collector = s.completion.collectors!.find(c => c.id === "delegatedPermissionGrants")!;
  collector.endpoints = ["/oauth2PermissionGrants", "/servicePrincipals", "/oauth2PermissionGrants/consent", "/users/person", "/users/other", "/groups/private-group/members"];
  const result = await exportInvestigation(compileSnapshot(s), { ...query, kind: "delegated-permission", userId: "person" });
  expect(result.package.snapshot.completion.collectors!.find(c => c.id === "delegatedPermissionGrants")!.endpoints)
    .toEqual(["/oauth2PermissionGrants", "/oauth2PermissionGrants/consent", "/servicePrincipals", "/users/person"]);
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
});

it("retains conflicting assignment candidates required to replay a resource's evidence boundary", async () => {
  const disputed = edge("disputed-assignment", "other", "resource", "ASSIGNED_TO");
  const s = snapshot([edge("assignment", "person", "resource", "ASSIGNED_TO"), disputed, { ...disputed, evidence: { ...disputed.evidence, configured: false } }]);
  const q = { ...query, kind: "assignment" as const, principalId: "person", permissionId: undefined };
  const result = await exportInvestigation(compileSnapshot(s), q);
  expect([...new Set(result.package.snapshot.edges.map(e => e.id))].sort()).toEqual(["assignment", "disputed-assignment"]);
  expect([...new Set(result.package.snapshot.edges.filter(e => e.id === "disputed-assignment").map(e => e.evidence.configured))].sort()).toEqual([false, true]);
  const replay = await verifyInvestigation(canonical(result.package));
  expect(replay.proof.verdict).toBe("conflicting");
  expect(replay.proof.conflicts.map(c => c.factId)).toEqual(["relationship:disputed-assignment"]);
});

it("redacts a recorded scope identifier even when the requested scope differs and the scope object was not resolved", async () => {
  const unit = "a0123456-789a-bcde-f012-3456789abcde";
  const assignment = edge("assignment", "person", "role", "ACTIVE_IN_ROLE");
  assignment.scope = { directoryScopeId: `/administrativeUnits/${unit}`, objectId: null };
  const s = snapshot([assignment]);
  const q = { ...query, kind: "active-role" as const, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: "/" };
  const result = await exportInvestigation(compileSnapshot(s), q, "pseudonymized");
  expect(result.privateMapping[unit]).toMatch(/^p\d+$/);
  expect(result.package.snapshot.edges[0]!.scope).toEqual({ directoryScopeId: `/administrativeUnits/${result.privateMapping[unit]}`, objectId: null });
  expect(canonical(result.package)).not.toContain(unit);
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("refuted");
});
