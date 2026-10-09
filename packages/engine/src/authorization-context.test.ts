import { expect, it } from "vitest";
import type { NodeKind } from "@entra-explorer/domain";
import { evaluateAuthorization } from "./authorization";
import { canonical } from "./canonical";
import { compileSnapshot } from "./model";
import { exportInvestigation, verifyInvestigation } from "./portable";
import { edge, query, snapshot } from "./test-support";

// A delegated grant describes access on behalf of a person. Merely supplying an
// existing object ID must not turn a workload, group, or application into one.
it.each<NodeKind>(["user", "application", "servicePrincipal", "managedIdentity", "group", "device", "directoryRole", "federatedCredential"])("requires a person for delegated user context: %s", kind => {
  const grant = edge("consent", "client", "resource", "CAN_CALL_DELEGATED");
  grant.consent = { audience: "all-users", principalId: null };
  const source = snapshot([grant]);
  source.nodes.find(n => n.id === "person")!.kind = kind;
  const proof = evaluateAuthorization(compileSnapshot(source), { ...query, kind: "delegated-permission", userId: "person" });
  expect(proof.verdict).toBe(kind === "user" ? "supported" : "refuted");
  expect(proof.paths).toEqual(kind === "user" ? [["consent"]] : []);
});

it.each(["control-path", "membership"] as const)("keeps a disconnected conflicting relationship outside a %s conclusion and export", async kind => {
  const source = kind === "control-path"
    ? snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")])
    : snapshot([edge("member", "person", "team", "MEMBER_OF")]);
  const q = { ...query, kind, principalId: "person", resourceId: kind === "membership" ? "team" : "resource", permissionId: undefined };
  const unrelated = edge("disconnected", "other", "nested", kind === "membership" ? "MEMBER_OF" : "OWNS");
  source.edges.push(unrelated, { ...unrelated, evidence: { ...unrelated.evidence, configured: false } });
  const model = compileSnapshot(source);
  const proof = evaluateAuthorization(model, q);
  expect(proof).toMatchObject({ verdict: "supported", conflicts: [] });
  expect(proof.dependencies).not.toContain("relationship:disconnected");
  const exported = await exportInvestigation(model, q);
  expect(canonical(exported.package)).not.toContain("disconnected");
  expect((await verifyInvestigation(canonical(exported.package))).proof.verdict).toBe("supported");
});

it("keeps a conflict relevant when its noncanonical source variant connects to the selected principal", () => {
  const disconnected = edge("disputed", "other", "client", "OWNS");
  const connected = edge("disputed", "person", "client", "OWNS");
  const source = snapshot([disconnected, connected, edge("grant", "client", "resource")]);
  const proof = evaluateAuthorization(compileSnapshot(source), { ...query, kind: "control-path", principalId: "person" });
  expect(proof.verdict).toBe("conflicting");
  expect(proof.conflicts.map(c => c.factId)).toEqual(["relationship:disputed"]);
});

it("does not traverse an unsupported relationship variant while retaining its disputed identity", () => {
  const source = snapshot([
    edge("disputed", "person", "team", "MEMBER_OF"),
    edge("disputed", "person", "client", "OWNS"),
    edge("private-membership", "client", "nested", "MEMBER_OF"),
  ]);
  const proof = evaluateAuthorization(compileSnapshot(source), { ...query, kind: "membership", principalId: "person", resourceId: "team", permissionId: undefined });
  expect(proof.verdict).toBe("conflicting");
  expect(proof.dependencies).toContain("relationship:disputed");
  expect(proof.dependencies).not.toContain("relationship:private-membership");
});

it.each<NodeKind>(["user", "group", "device", "servicePrincipal", "managedIdentity"])("application group assignments expand only direct user members: %s", kind => {
  const source = snapshot([edge("member", "person", "team", "MEMBER_OF"), edge("assignment", "team", "resource", "ASSIGNED_TO")]);
  source.nodes.find(n => n.id === "person")!.kind = kind;
  const q = { ...query, kind: "assignment" as const, principalId: "person", permissionId: undefined };
  const proof = evaluateAuthorization(compileSnapshot(source), q);
  expect(proof.verdict).toBe(kind === "user" ? "supported" : "refuted");
  expect(proof.paths).toEqual(kind === "user" ? [["member", "assignment"]] : []);
  // The assigned group itself still has a direct assignment; rejecting a
  // subgroup's inheritance must not hide the recorded parent assignment.
  expect(evaluateAuthorization(compileSnapshot(source), { ...q, principalId: "team" }).paths).toEqual([["assignment"]]);
});

it("keeps absent and conflicting delegated user records uncertain", () => {
  const grant = edge("consent", "client", "resource", "CAN_CALL_DELEGATED");
  grant.consent = { audience: "single-user", principalId: "person" };
  const source = snapshot([grant]);
  const q = { ...query, kind: "delegated-permission" as const, userId: "person" };
  const user = source.nodes.find(n => n.id === "person")!;
  source.nodes = source.nodes.filter(n => n.id !== "person");
  expect(evaluateAuthorization(compileSnapshot(source), q)).toMatchObject({ verdict: "unknown", missing: ["object:person"] });
  source.nodes.push(user, { ...user, kind: "group" });
  expect(evaluateAuthorization(compileSnapshot(source), q)).toMatchObject({ verdict: "conflicting", conflicts: [{ factId: "object:person" }] });
});

it("a valid source record ID cannot conceal a blank source record in the same grant", () => {
  const source = snapshot();
  source.edges[0]!.evidence.sourceRecordIds = ["recorded-grant", "   "];
  expect(evaluateAuthorization(compileSnapshot(source), query)).toMatchObject({ verdict: "unknown", missing: ["relationship:grant:complete-source"] });
});
