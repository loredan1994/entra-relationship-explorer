import { expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot, exportInvestigation, verifyInvestigation } from "./index";
import { edge, node, query, snapshot } from "./test-support";

const guid = "a0123456-789a-bcde-f012-3456789abcde";
const escapedGuid = [...guid].map(c => `%${c.charCodeAt(0).toString(16)}`).join("");

it.each([
  `id eq '${guid}'`,
  encodeURIComponent(`id eq '${guid}'`),
  `id%20eq%20%27${escapedGuid}%27`,
  `id eq '${guid}' and malformed eq '%'`,
  `id%20eq%20%27${escapedGuid}%27 and malformed eq '%'`,
])("pseudonymizes complete identifiers inside endpoint expressions: %s", async expression => {
  const s = snapshot();
  const endpoint = `/servicePrincipals/resource/appRoleAssignedTo?$filter=${expression}`;
  s.edges[0]!.evidence.sourceEndpoint = endpoint;
  s.nodes[0]!.sourceEndpoint = `/servicePrincipals?$filter=${expression}`;
  const collector = s.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  collector.endpoints = [endpoint];
  collector.failedEndpoints = [endpoint];
  collector.state = "partial";
  const result = await exportInvestigation(compileSnapshot(s), query, "pseudonymized");
  const text = canonical(result.package);
  expect(result.privateMapping[guid]).toMatch(/^p\d+$/);
  expect(text).not.toContain(guid);
  expect(text.toLowerCase()).not.toContain(escapedGuid);
  expect(result.package.snapshot.edges[0]!.evidence.sourceEndpoint).toContain(result.privateMapping[guid]);
  expect((await verifyInvestigation(text)).verified).toBe(true);
});

it("preserves unrelated partial tokens, malformed escapes and inherited object names", async () => {
  const s = snapshot();
  s.edges[0]!.evidence.sourceEndpoint = `/constructor/toString/prototype/resource?$filter=prefix-${guid}-suffix&value=%broken&encoded=unchanged%2fvalue`;
  const result = await exportInvestigation(compileSnapshot(s), query, "pseudonymized");
  expect(result.package.snapshot.edges[0]!.evidence.sourceEndpoint).toBe(`/constructor/toString/prototype/${result.privateMapping.resource}?$filter=prefix-${guid}-suffix&value=%broken&encoded=unchanged%2fvalue`);
  expect((await verifyInvestigation(canonical(result.package))).verified).toBe(true);
});

it.each(["node", "edge", "coverage", "failed-coverage"])("discovers an identifier recorded only in its %s endpoint", async source => {
  const s = snapshot();
  const endpoint = `/servicePrincipals?$filter=id eq '${guid}'`;
  const collector = s.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  if (source === "node") s.nodes[0]!.sourceEndpoint = endpoint;
  if (source === "edge") s.edges[0]!.evidence.sourceEndpoint = endpoint;
  if (source === "coverage") collector.endpoints = [endpoint];
  if (source === "failed-coverage") { collector.failedEndpoints = [endpoint]; collector.state = "partial"; }
  const result = await exportInvestigation(compileSnapshot(s), query, "pseudonymized");
  expect(result.privateMapping[guid]).toMatch(/^p\d+$/);
  const text = canonical(result.package);
  expect(text).not.toContain(guid);
  expect(text).toContain(`/servicePrincipals?$filter=id eq '${result.privateMapping[guid]}'`);
  expect((await verifyInvestigation(text)).verified).toBe(true);
});

it("pseudonymizes a query-only directory scope even when no assignment exists", async () => {
  const s = snapshot([]);
  const q = { ...query, kind: "active-role" as const, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: `/administrativeUnits/${guid}` };
  const result = await exportInvestigation(compileSnapshot(s), q, "pseudonymized");
  expect(result.package.query.directoryScopeId).toBe(`/administrativeUnits/${result.privateMapping[guid]}`);
  expect(canonical(result.package)).not.toContain(guid);
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("refuted");
});

it("redacts a single-user consent recipient outside the query and collected user inventory", async () => {
  const consent = edge("consent", "client", "resource", "CAN_CALL_DELEGATED");
  consent.consent = { audience: "single-user", principalId: "uncollected-recipient" };
  const result = await exportInvestigation(compileSnapshot(snapshot([consent])), { ...query, kind: "delegated-permission", userId: "person" }, "pseudonymized");
  expect(result.package.snapshot.edges[0]!.consent?.principalId).toBe(result.privateMapping["uncollected-recipient"]);
  expect(canonical(result.package)).not.toContain("uncollected-recipient");
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("refuted");
});

it("pseudonymizes a complete escaped non-GUID identifier without splitting its content", async () => {
  const s = snapshot();
  const target = "resource/with spaces";
  s.nodes[1]!.id = target; s.edges[0]!.targetId = target; s.edges[0]!.evidence.targetObjectId = target;
  s.edges[0]!.evidence.sourceEndpoint = `/servicePrincipals/${encodeURIComponent(target)}/appRoleAssignedTo`;
  const result = await exportInvestigation(compileSnapshot(s), { ...query, resourceId: target }, "pseudonymized");
  expect(result.package.snapshot.edges[0]!.evidence.sourceEndpoint).toBe(`/servicePrincipals/${result.privateMapping[target]}/appRoleAssignedTo`);
  expect((await verifyInvestigation(canonical(result.package))).verified).toBe(true);
});

it("pseudonymizes explicit evidence object IDs even when they differ from graph endpoints", async () => {
  const s = snapshot();
  s.edges[0]!.evidence.sourceObjectId = "source-record-object";
  s.edges[0]!.evidence.targetObjectId = guid;
  const result = await exportInvestigation(compileSnapshot(s), query, "pseudonymized");
  const text = canonical(result.package);
  expect(text).not.toContain("source-record-object");
  expect(text).not.toContain(guid);
  expect(result.package.snapshot.edges[0]!.evidence.sourceObjectId).toBe(result.privateMapping["source-record-object"]);
  expect(result.package.snapshot.edges[0]!.evidence.targetObjectId).toBe(result.privateMapping[guid]);
  expect((await verifyInvestigation(text)).verified).toBe(true);
});

it.each([null, guid])("preserves scoped role proofs and the root-scope null object: %s", async objectId => {
  const assignment = edge("role-assignment", "person", "role", "ACTIVE_IN_ROLE");
  assignment.scope = { directoryScopeId: objectId ? `/administrativeUnits/${objectId}` : "/", objectId };
  const s = snapshot([assignment]);
  const roleQuery = { ...query, kind: "active-role" as const, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: assignment.scope.directoryScopeId };
  const result = await exportInvestigation(compileSnapshot(s), roleQuery, "pseudonymized");
  const scope = result.package.snapshot.edges[0]!.scope!;
  expect(scope).toEqual({ directoryScopeId: objectId ? `/administrativeUnits/${result.privateMapping[objectId]}` : "/", objectId: objectId ? result.privateMapping[objectId] : null });
  expect(result.package.query.directoryScopeId).toBe(scope.directoryScopeId);
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
});

it("preserves a wide membership projection and its target proof", async () => {
  const count = 300;
  const s = snapshot([]);
  const groups = Array.from({ length: count }, (_, i) => `group-${i}`);
  s.nodes.push(...groups.map(id => node(id, "group")));
  s.edges = groups.map((id, i) => edge(`membership-${i}`, "person", id, "MEMBER_OF"));
  s.edges.push(edge("unrelated", "other", "team", "MEMBER_OF"));
  const membership = { ...query, kind: "membership" as const, permissionId: undefined, principalId: "person", resourceId: groups.at(-1)! };
  const result = await exportInvestigation(compileSnapshot(s), membership);
  expect(result.package.snapshot.edges).toHaveLength(count);
  expect((await verifyInvestigation(canonical(result.package))).proof.paths).toEqual([[`membership-${count - 1}`]]);
});
