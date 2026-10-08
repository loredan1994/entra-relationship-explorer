import { expect, it } from "vitest";
import { permissionLedger } from "./permission-ledger";
import { node, edge, snapshot } from "./test-support";
import type { RelationshipEdge } from "./types";
function graph(kind: "application" | "delegated" = "application") {
  const app = node({ id: "app", kind: "application", label: "Blueprint", appId: "client-app", sourceEndpoint: "/applications?$select=id,requiredResourceAccess", requestedPermissions: [{ resourceAppId: "api-app", permissionId: "read", kind }] });
  const client = node({ id: "client", kind: "servicePrincipal", label: "Client", appId: "client-app" });
  const api = node({ id: "api", kind: "servicePrincipal", label: "API", appId: "api-app", sourceEndpoint: "/servicePrincipals?$select=id,appRoles", permissionDefinitions: [{ id: "wrong-kind", value: "Data.Read", kind: kind === "application" ? "delegated" : "application" }, { id: "read", value: "Data.Read", kind }] });
  const grant: RelationshipEdge = { ...edge(kind === "application" ? "CAN_CALL_AS_APP" : "CAN_CALL_DELEGATED", client, api, { id: "grant", permissions: ["Data.Read"], evidence: { sourceEndpoint: "/grants" } }), ...(kind === "application" ? { permissionIds: ["read"] } : {}), consent: { audience: "single-user", principalId: "person" } };
  return { app, client, api, grant, s: snapshot([app, client, api], [grant]) };
}
it.each(["application", "delegated"] as const)("reconciles %s declarations and grants by resource, permission ID and kind", kind => {
  const { s } = graph(kind);
  expect(permissionLedger(s)).toEqual([{
    id: `grant:${kind === "application" ? "read" : "Data.Read"}`, applicationId: "app", identityId: "client", identity: "Client", resourceId: "api", resource: "API", permissionId: "read", permission: "Data.Read", kind, status: "requested-and-granted", audience: kind === "application" ? "Application identity" : "One user", principalId: kind === "application" ? null : "person", edgeId: "grant", sourceEndpoints: ["/grants", "/applications?$select=id,requiredResourceAccess", "/servicePrincipals?$select=id,appRoles"], reason: "The declaration and a configured grant match. This does not prove permission use.",
  }]);
});
it.each(["application", "delegated"] as const)("requires every request key to match before calling a %s grant declared", kind => {
  for (const patch of [{ resourceAppId: "different" }, { permissionId: "different" }, { kind: kind === "application" ? "delegated" as const : "application" as const }]) {
    const { app, s } = graph(kind); Object.assign(app.requestedPermissions![0]!, patch);
    expect(permissionLedger(s).find(r => r.edgeId === "grant")).toMatchObject({ status: "granted-not-requested", reason: "Configured grant is absent from the collected local manifest; review intent before planning removal." });
  }
});
it("uses application permission IDs without a definition, but never guesses unresolved delegated IDs", () => {
  for (const kind of ["application", "delegated"] as const) {
    const { app, api, s } = graph(kind); app.requestedPermissions = []; delete api.permissionDefinitions;
    expect(permissionLedger(s)).toMatchObject([{ permissionId: kind === "application" ? "read" : null, permission: kind === "application" ? "read" : "Data.Read", status: kind === "application" ? "granted-not-requested" : "unknown" }]);
  }
  const { grant, s } = graph(); grant.permissionIds = [];
  expect(permissionLedger(s)).toMatchObject([{ permissionId: "read", permission: "Data.Read", status: "requested-and-granted" }]);
});
it("keeps missing definitions, manifests, app IDs and incomplete grants explicitly unknown", () => {
  for (const mutation of ["manifest", "registration", "app-id", "resource-id", "partial"] as const) {
    const { app, api, grant, s } = graph();
    if (mutation === "manifest") delete app.requestedPermissions;
    if (mutation === "registration") s.nodes = s.nodes.filter(n => n.id !== "app");
    if (mutation === "app-id") delete app.appId;
    if (mutation === "resource-id") delete api.appId;
    if (mutation === "partial") grant.evidence.completeness = "partial";
    expect(permissionLedger(s).find(r => r.edgeId === "grant")).toMatchObject({ status: "unknown", reason: "The local manifest, permission definition or grant evidence is incomplete. External app manifests are not available in this tenant." });
  }
});
it.each(["all-users", "single-user", "unknown", undefined] as const)("preserves delegated consent audience %s without inventing a principal", audience => {
  const { grant, s } = graph("delegated"); grant.consent = audience ? { audience, principalId: null } : undefined;
  expect(permissionLedger(s)[0]).toMatchObject({ audience: audience === "all-users" ? "All users" : audience === "single-user" ? "One user" : "Unknown consent audience", principalId: null });
});
it("uses minimal provenance without empty endpoints or duplicated sources", () => {
  const { app, api, s } = graph(); app.sourceEndpoint = "/grants"; api.sourceEndpoint = "/grants";
  expect(permissionLedger(s)[0]!.sourceEndpoints).toEqual(["/grants"]);
  delete app.sourceEndpoint; delete api.sourceEndpoint;
  expect(permissionLedger(s)[0]!.sourceEndpoints).toEqual(["/grants"]);
  s.nodes = s.nodes.filter(n => n.id !== "app");
  expect(permissionLedger(s)[0]!.applicationId).toBeNull();
});
it.each(["application", "delegated"] as const)("asserts %s absence only against a resolved identity, definition and collected endpoint", kind => {
  const { app, s } = graph(kind); s.edges = [];
  const endpoint = kind === "application" ? "/servicePrincipals/api/appRoleAssignedTo" : "/oauth2PermissionGrants";
  s.completion.collectedEndpoints = [`${endpoint}?$select=id`];
  expect(permissionLedger(s)).toEqual([{
    id: `request:app:api-app:${kind}:read`, applicationId: "app", identityId: "client", identity: "Blueprint", resourceId: "api", resource: "API", permissionId: "read", permission: "Data.Read", kind, status: "requested-not-granted", audience: "No matched grant", principalId: null, edgeId: null, sourceEndpoints: [app.sourceEndpoint!, "/servicePrincipals?$select=id,appRoles", `${endpoint}?$select=id`], reason: "Declared in the manifest, but no matching grant was collected in the covered endpoint.",
  }]);
  s.completion.skippedEndpoints = [endpoint];
  expect(permissionLedger(s)[0]).toMatchObject({ status: "unknown", reason: "A missing identity, resource definition or grant collection prevents reconciliation." });
});
it("does not confuse non-workload objects, mismatched app IDs or wrong-kind definitions with identity inventory", () => {
  for (const problem of ["client-kind", "resource-kind", "client-app", "client-missing-app", "definition-kind", "definition-id", "no-definitions"] as const) {
    const { client, api, s } = graph(); s.edges = []; s.completion.collectedEndpoints = ["/servicePrincipals/api/appRoleAssignedTo"];
    if (problem === "client-kind") client.kind = "application";
    if (problem === "resource-kind") api.kind = "application";
    if (problem === "client-app") client.appId = "wrong";
    if (problem === "client-missing-app") delete client.appId;
    if (problem === "definition-kind") api.permissionDefinitions![1]!.kind = "delegated";
    if (problem === "definition-id") api.permissionDefinitions![1]!.id = "wrong";
    if (problem === "no-definitions") delete api.permissionDefinitions;
    expect(permissionLedger(s)[0]!.status).toBe("unknown");
  }
});
it("supports managed identities and leaves missing resources/identity IDs visible by stable manifest IDs", () => {
  const { app, client, api, s } = graph(); s.edges = [];
  client.kind = "managedIdentity"; api.kind = "managedIdentity";
  s.completion.collectedEndpoints = ["/servicePrincipals/api/appRoleAssignedTo"];
  expect(permissionLedger(s)[0]!.status).toBe("requested-not-granted");
  s.nodes = [app]; delete app.sourceEndpoint;
  expect(permissionLedger(s)).toMatchObject([{ identityId: null, resourceId: null, resource: "api-app", permission: "read", status: "unknown", sourceEndpoints: ["/applications"] }]);
});
it("excludes other relationship types, orders rows deterministically and rejects mixed tenants", () => {
  const { client, api, s } = graph();
  s.edges.push(edge("OWNS", client, api, { permissions: ["Ignore"] }));
  s.edges.push({ ...s.edges[0]!, id: "aaa" });
  expect(permissionLedger(s).map(r => r.id)).toEqual(["aaa:read", "grant:read"]);
  s.nodes[0]!.tenantId = "other"; expect(() => permissionLedger(s)).toThrow();
});

it("matches local registrations by app ID before using their declarations", () => {
  const { s } = graph(); s.nodes.unshift(node({ id: "wrong", kind: "application", label: "Wrong registration", appId: "wrong-client", requestedPermissions: [] }));
  expect(permissionLedger(s).find(r => r.edgeId === "grant")!.applicationId).toBe("app");
});
it("handles legacy application grants without permission IDs and ignores IDs on delegated grants", () => {
  const { grant, s, api } = graph(); delete grant.permissionIds; delete api.permissionDefinitions;
  expect(permissionLedger(s).find(r => r.edgeId === "grant")).toMatchObject({ permissionId: null, permission: "Data.Read", status: "unknown" });
  const delegated = graph("delegated"); delegated.grant.permissionIds = ["not-an-app-role"];
  expect(permissionLedger(delegated.s)[0]).toMatchObject({ permissionId: "read", permission: "Data.Read", status: "requested-and-granted" });
});
it("sorts dissimilar identity rows by label even when grant IDs sort oppositely", () => {
  const { client, api, grant, s } = graph(); client.label = "Zulu";
  const other = node({ id: "a-client", kind: "servicePrincipal", label: "Alpha" }); s.nodes.push(other); s.edges.push({ ...grant, id: "zzz", sourceId: other.id, targetId: api.id });
  expect(permissionLedger(s).filter(r => r.edgeId).map(r => r.identity)).toEqual(["Alpha", "Zulu"]);
  s.edges.reverse();
  expect(permissionLedger(s).filter(r => r.edgeId).map(r => r.identity)).toEqual(["Alpha", "Zulu"]);
});

it("does not invent requests for historical registrations without manifest inventory", () => {
  expect(permissionLedger(snapshot([node({ kind: "application", label: "Legacy" })], []))).toEqual([]);
});
it("keeps delegated permission IDs unresolved even if a legacy grant carries an unrelated ID array", () => {
  const { grant, api, s } = graph("delegated");
  grant.permissionIds = ["Data.Read"]; delete api.permissionDefinitions;
  expect(permissionLedger(s).find(r => r.edgeId === "grant")).toMatchObject({ permissionId: null, status: "unknown" });
});

it("does not match declarations through blank legacy resource or permission IDs", () => {
  for (const field of ["resource", "permission"]) {
    const { app, api, grant, s } = graph();
    if (field === "resource") { api.appId = ""; app.requestedPermissions![0]!.resourceAppId = ""; }
    else { grant.permissionIds = [""]; api.permissionDefinitions![1]!.id = ""; app.requestedPermissions![0]!.permissionId = ""; }
    expect(permissionLedger(s).find(r => r.edgeId === "grant")!.status).toBe("unknown");
  }
});
