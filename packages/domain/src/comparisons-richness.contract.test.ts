import { expect, it } from "vitest";
import { compareSnapshots, objectFieldIsCovered } from "./comparisons";
import { node, edge, snapshot } from "./test-support";
function pair() {
  const app = node({ id: "app", kind: "application", label: "App", sourceEndpoint: "/applications" });
  const sp = node({ id: "sp", kind: "servicePrincipal", label: "Identity" });
  const before = snapshot([app, sp], [edge("CAN_CALL_AS_APP", sp, app)]);
  before.completion.collectedEndpoints.push("/applications/app/owners");
  return { before, after: structuredClone(before) };
}
it.each(["consent", "permissionIds"] as const)("keeps newly collected or missing %s metadata unconfirmed in either direction", field => {
  for (const direction of ["added", "missing"]) {
    const { before, after } = pair();
    const target = direction === "added" ? after : before;
    if (field === "consent") target.edges[0]!.consent = { audience: "all-users", principalId: null }; else target.edges[0]!.permissionIds = ["read"];
    const diff = compareSnapshots(before, after);
    expect(diff.counts).toEqual({ added: 0, removed: 0, changed: 0, unconfirmed: 1 });
    expect(diff.changes[0]).toMatchObject({ subject: "relationship", kind: "unconfirmed", detail: "Relationship metadata was not collected in both snapshots.", fields: [{ field, before: direction === "added" ? "Not collected" : expect.any(String), after: direction === "missing" ? "Not collected" : expect.any(String), state: "unconfirmed", reason: "This metadata was not collected in both snapshots." }] });
    after.edges[0]!.permissions = ["changed"];
    const mixed = compareSnapshots(before, after).changes[0]!;
    expect(mixed.kind).toBe("changed");
    expect(mixed.fields!.find(f => f.field === "permissions")!.state).toBeUndefined();
  }
});
it("confirms explicit audience and permission changes collected in both snapshots", () => {
  const { before, after } = pair();
  before.edges[0]!.consent = { audience: "single-user", principalId: "person" }; after.edges[0]!.consent = { audience: "all-users", principalId: null };
  before.edges[0]!.permissionIds = ["read"]; after.edges[0]!.permissionIds = ["write"];
  const change = compareSnapshots(before, after).changes[0]!;
  expect(change.kind).toBe("changed"); expect(change.fields!.map(f => f.state)).toEqual([undefined, undefined]);
});
it.each(["credentials", "requestedPermissions", "permissionDefinitions"] as const)("distinguishes missing %s from a collected empty inventory", field => {
  const { before, after } = pair();
  after.nodes[0]![field] = [];
  expect(compareSnapshots(before, after).changes[0]).toMatchObject({ kind: "unconfirmed", detail: "Field differences are unconfirmed because their source evidence is incomplete.", fields: [{ field, state: "unconfirmed", reason: "The source for this field was not fully collected in both snapshots; the displayed difference may reflect missing evidence." }] });
  expect(objectFieldIsCovered(before, before.nodes[0]!, field)).toBe(false);
  expect(objectFieldIsCovered(after, after.nodes[0]!, field)).toBe(true);
  after.nodes[0]!.label = "Confirmed new label";
  expect(compareSnapshots(before, after).changes[0]).toMatchObject({ kind: "changed", detail: "Object metadata changed; some field differences remain unconfirmed." });
});
it("treats manifest, credential and definition ordering as non-semantic without modifying inputs", () => {
  const { before, after } = pair();
  before.nodes[0]!.credentials = ["z", "a"].map(id => ({ id, kind: "password", label: id, startsAt: null, expiresAt: null, sourceEndpoint: "/applications" }));
  before.nodes[0]!.requestedPermissions = ["z", "a"].map(permissionId => ({ resourceAppId: "resource", permissionId, kind: "application" }));
  before.nodes[0]!.permissionDefinitions = ["z", "a"].map(id => ({ id, value: id, kind: "application" }));
  before.edges[0]!.permissionIds = ["z", "a"];
  after.nodes[0] = structuredClone(before.nodes[0]!);
  after.nodes[0]!.credentials!.reverse(); after.nodes[0]!.requestedPermissions!.reverse(); after.nodes[0]!.permissionDefinitions!.reverse();
  after.edges[0]!.permissionIds = ["a", "z"];
  const original = JSON.stringify(before);
  expect(compareSnapshots(before, after).changes).toEqual([]); expect(JSON.stringify(before)).toBe(original);
});
it("requires every previously collected endpoint before calling disappearance a removal", () => {
  const { before, after } = pair(); after.edges = []; after.completion.collectedEndpoints = ["/applications"];
  expect(compareSnapshots(before, after).changes[0]).toMatchObject({ kind: "unconfirmed", detail: "Absent from this scan; incomplete or reduced coverage cannot establish removal." });
});
it.each(["servicePrincipal", "managedIdentity"] as const)("requires %s owners coverage for owner-dependent risk only", kind => {
  const identity = node({ id: "identity", kind, label: "Identity", sourceEndpoint: "/servicePrincipals" });
  const s = snapshot([identity], []);
  expect(objectFieldIsCovered(s, identity, "label")).toBe(true);
  expect(objectFieldIsCovered(s, identity, "ownerIds")).toBe(false);
  expect(objectFieldIsCovered(s, identity, "risk")).toBe(false);
  s.completion.collectedEndpoints.push("/servicePrincipals/identity/owners");
  expect(objectFieldIsCovered(s, identity, "ownerIds")).toBe(true); expect(objectFieldIsCovered(s, identity, "risk")).toBe(true);
});
it("resolves field provenance through the matching federation edge and uses completion only without provenance", () => {
  const trust = node({ id: "trust", kind: "federatedCredential", label: "Trust" });
  const other = node({ id: "other", kind: "federatedCredential", label: "Other" });
  const app = node({ id: "app", kind: "application", label: "App" });
  const s = snapshot([trust, other, app], [edge("OWNS", trust, app), edge("FEDERATES_AS", other, app, { evidence: { sourceEndpoint: "/wrong" } }), edge("FEDERATES_AS", trust, app, { evidence: { sourceEndpoint: "/applications/app/federatedIdentityCredentials" } })]);
  expect(objectFieldIsCovered(s, trust, "metadata")).toBe(false);
  s.completion.collectedEndpoints.push("/applications/app/federatedIdentityCredentials");
  expect(objectFieldIsCovered(s, trust, "metadata")).toBe(true);
  s.completion.status = "partial";
  expect(objectFieldIsCovered(s, trust, "metadata")).toBe(true);
  const user = node({ id: "user", kind: "user", label: "User" }); s.nodes.push(user);
  expect(objectFieldIsCovered(s, user, "label")).toBe(false);
  s.completion.status = "complete"; expect(objectFieldIsCovered(s, user, "label")).toBe(true);
});

it("uses the changed object's own field inventory even when another object comes first", () => {
  for (const missingSide of ["before", "after"]) {
    const first = node({ kind: "application", label: "First", credentials: [] });
    const changed = node({ kind: "application", label: "Changed", credentials: [] });
    const before = snapshot([first, changed], []), after = structuredClone(before);
    delete (missingSide === "before" ? before : after).nodes[1]!.credentials;
    expect(compareSnapshots(before, after).changes[0]).toMatchObject({ id: changed.id, kind: "unconfirmed" });
  }
});
it("does not infer federation provenance for an unrelated object kind", () => {
  const person = node({ kind: "user", label: "Person" }); const app = node({ kind: "application", label: "App" });
  const s = snapshot([person, app], [edge("FEDERATES_AS", person, app, { evidence: { sourceEndpoint: "/missing" } })]);
  expect(objectFieldIsCovered(s, person, "label")).toBe(true);
});
