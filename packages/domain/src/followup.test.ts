import { describe, expect, it } from "vitest";
import { cleanProjectFixture, cleanProjectPreviousFixture, compareSnapshots, createScenarioPlan, credentialHistory, importScenarioPlan, simulateRemoval } from "./index";
import { edge, node, snapshot } from "./test-support";

const oldTime = "2026-08-01T00:00:00Z", newTime = "2026-08-02T00:00:00Z";
function ownerPair() {
  const app = node({ id: "app", kind: "application", label: "Payroll", sourceEndpoint: "/applications", ownerIds: ["owner"], risk: { level: "low", reason: "Owned" } });
  const before = snapshot([app], [], { scannedAt: oldTime });
  before.completion.collectedEndpoints = ["/applications", "/applications/app/owners"];
  const after = structuredClone(before); after.scannedAt = newTime;
  after.nodes[0]!.ownerIds = [];
  after.nodes[0]!.risk = { level: "high", reason: "No owner" };
  after.completion.collectedEndpoints = ["/applications"];
  after.completion.skippedEndpoints = ["/applications/app/owners"];
  after.completion.status = "partial";
  return { before, after };
}
describe("field evidence integrity", () => {
  it("does not claim ownership removal or increased risk after an owner read fails", () => {
    const { before, after } = ownerPair();
    expect(compareSnapshots(before, after).changes).toEqual([expect.objectContaining({ kind: "unconfirmed", fields: [expect.objectContaining({ field: "ownerIds", state: "unconfirmed" }), expect.objectContaining({ field: "risk", state: "unconfirmed" })] })]);
    after.nodes[0]!.label = "Renamed payroll";
    const result = compareSnapshots(before, after).changes[0]!;
    expect(result.kind).toBe("changed");
    expect(result.fields!.find(f => f.field === "label")!.state).not.toBe("unconfirmed");
  });
  it("confirms a removal when both owner inventories were actually collected", () => {
    const { before, after } = ownerPair(); after.completion = structuredClone(before.completion);
    expect(compareSnapshots(before, after).counts.changed).toBe(1);
  });
  it("ignores property ordering but detects definition and permission ID changes", () => {
    const resource = node({ kind: "servicePrincipal", label: "API", metadata: { first: "a", second: "b" }, permissionDefinitions: [{ id: "id", kind: "application", value: "Read" }] });
    const before = snapshot([resource], [edge("CAN_CALL_AS_APP", resource, resource, { permissionIds: ["old"] })]);
    const after = structuredClone(before);
    after.nodes[0]!.metadata = { second: "b", first: "a" };
    expect(compareSnapshots(before, after).changes).toEqual([]);
    after.nodes[0]!.permissionDefinitions![0]!.value = "Write";
    after.edges[0]!.permissionIds = ["new"];
    expect(compareSnapshots(before, after).changes.map(c => c.fields!.map(f => f.field))).toEqual([["permissionDefinitions"], ["permissionIds"]]);
  });
  it("rejects invalid dates instead of silently accepting an unordered history", () => {
    const { before, after } = ownerPair(); before.scannedAt = "invalid";
    expect(() => compareSnapshots(before, after)).toThrow("timestamps");
  });
});

describe("portable local scenario plans", () => {
  const id = cleanProjectFixture.edges.find(e => e.type === "OWNS")!.id;
  const plan = () => createScenarioPlan(cleanProjectFixture, [id]);
  it("round trips exclusions and recomputes outcomes instead of trusting imported results", () => {
    const exported = plan(); exported.remainingPathIds = ["forged-result"];
    const excluded = importScenarioPlan(JSON.stringify(exported), cleanProjectFixture);
    expect(excluded).toEqual([id]);
    expect(simulateRemoval(cleanProjectFixture, excluded).remainingPaths.map(p => p.id)).not.toContain("forged-result");
  });
  it.each([
    [{ tenantId: "other" }, /different tenant/],
    [{ snapshotId: "old" }, /different snapshot/],
    [{ scannedAt: "2000-01-01" }, /different snapshot/],
    [{ schemaVersion: 2 }, /schema/],
    [{ script: "anything" }, /schema/],
    [{ excludedEdgeIds: ["absent"] }, /cannot be changed/],
    [{ excludedEdgeIds: Array(101).fill(id) }, /at most 100/],
    [{ excludedEdgeIds: [42] }, /relationship IDs/],
  ])("rejects unsafe or stale plan %j", (patch, message) => {
    expect(() => importScenarioPlan(JSON.stringify({ ...plan(), ...patch }), cleanProjectFixture)).toThrow(message);
  });
  it("bounds input bytes and rejects malformed documents before replacing a scenario", () => {
    for (const source of ["null", "[]", "{"]) expect(() => importScenarioPlan(source, cleanProjectFixture)).toThrow();
    expect(() => importScenarioPlan("é".repeat(50_001), cleanProjectFixture)).toThrow("100 KB");
    const observation = { ...plan(), excludedEdgeIds: [cleanProjectFixture.edges.find(e => e.type === "INSTANTIATES_AS")!.id] };
    expect(() => importScenarioPlan(JSON.stringify(observation), cleanProjectFixture)).toThrow("cannot be changed");
  });
});

describe("individual credential and trust history", () => {
  const key = { id: "key", kind: "password" as const, label: "Key", startsAt: "2025-01-01T00:00:00Z", expiresAt: newTime, sourceEndpoint: "/applications" };
  function pair() {
    const app = node({ id: "app", kind: "application", label: "Workload", credentials: [key] });
    const before = snapshot([app], [], { scannedAt: oldTime }); before.completion.collectedEndpoints = ["/applications", "/applications/app/federatedIdentityCredentials"];
    const after = structuredClone(before); after.scannedAt = newTime;
    return { before, after };
  }
  it("shows the added replacement key in the sample without claiming the expired key disappeared", () => {
    expect(credentialHistory(cleanProjectPreviousFixture, cleanProjectFixture)).toEqual([expect.objectContaining({ credentialId: "sample-new-key", change: "added", kind: "certificate" })]);
  });
  it("separates expiry caused by time passing from credential configuration changes", () => {
    const { before, after } = pair();
    expect(credentialHistory(before, after)).toEqual([expect.objectContaining({ change: "validity-changed", before: expect.objectContaining({ state: "expires-soon" }), after: expect.objectContaining({ state: "expired" }) })]);
    after.nodes[0]!.credentials![0]!.label = "Renamed key";
    expect(credentialHistory(before, after)[0]!.change).toBe("changed");
  });
  it("distinguishes known empty inventory, unknown inventory, and failed collection", () => {
    const { before, after } = pair(); after.nodes[0]!.credentials = [];
    expect(credentialHistory(before, after)[0]!.change).toBe("removed");
    delete after.nodes[0]!.credentials;
    expect(credentialHistory(before, after)[0]!.change).toBe("unconfirmed");
    after.nodes[0]!.credentials = []; after.completion.skippedEndpoints = ["/applications"];
    expect(credentialHistory(before, after)[0]!.change).toBe("unconfirmed");
  });
  it("preserves issuer, subject and audience changes with their trust endpoint", () => {
    const { before, after } = pair(); before.nodes[0]!.credentials = []; after.nodes[0]!.credentials = [];
    const trust = node({ id: "trust", kind: "federatedCredential", label: "Deployment", metadata: { issuer: "https://issuer.example", subject: "repo:sample/main", audiences: "api://exchange" } });
    const relation = edge("FEDERATES_AS", trust, before.nodes[0]!, { evidence: { sourceEndpoint: "/applications/app/federatedIdentityCredentials" } });
    before.nodes.push(trust); before.edges.push(relation);
    after.nodes.push({ ...trust, metadata: { ...trust.metadata, subject: "repo:sample/other" } }); after.edges.push(relation);
    const [change] = credentialHistory(before, after);
    expect(change).toMatchObject({ kind: "federation", change: "changed", before: { details: { subject: "repo:sample/main" } }, after: { details: { subject: "repo:sample/other" } }, sourceEndpoints: ["/applications/app/federatedIdentityCredentials"] });
    after.edges = []; after.completion.skippedEndpoints = ["/applications/app/federatedIdentityCredentials"];
    expect(credentialHistory(before, after)[0]!.change).toBe("unconfirmed");
  });
});

it("does not confuse managed identity inventory with federation expansion coverage", () => {
  const identity = node({ id: "managed", kind: "managedIdentity", label: "Build identity", credentials: [] });
  const trust = node({ id: "trust", kind: "federatedCredential", label: "Build trust" });
  const endpoint = "/servicePrincipals?$select=id&$expand=federatedIdentityCredentials($select=id,issuer,subject,audiences)";
  const before = snapshot([identity], [], { scannedAt: oldTime });
  before.completion.collectedEndpoints = ["/servicePrincipals?$select=id,displayName"];
  const after = snapshot([identity, trust], [edge("FEDERATES_AS", trust, identity, { evidence: { sourceEndpoint: endpoint } })], { scannedAt: newTime });
  after.completion.collectedEndpoints = [endpoint];
  expect(credentialHistory(before, after)[0]!.change).toBe("unconfirmed");
  before.completion.collectedEndpoints.push(endpoint);
  expect(credentialHistory(before, after)[0]!.change).toBe("added");
  before.completion.skippedEndpoints.push(endpoint);
  expect(credentialHistory(before, after)[0]!.change).toBe("unconfirmed");
});

it("marks metadata absent from an older schema as unknown instead of a configuration edit", () => {
  const app = node({ id: "app", kind: "application", label: "Legacy", sourceEndpoint: "/applications" });
  const before = snapshot([app], []); before.completion.collectedEndpoints = ["/applications"];
  const after = structuredClone(before);
  after.nodes[0]!.credentials = []; after.nodes[0]!.requestedPermissions = []; after.nodes[0]!.permissionDefinitions = [];
  const change = compareSnapshots(before, after).changes[0]!;
  expect(change.kind).toBe("unconfirmed");
  expect(change.fields!.every(field => field.state === "unconfirmed")).toBe(true);
});
