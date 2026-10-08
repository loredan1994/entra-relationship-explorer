import { expect, it } from "vitest";
import { credentialHistory } from "./credential-history";
import { node, edge, snapshot } from "./test-support";
import type { CredentialMetadata, NodeKind } from "./types";
const key: CredentialMetadata = { id: "key", kind: "password", label: "Deploy", startsAt: "2026-01-01", expiresAt: "2026-08-27T10:00:00.000Z", sourceEndpoint: "/applications" };
const metadataReason = "Credential or trust metadata differs between the selected snapshots. This does not prove deployment or use.";
const unknownReason = "Missing inventory or incomplete source coverage prevents confirming this difference.";
function pair(kind: NodeKind = "application") {
  const identity = node({ id: "identity", kind, label: "Identity", credentials: [key] });
  const before = snapshot([identity], [], { id: "before", scannedAt: "2026-08-26T10:00:00.000Z" });
  const after = structuredClone(before); after.id = "after"; after.scannedAt = "2026-08-27T10:00:00.000Z";
  return { before, after };
}
it("separates unchanged validity metadata from time-driven expiry with exact provenance", () => {
  const { before, after } = pair();
  expect(credentialHistory(before, after)).toEqual([{ identityId: "identity", identityLabel: "Identity", credentialId: "key", kind: "password", change: "validity-changed", before: { id: "key", kind: "password", details: { label: "Deploy", startsAt: "2026-01-01", expiresAt: key.expiresAt }, sourceEndpoint: "/applications", state: "expires-soon" }, after: { id: "key", kind: "password", details: { label: "Deploy", startsAt: "2026-01-01", expiresAt: key.expiresAt }, sourceEndpoint: "/applications", state: "expired" }, reason: "The validity interval is unchanged; time passing changed its state. This is not a tenant configuration edit.", sourceEndpoints: ["/applications"] }]);
  after.scannedAt = "2026-08-26T11:00:00.000Z";
  expect(credentialHistory(before, after)).toEqual([]);
});
it.each(["application", "servicePrincipal", "managedIdentity"] as const)("tracks %s addition and removal against the correct parent collection", kind => {
  const { before, after } = pair(kind); const endpoint = kind === "application" ? "/applications" : "/servicePrincipals";
  before.nodes = []; before.completion.collectedEndpoints = [endpoint];
  expect(credentialHistory(before, after)).toMatchObject([{ change: "added", before: null, after: { id: "key" }, reason: metadataReason, sourceEndpoints: ["/applications"] }]);
  before.completion.collectedEndpoints = ["/unrelated"];
  expect(credentialHistory(before, after)[0]).toMatchObject({ change: "unconfirmed", reason: unknownReason });
  before.completion.collectedEndpoints = [endpoint];
  const removed = { ...after, nodes: [], completion: { ...after.completion, collectedEndpoints: [endpoint] } };
  before.nodes = structuredClone(after.nodes);
  before.completion.collectedEndpoints.push("/applications");
  expect(credentialHistory(before, removed)).toMatchObject([{ change: "removed", before: { id: "key" }, after: null, sourceEndpoints: ["/applications"] }]);
});
it("reports edits, unknown inventories and deterministic ordering without considering non-workload keys", () => {
  const { before, after } = pair();
  after.nodes[0]!.credentials![0]!.label = "Changed";
  expect(credentialHistory(before, after)).toMatchObject([{ change: "changed", reason: metadataReason }]);
  delete before.nodes[0]!.credentials;
  expect(credentialHistory(before, after)).toMatchObject([{ change: "unconfirmed", reason: unknownReason }]);
  const ignored = node({ kind: "user", label: "User", credentials: [key] }); after.nodes.push(ignored);
  after.nodes.push(node({ id: "second", kind: "application", label: "A first identity", credentials: [{ ...key, id: "z", kind: "password" }, { ...key, id: "a", kind: "password" }, { ...key, id: "z", kind: "certificate" }] }));
  expect(credentialHistory(before, after).map(c => `${c.identityId}:${c.kind}:${c.credentialId}`)).toEqual(["second:certificate:z", "second:password:a", "second:password:z", "identity:password:key"]);
});
it("resolves each federation to its own parent, preserving missing metadata as null", () => {
  const { before, after } = pair(); before.nodes[0]!.credentials = []; after.nodes[0]!.credentials = [];
  const other = node({ id: "other", kind: "managedIdentity", label: "Other" });
  const trust = node({ id: "trust", kind: "federatedCredential", label: "Trust", metadata: { issuer: "https://issuer", subject: "old", audiences: "aud" } });
  const sparse = node({ id: "sparse", kind: "federatedCredential", label: "Sparse", metadata: { issuer: null, subject: 42 } });
  before.nodes.push(other, trust, sparse); after.nodes.push(structuredClone(other), structuredClone(trust), structuredClone(sparse));
  after.nodes.find(n => n.id === "trust")!.metadata!.subject = "new";
  delete after.nodes.find(n => n.id === "sparse")!.metadata;
  const links = [edge("FEDERATES_AS", trust, before.nodes[0]!, { evidence: { sourceEndpoint: "/applications/identity/federatedIdentityCredentials" } }), edge("FEDERATES_AS", sparse, other, { evidence: { sourceEndpoint: "/applications/other/federatedIdentityCredentials" } }), edge("OWNS", other, before.nodes[0]!)];
  before.edges = links; after.edges = structuredClone(links);
  before.completion.collectedEndpoints.push("/applications/identity/federatedIdentityCredentials", "/applications/other/federatedIdentityCredentials");
  after.completion.collectedEndpoints = [...before.completion.collectedEndpoints];
  expect(credentialHistory(before, after)).toMatchObject([
    { identityId: "identity", credentialId: "trust", kind: "federation", change: "changed", before: { details: { label: "Trust", issuer: "https://issuer", subject: "old", audiences: "aud" } }, after: { details: { label: "Trust", issuer: "https://issuer", subject: "new", audiences: "aud" } }, reason: metadataReason },
    { identityId: "other", credentialId: "sparse", kind: "federation", change: "changed", before: { details: { issuer: null, subject: "42", audiences: null } }, after: { details: { issuer: null, subject: null, audiences: null } } },
  ]);
});
it("requires the explicit managed identity federation expansion in both snapshots", () => {
  const { before, after } = pair("managedIdentity");
  const trust = node({ id: "trust", kind: "federatedCredential", label: "Trust" });
  after.nodes.push(trust); after.edges.push(edge("FEDERATES_AS", trust, after.nodes[0]!, { evidence: { sourceEndpoint: "/servicePrincipals?$select=id&$expand=federatedIdentityCredentials($select=id)" } }));
  before.nodes[0]!.credentials = []; after.nodes[0]!.credentials = [];
  const expanded = "/servicePrincipals?$expand=federatedIdentityCredentials($select=id)";
  const inspect = () => credentialHistory(before, after)[0]!;
  for (const endpoint of ["/servicePrincipals", "/servicePrincipals?$expand=owners", "/other?$expand=federatedIdentityCredentials"]) {
    before.completion.collectedEndpoints = [endpoint]; after.completion.collectedEndpoints = [expanded];
    expect(inspect().change).toBe("unconfirmed");
  }
  before.completion.collectedEndpoints = [expanded];
  expect(inspect()).toMatchObject({ change: "added", kind: "federation", reason: metadataReason });
  before.completion.skippedEndpoints = [expanded]; expect(inspect().change).toBe("unconfirmed");
});
it("rejects tenant and chronology violations", () => {
  const { before, after } = pair(); after.tenant.tenantId = "other";
  expect(() => credentialHistory(before, after)).toThrow();
  const valid = pair(); valid.after.scannedAt = "2000-01-01";
  expect(() => credentialHistory(valid.before, valid.after)).toThrow();
});

it("distinguishes multiple trusts, non-federation edges and legacy base-endpoint metadata", () => {
  const { before, after } = pair("managedIdentity"); before.nodes[0]!.credentials = []; after.nodes[0]!.credentials = [];
  for (const id of ["one", "two"]) {
    const trust = node({ id, kind: "federatedCredential", label: id });
    after.nodes.push(trust); after.edges.push(edge("FEDERATES_AS", trust, after.nodes[0]!, { evidence: { sourceEndpoint: "/servicePrincipals" } }));
  }
  const owner = node({ id: "owner", kind: "user", label: "Owner" }); after.nodes.push(owner); after.edges.push(edge("OWNS", owner, after.nodes[0]!));
  expect(credentialHistory(before, after).map(c => [c.credentialId, c.change])).toEqual([["one", "unconfirmed"], ["two", "unconfirmed"]]);
  const expansion = "/servicePrincipals?$expand=federatedIdentityCredentials";
  before.completion.collectedEndpoints.push(expansion); after.completion.collectedEndpoints.push(expansion);
  expect(credentialHistory(before, after).map(c => [c.credentialId, c.change])).toEqual([["one", "added"], ["two", "added"]]);
  // Password inventory is supplied by the base read and does not require federation.
  before.completion.collectedEndpoints = ["/servicePrincipals"]; after.completion.collectedEndpoints = ["/servicePrincipals"];
  after.nodes[0]!.credentials = [{ ...key, sourceEndpoint: "/servicePrincipals" }]; after.edges = [];
  expect(credentialHistory(before, after)).toMatchObject([{ kind: "password", change: "added" }]);
});
