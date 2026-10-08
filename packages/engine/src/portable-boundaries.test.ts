import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot, exportInvestigation, verifyInvestigation, type InvestigationPackage } from "./index";
import { edge, node, query, snapshot } from "./test-support";
it.each([
  ["prefix-eyJabcdefghij.a.b", true],
  ["prefix-eyJabcdefghi.a.b", false],
  ["prefixeyJabcdefghij.a.b", false],
  ["prefix_eyJabcdefghij.a.b", false],
  ["!eyJabcdefghij.a.b?", true],
  ["before.a.b eyJabcdefghij.a.b", true],
  ["one.eyJabcdefghij.a.b", true],
  ["eyJabcdefghij..b", false],
  ["eyJabcdefghij.a.", false],
  ["eyJabcdefghij.a!b", false],
  ["eyJabcdefghij!.a.b", false],
  ["prefix-eyJabcdefghij-_._-._-", true],
])("keeps token detection boundaries for %s", async (value, secret) => {
  await expect(verifyInvestigation(JSON.stringify(value))).rejects.toThrow(secret ? "Secret-like or oversized" : "Invalid investigation document");
});
it("rejects oversized repeated token prefixes before scanning them", async () => {
  await expect(verifyInvestigation(JSON.stringify("eyJabcdefghijk-".repeat(30_000)))).rejects.toThrow("Secret-like or oversized");
  await expect(verifyInvestigation(JSON.stringify("eyJabcdefghijk-".repeat(3000)))).rejects.toThrow("Invalid investigation document");
});
function rehash(p: InvestigationPackage) { const { manifest, ...body } = p; manifest.digest = createHash("sha256").update(canonical(body)).digest("hex"); return canonical(p); }
it("replays typed object and coverage conflicts and omits unrelated conflict families", async () => {
  const s = snapshot(); s.nodes.push({ ...s.nodes[0]!, kind: "application" }, { ...node("unrelated"), kind: "group" }, node("unrelated"));
  const c = s.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
  c.endpoints = ["/servicePrincipals", "/applications/client/owners", "/applications/other/owners", "/users/person", "/groups/unrelated/members", "/servicePrincipals/resource/appRoleAssignedTo"];
  s.completion.collectors!.push({ ...c, state: "denied" });
  s.completion.collectors!.push({ ...s.completion.collectors!.find(c => c.id === "roles")!, state: "denied" });
  const result = await exportInvestigation(compileSnapshot(s), query);
  expect(result.package.snapshot.nodes.filter(n => n.id === "client").map(n => n.kind)).toEqual(["application", "application", "servicePrincipal"]);
  expect(result.package.snapshot.completion.collectors!.filter(c => c.id === "appRoleAssignments")).toHaveLength(3);
  expect(result.package.snapshot.completion.collectors!.find(c => c.id === "appRoleAssignments")!.endpoints).toEqual(["/applications/client/owners", "/servicePrincipals", "/servicePrincipals/resource/appRoleAssignedTo"]);
  const verified = await verifyInvestigation(canonical(result.package));
  expect(verified.proof.verdict).toBe("conflicting"); expect(verified.proof.conflicts.map(c => c.factId).sort()).toEqual(["coverage:appRoleAssignments", "object:client"]);
});
it("refuses export when stripping an unsupported source conflict would change the conclusion", async () => {
  const s = snapshot(); s.nodes.push({ ...s.nodes[0]!, label: "Different source record" });
  await expect(exportInvestigation(compileSnapshot(s), query)).rejects.toThrow("The minimized projection cannot preserve this conclusion.");
});
it("preserves reachable conflicting control variants and never walks through terminal API grants", async () => {
  const s = snapshot([edge("owner", "other", "client", "OWNS"), edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource"), edge("after-api", "resource", "blueprint", "OWNS"), edge("unrelated", "team", "nested", "MEMBER_OF")]);
  s.edges.push({ ...s.edges.at(-1)!, evidence: { ...s.edges.at(-1)!.evidence, configured: false } });
  const q = { ...query, kind: "control-path" as const, principalId: "person" };
  const { package: packet } = await exportInvestigation(compileSnapshot(s), q);
  expect(packet.snapshot.edges.map(e => e.id)).toEqual(["grant", "owner", "owner", "owner"]);
  expect((await verifyInvestigation(canonical(packet))).proof.verdict).toBe("conflicting");
});
it("exports membership closure with cycles and excludes disconnected membership", async () => {
  const s = snapshot([edge("a", "person", "team", "MEMBER_OF"), edge("b", "team", "nested", "MEMBER_OF"), edge("cycle", "nested", "team", "MEMBER_OF"), edge("disconnected", "other", "blueprint", "MEMBER_OF")]);
  const q = { ...query, permissionId: undefined, kind: "membership" as const, principalId: "person", resourceId: "nested" };
  const { package: packet } = await exportInvestigation(compileSnapshot(s), q);
  expect(packet.snapshot.edges.map(e => e.id)).toEqual(["a", "b", "cycle"]);
  expect((await verifyInvestigation(canonical(packet))).proof.paths).toEqual([["a", "b"]]);
});
it("pseudonymizes endpoint-only GUIDs, alternate permissions and missing query identities", async () => {
  const guid = "A0123456-789A-BCDE-F012-3456789ABCDE", second = "12345678-abcd-1234-5678-abcdefabcdef";
  const s = snapshot(); s.edges[0]!.permissionIds!.push("alternate-permission"); s.edges[0]!.evidence.sourceEndpoint = `/servicePrincipals/resource/appRoleAssignedTo?$filter=id=${guid}`;
  s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.failedEndpoints = [`/applications/${second}/owners`];
  s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "partial";
  const q = { ...query, userId: "uncollected-user", permissionId: "absent-permission" };
  const result = await exportInvestigation(compileSnapshot(s), q, "pseudonymized");
  for (const value of [guid, second, "uncollected-user", "absent-permission", "alternate-permission"]) { expect(result.privateMapping[value]).toBeDefined(); expect(canonical(result.package)).not.toContain(value); }
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("unknown");
});
it("pseudonymizes all-user consent and projections lacking source endpoints or permission IDs", async () => {
  const e = edge("consent", "client", "resource", "CAN_CALL_DELEGATED"); e.consent = { audience: "all-users", principalId: null }; delete e.permissionIds;
  const s = snapshot([e]); delete s.nodes[0]!.sourceEndpoint;
  const result = await exportInvestigation(compileSnapshot(s), { ...query, kind: "delegated-permission", userId: "person" }, "pseudonymized");
  expect(result.package.snapshot.edges[0]!.consent).toEqual({ audience: "all-users", principalId: null });
  expect(result.package.snapshot.nodes.find(n => n.id === result.privateMapping.client)!.sourceEndpoint).toBeUndefined();
  expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("unknown");
});
it.each([null, [], true, 123, "document"])("rejects invalid root %j explicitly", async value => {
  await expect(verifyInvestigation(JSON.stringify(value))).rejects.toThrow("Invalid investigation document.");
});
it("distinguishes schema, format, version, hash, projection and replay failures", async () => {
  const original = (await exportInvestigation(compileSnapshot(snapshot()), query)).package;
  for (const key of ["format", "query", "proof"]) { const p = structuredClone(original); delete (p as unknown as Record<string, unknown>)[key]; await expect(verifyInvestigation(canonical(p))).rejects.toThrow("Unknown or missing investigation fields."); }
  const format = structuredClone(original); Object.assign(format, { format: "future" }); await expect(verifyInvestigation(canonical(format))).rejects.toThrow("Unsupported investigation format.");
  const version = structuredClone(original); version.manifest.ruleVersion = "future"; await expect(verifyInvestigation(canonical(version))).rejects.toThrow("Unsupported engine or integrity version.");
  const hash = structuredClone(original); hash.manifest.digest = "0".repeat(64); await expect(verifyInvestigation(canonical(hash))).rejects.toThrow("Investigation integrity check failed.");
  const extra = structuredClone(original); extra.snapshot.nodes[0]!.description = "Not allowed"; await expect(verifyInvestigation(rehash(extra))).rejects.toThrow("Investigation contains nonminimal or unsupported facts.");
  const proof = structuredClone(original); proof.proof.verdict = "refuted"; await expect(verifyInvestigation(rehash(proof))).rejects.toThrow("Proof replay or dependency check failed.");
  const invalid = structuredClone(original); Object.assign(invalid.query, { extra: "field" }); await expect(verifyInvestigation(rehash(invalid))).rejects.toThrow("Unknown or invalid authorization query fields.");
  expect((await verifyInvestigation(canonical(original))).notice).toBe("Integrity and model replay verified. Hashes do not authenticate Microsoft as the source. Pseudonymization does not anonymize topology.");
});
it("enforces nested-array and scalar bounds before interpreting the document", async () => {
  await expect(verifyInvestigation("[".repeat(24) + "0" + "]".repeat(24))).rejects.toThrow("Invalid investigation document.");
  await expect(verifyInvestigation("[".repeat(25) + "0" + "]".repeat(25))).rejects.toThrow("structural limits");
  await expect(verifyInvestigation(JSON.stringify(Array(149999).fill(0)))).rejects.toThrow("Invalid investigation document.");
  await expect(verifyInvestigation(JSON.stringify(Array(150000).fill(0)))).rejects.toThrow("structural limits");
  await expect(verifyInvestigation(JSON.stringify({ value: "x".repeat(50000) }))).rejects.toThrow("Unknown or missing investigation fields.");
});
it.each(["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "eyJabcdefghij.a.b", "eyJ_-ABCdef012.abcdef._-Z"])("rejects secret-like scalar in an otherwise exportable record: %s", async value => {
  const s = snapshot(); s.edges[0]!.evidence.sourceRecordIds = [value];
  await expect(exportInvestigation(compileSnapshot(s), query)).rejects.toThrow("Secret-like or oversized content rejected.");
});
it("accepts ordinary claim-like text, but never partial token matches mistaken for complete JWTs", async () => {
  for (const value of ["prefixeyJabcdefghij.a.b", "eyJabcdefghij.a.", "eyJabcdefghi.a.b", "BEGIN RSA PUBLIC KEY", "eyJabcdefghij..b"]) {
    const s = snapshot(); s.edges[0]!.evidence.sourceRecordIds = [value];
    const result = await exportInvestigation(compileSnapshot(s), query);
    expect((await verifyInvestigation(canonical(result.package))).verified).toBe(true);
  }
});
it("accepts exactly 5 MB, rejects an extra UTF-8 byte and applies the same limit to export", async () => {
  const s = snapshot(); s.edges[0]!.evidence.sourceRecordIds = Array.from({ length: 55 }, (_, i) => `${i}:` + "x".repeat(44997)); s.edges[0]!.permissions = ["p"];
  const initial = await exportInvestigation(compileSnapshot(s), query);
  const bytes = new TextEncoder().encode(canonical(initial.package)).length;
  const padding = 5_000_000 - bytes; expect(padding).toBeGreaterThan(0); expect(padding).toBeLessThan(50000);
  s.edges[0]!.permissions = ["p".repeat(padding + 1)];
  const result = await exportInvestigation(compileSnapshot(s), query);
  const text = canonical(result.package); expect(new TextEncoder().encode(text).length).toBe(5_000_000);
  expect((await verifyInvestigation(text)).verified).toBe(true);
  await expect(verifyInvestigation(text + " ")).rejects.toThrow("Investigation exceeds 5 MB.");
  s.edges[0]!.permissions[0] += "p";
  await expect(exportInvestigation(compileSnapshot(s), query)).rejects.toThrow("Investigation exceeds the 5 MB export limit. Narrow the query.");
});
