import { describe, expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot } from "./model";
import { compareContract, evaluateContract, parseContract, type AccessContract } from "./contracts";
import { exportInvestigation, verifyInvestigation } from "./portable";
import { edge, query, snapshot } from "./test-support";

const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "production-only", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: ["client"] };
describe("access contracts and semantic change review", () => {
  it("allows only declared principals and supplies the minimal violating witness", () => {
    const s = snapshot(); expect(evaluateContract(compileSnapshot(s), only).status).toBe("pass");
    s.nodes.find(n => n.id === "other")!.kind = "servicePrincipal";
    s.edges.push(edge("rogue", "other", "resource"));
    const result = evaluateContract(compileSnapshot(s), only); expect(result.status).toBe("fail"); expect(result.witnesses[0]!.paths).toEqual([["rogue"]]);
  });
  it("partial collection changes pass to unknown and no recorded target is never a pass", () => {
    const s = snapshot(); s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "partial";
    expect(evaluateContract(compileSnapshot(s), only).status).toBe("unknown");
    expect(evaluateContract(compileSnapshot(snapshot()), { ...only, resourceId: "absent" }).status).toBe("unknown");
  });
  it("required grants fail only with complete evidence of absence", () => {
    const c: AccessContract = { version: 1, tenantId: query.tenantId, id: "required", kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" };
    expect(evaluateContract(compileSnapshot(snapshot()), c).status).toBe("pass");
    expect(evaluateContract(compileSnapshot(snapshot([])), c).status).toBe("fail");
  });
  it("ignores display-name/reordering noise but detects a new alternative path", () => {
    const s = snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")]);
    const c: AccessContract = { version: 1, tenantId: query.tenantId, id: "no-owner-control", kind: "no-control-path", sourceIds: ["person"], resourceIds: ["resource"] };
    const before = compileSnapshot(s); s.nodes.reverse(); s.edges.reverse(); s.nodes[0]!.label = "Renamed"; s.id = "later";
    expect(compareContract(before, compileSnapshot(s), c).addedPaths).toEqual([]);
    s.edges.push(edge("blueprint-owner", "person", "blueprint", "OWNS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"));
    const result = compareContract(before, compileSnapshot(s), c); expect(result.addedPaths).toHaveLength(1); expect(result.removedPaths).toEqual([]); expect(result.complete).toBe(true);
  });
  it("rejects executable fields, mixed tenants, excessive input, and ambiguous ID lists", () => {
    expect(() => parseContract(JSON.stringify({ ...only, script: "console.log('unsafe')" }))).toThrow("fields");
    expect(() => parseContract(" ".repeat(100_001))).toThrow("100 KB");
    expect(() => parseContract(JSON.stringify({ ...only, allowedPrincipalIds: ["client", "client"] }))).toThrow("ID list");
    expect(() => evaluateContract(compileSnapshot(snapshot()), { ...only, tenantId: "other" })).toThrow("Cross-tenant");
    expect(() => parseContract(JSON.stringify({ ...only, version: 2 }))).toThrow("schema");
  });
});

describe("bounded portable investigation replay", () => {
  it("replays the projected facts and removes unrelated names, credentials and metadata", async () => {
    const s = snapshot(); s.nodes[0]!.label = "Private display name"; s.nodes[0]!.metadata = { secretText: "never-export-this" };
    const result = await exportInvestigation(compileSnapshot(s), query);
    expect(canonical(result.package)).not.toContain("Private display name"); expect(canonical(result.package)).not.toContain("never-export-this");
    expect(result.package.snapshot.nodes.map(n => n.id).sort()).toEqual(["client", "resource"]);
    const verified = await verifyInvestigation(canonical(result.package)); expect(verified.verified).toBe(true); expect(verified.proof.verdict).toBe("supported");
  });
  it("pseudonymizes identifiers consistently and never embeds the private mapping", async () => {
    const result = await exportInvestigation(compileSnapshot(snapshot()), query, "pseudonymized");
    const body = canonical(result.package);
    expect(body).not.toContain('"synthetic-tenant"'); expect(body).not.toContain('"read-id"'); expect(body).not.toContain('"client"');
    expect(result.privateMapping.client).toMatch(/^p\d+$/); expect(body).not.toContain("privateMapping");
    expect((await verifyInvestigation(body)).proof.verdict).toBe("supported");
  });
  it.each(["fact", "proof", "dependency", "tenant", "version"])("detects %s tampering", async kind => {
    const { package: packet } = await exportInvestigation(compileSnapshot(snapshot()), query);
    if (kind === "fact") packet.snapshot.edges[0]!.permissionIds = ["changed"];
    if (kind === "proof") packet.proof.verdict = "refuted";
    if (kind === "dependency") packet.manifest.dependencies = [];
    if (kind === "tenant") packet.snapshot.nodes[0]!.tenantId = "foreign";
    if (kind === "version") packet.manifest.ruleVersion = "future";
    await expect(verifyInvestigation(canonical(packet))).rejects.toThrow();
  });
  it("fails safely on oversized, path-based, secret-like, and malformed imports", async () => {
    await expect(verifyInvestigation(" ".repeat(5_000_001))).rejects.toThrow("5 MB");
    for (const text of ['{"path":"../../secrets"}', '{"files":[]}', '{"__proto__":{}}', '"-----BEGIN PRIVATE KEY-----"', '{"format":"future"}', '[]']) await expect(verifyInvestigation(text)).rejects.toThrow();
    await expect(verifyInvestigation('{"nested":'.repeat(30) + '0' + '}'.repeat(30))).rejects.toThrow("structural");
  });
  it("replays negative and missing-evidence conclusions without inventing absent facts", async () => {
    const s = snapshot([]); const first = await exportInvestigation(compileSnapshot(s), query); expect((await verifyInvestigation(canonical(first.package))).proof.verdict).toBe("refuted");
    s.completion.collectors = []; const second = await exportInvestigation(compileSnapshot(s), query); expect((await verifyInvestigation(canonical(second.package))).proof.verdict).toBe("unknown");
  });
  it("projects only the reachable control region and rejects incomplete search exports", async () => {
    const s = snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource"), edge("unrelated-owner", "other", "blueprint", "OWNS"), edge("unrelated-target", "client", "blueprint")]);
    const q = { ...query, kind: "control-path" as const, principalId: "person" };
    const result = await exportInvestigation(compileSnapshot(s), q);
    expect(result.package.snapshot.edges.map(e => e.id)).toEqual(["grant", "owner"]);
    expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
    await expect(exportInvestigation(compileSnapshot(s), q, "identified", { maxDepth: 1, maxPaths: 1, maxSteps: 1 })).rejects.toThrow("Narrow the query");
  });
});
