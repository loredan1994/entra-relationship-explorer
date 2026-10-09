import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bound, canonical, compare, immutable, timestamp, unique } from "./canonical";
import { compileSnapshot, complete } from "./model";
import { evaluateAuthorization } from "./authorization";
import { exportInvestigation, verifyInvestigation, type InvestigationPackage } from "./portable";
import { parseContract } from "./contracts";
import { simulateContinuity } from "./continuity";
import { edge, node, query, snapshot, TIME } from "./test-support";

function rehash(packet: InvestigationPackage) {
  const { manifest, ...body } = packet;
  manifest.digest = createHash("sha256").update(canonical(body)).digest("hex");
  return canonical(packet);
}

describe("bounded canonical JSON primitives", () => {
  it("orders object keys and sets, preserves array order, omits undefined fields", () => {
    expect(canonical({ z: true, a: [null, false, "quote\"", 0, -2.5], omitted: undefined })).toBe('{"a":[null,false,"quote\\"",0,-2.5],"z":true}');
    expect(canonical([2, 1])).not.toBe(canonical([1, 2]));
    expect(unique(["b", "a", "b", "A"])).toEqual(["A", "a", "b"]);
    expect(compare("a", "b")).toBe(-1); expect(compare("b", "a")).toBe(1); expect(compare("a", "a")).toBe(0);
  });
  it.each([undefined, NaN, Infinity, -Infinity, 1n, () => 1, Symbol("x")])("rejects non-JSON value %s", value => expect(() => canonical(value)).toThrow("finite JSON"));
  it.each([0, -1, 1.5, NaN, Infinity, 11])("rejects invalid resource budget %s", value => expect(() => bound(value, 10, "test")).toThrow("test budget"));
  it("accepts exact positive budget boundaries and valid timestamps", () => {
    expect(bound(1, 10, "test")).toBe(1); expect(bound(10, 10, "test")).toBe(10); expect(timestamp("1970-01-01T00:00:00Z")).toBe(0);
    expect(() => timestamp("not-a-date")).toThrow("timestamp");
    const value = { child: [{ n: 1 }] }; expect(immutable(value)).toBe(value); expect(Object.isFrozen(value.child[0])).toBe(true); expect(immutable(value)).toBe(value);
  });
});

describe("tenant and evidence input validation", () => {
  it("rejects empty identities, oversized inventories, and cross-tenant relationships", () => {
    for (const mutate of [(s: ReturnType<typeof snapshot>) => { s.id = ""; }, (s: ReturnType<typeof snapshot>) => { s.tenant.tenantId = ""; }, (s: ReturnType<typeof snapshot>) => { s.nodes[0]!.id = ""; }, (s: ReturnType<typeof snapshot>) => { s.edges[0]!.tenantId = "other"; }]) { const s = snapshot(); mutate(s); expect(() => compileSnapshot(s)).toThrow(); }
    const s = snapshot(); s.nodes = Array(100_001).fill(node("same")); expect(() => compileSnapshot(s)).toThrow("input limits");
    s.nodes = []; s.edges = Array(500_001).fill(edge("same", "a", "b")); expect(() => compileSnapshot(s)).toThrow("input limits");
  });
  it("a failed endpoint or contradictory collector invalidates declared completeness", () => {
    const s = snapshot(); const c = s.completion.collectors!.find(c => c.id === "appRoleAssignments")!;
    expect(complete(compileSnapshot(s), c.id)).toBe(true);
    c.failedEndpoints = ["/failed"]; expect(complete(compileSnapshot(s), c.id)).toBe(false);
    c.failedEndpoints = []; s.completion.collectors!.push({ ...c, state: "denied" });
    const m = compileSnapshot(s); expect(complete(m, c.id)).toBe(false); expect(evaluateAuthorization(m, query).verdict).toBe("conflicting");
  });
  it("rejects unknown query kinds, fields and excessive identifiers", () => {
    for (const bad of [{ ...query, kind: "constructor" }, { ...query, execute: "no" }, { ...query, principalId: 3 }, { ...query, principalId: "x".repeat(501) }, { ...query, resourceId: "" }]) expect(() => evaluateAuthorization(compileSnapshot(snapshot()), bad as typeof query)).toThrow();
  });
  it("preserves unknown deployment and metadata instead of assuming empty means safe", () => {
    const m = compileSnapshot(snapshot());
    const plan = { tenantId: query.tenantId, horizon: { startsAt: TIME, endsAt: "2026-10-09T12:00:00.000Z" }, clockSkewSeconds: 0, deployments: [], workloads: [{ id: "worker", credentialKeys: ["missing/key"], requires: ["missing-workload"] }] };
    const result = simulateContinuity(m, plan); expect(result.verdict).toBe("unknown"); expect(result.missing).toEqual(["credential:missing/key:validity", "deployment:missing/key", "workload:missing-workload"]);
    expect(simulateContinuity(m, plan, 1).limits).toEqual({ steps: 1, maxSteps: 1, exhausted: true });
    expect(simulateContinuity(m, { ...plan, workloads: [] }).verdict).toBe("unknown");
    expect(() => simulateContinuity(m, { ...plan, horizon: { startsAt: TIME, endsAt: TIME } })).toThrow("horizon");
    expect(() => simulateContinuity(m, { ...plan, workloads: [...plan.workloads, ...plan.workloads] })).toThrow("Duplicate");
    expect(() => simulateContinuity(m, { ...plan, deployments: Array.from({ length: 1001 }, (_, i) => ({ credentialKey: `key-${i}`, availableFrom: null })) })).toThrow("input limits");
  });
});

describe("offline verifier adversarial format checks", () => {
  it.each(["missing-edge", "missing-object", "cross-tenant", "extra-node-field", "extra-query-field", "extra-budget-field", "extra-manifest-field", "missing-manifest-field", "wrong-dependencies", "wrong-conclusion", "wrong-sharing", "wrong-algorithm", "wrong-engine"])("rejects %s even when the attacker recomputes the unkeyed hash", async mutation => {
    const { package: p } = await exportInvestigation(compileSnapshot(snapshot()), query);
    switch (mutation) {
      case "missing-edge": p.snapshot.edges = []; break;
      case "missing-object": p.snapshot.nodes = []; break;
      case "cross-tenant": p.snapshot.nodes[0]!.tenantId = "other"; break;
      case "extra-node-field": p.snapshot.nodes[0]!.metadata = { arbitrary: "not-exportable" }; break;
      case "extra-query-field": Object.assign(p.query, { run: "arbitrary" }); break;
      case "extra-budget-field": Object.assign(p.budget, { arbitrary: 1 }); break;
      case "extra-manifest-field": Object.assign(p.manifest, { arbitrary: 1 }); break;
      case "missing-manifest-field": delete (p.manifest as Partial<typeof p.manifest>).dependencies; break;
      case "wrong-dependencies": p.manifest.dependencies = []; break;
      case "wrong-conclusion": p.proof.verdict = "refuted"; break;
      case "wrong-sharing": Object.assign(p, { sharing: "anonymous" }); break;
      case "wrong-algorithm": Object.assign(p.manifest, { algorithm: "MD5" }); break;
      case "wrong-engine": p.manifest.engineVersion = "2.0.0"; break;
    }
    await expect(verifyInvestigation(rehash(p))).rejects.toThrow();
  });
  it.each(["__proto__", "constructor", "prototype", "accessToken", "refreshToken", "clientSecret", "secretText", "privateKey", "files", "path", "filename"])("rejects forbidden JSON field %s before interpretation", async key => {
    await expect(verifyInvestigation(`{"${key}":"synthetic-value"}`)).rejects.toThrow("Forbidden investigation field");
  });
  it("rejects JWT-like data and oversized scalar values before interpretation", async () => {
    await expect(verifyInvestigation(JSON.stringify({ value: "eyJabcdefghijklm.payload.signature" }))).rejects.toThrow("Secret-like");
    await expect(verifyInvestigation(JSON.stringify({ value: "x".repeat(50_001) }))).rejects.toThrow("oversized");
    await expect(verifyInvestigation(JSON.stringify(Array(150_001).fill(0)))).rejects.toThrow("structural limits");
  });
  it("pseudonymizes role scope object IDs and delegated principals without changing the conclusion", async () => {
    const grant = edge("role-grant", "person", "role", "ACTIVE_IN_ROLE"); grant.scope = { directoryScopeId: "/administrativeUnits/unit", objectId: "unit" };
    const q = { ...query, kind: "active-role" as const, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: "/administrativeUnits/unit" };
    const result = await exportInvestigation(compileSnapshot(snapshot([grant])), q, "pseudonymized");
    expect(result.privateMapping.unit).toBeDefined(); expect(JSON.stringify(result.package)).not.toContain("/administrativeUnits/unit"); expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
    const consent = edge("consent", "client", "resource", "CAN_CALL_DELEGATED"); consent.consent = { audience: "single-user", principalId: "person" };
    const packet = await exportInvestigation(compileSnapshot(snapshot([consent])), { ...query, kind: "delegated-permission", userId: "person" }, "pseudonymized");
    expect(JSON.stringify(packet.package)).not.toContain('"person"'); expect((await verifyInvestigation(canonical(packet.package))).proof.verdict).toBe("supported");
  });
  it("replays conflicting source variants rather than trusting the exported verdict", async () => {
    const s = snapshot(); s.edges.push({ ...s.edges[0]!, permissions: ["Other"], permissionIds: ["other"] });
    const result = await exportInvestigation(compileSnapshot(s), query);
    expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("conflicting");
  });
  it("replays tenant-scale coverage without joining hundreds of source endpoints into an oversized scalar", async () => {
    const s = snapshot();
    s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.endpoints = ["/servicePrincipals/resource/appRoleAssignedTo", ...Array.from({ length: 1500 }, (_, i) => `/servicePrincipals/unrelated-${i}/appRoleAssignedTo?$select=id,resourceId,principalId,appRoleId`)];
    const proof = evaluateAuthorization(compileSnapshot(s), query);
    expect(proof.facts.find(f => f.id === "coverage:appRoleAssignments")!.sourceEndpoints).toHaveLength(1501);
    const result = await exportInvestigation(compileSnapshot(s), query, "pseudonymized");
    expect(JSON.stringify(result.package)).not.toContain("unrelated-");
    expect((await verifyInvestigation(canonical(result.package))).proof.verdict).toBe("supported");
  });
  it.each([null, [], {}, { version: 1, kind: "future" }, { version: 1, kind: "only-principals", tenantId: "t", id: "i", resourceId: "r", permissionId: "p", allowedPrincipalIds: Array(101).fill("a") }])("rejects malformed contract data", bad => expect(() => parseContract(JSON.stringify(bad))).toThrow());
});
it("preserves observation metadata without converting it to configuration and orders credential sources", () => {
  const s = snapshot(); s.edges[0]!.evidence.observed = { lastSeenAt: TIME, windowStartsAt: "2026-10-01T00:00:00.000Z" };
  s.nodes[0]!.credentials = ["z", "a"].map(id => ({ id, kind: "certificate", label: "private", startsAt: null, expiresAt: null, sourceEndpoint: "/applications/client" }));
  const m = compileSnapshot(s);
  expect(m.edges[0]!.evidence.observed).toEqual({ lastSeenAt: TIME, windowStartsAt: "2026-10-01T00:00:00.000Z" });
  expect(m.nodes.find(n => n.id === "client")!.credentials!.map(c => c.id)).toEqual(["a", "z"]);
  const p = node("policy", "policy"); p.metadata = { policyType: "conditionalAccess", arbitrary: "ignore" }; s.nodes.push(p);
  expect(compileSnapshot(s).nodes.find(n => n.id === "policy")!.metadata).toEqual({ policyType: "conditionalAccess" });
  s.completion.collectors = undefined; expect(compileSnapshot(s).coverage).toEqual([]);
});
it("rejects missing snapshot and fact identities with explicit errors", () => {
  const s = snapshot(); s.id = ""; expect(() => compileSnapshot(s)).toThrow("A tenant and snapshot are required.");
  s.id = "valid"; s.edges[0]!.id = ""; expect(() => compileSnapshot(s)).toThrow("Every fact requires an ID.");
});
it("deep freezing preserves non-object values and does not revisit frozen getters", () => {
  let calls = 0;
  const value = { get child() { calls++; return { n: 1 }; } };
  immutable(value); immutable(value); expect(calls).toBe(1);
  const fn = () => 1;
  expect(immutable(fn)).toBe(fn); expect(Object.isFrozen(fn)).toBe(false);
  for (const primitive of [null, undefined, 1, "text", true]) expect(immutable(primitive)).toBe(primitive);
});
it("permits exact inventory capacity through the size check before diagnosing malformed facts", () => {
  // A malformed first record proves that the capacity guard accepted equality.
  // Validating 500,000 duplicate records before an unrelated ID error adds no
  // boundary evidence and can time out under mutation instrumentation.
  const s = snapshot(); s.nodes = Array(100_000).fill(null);
  expect(() => compileSnapshot(s)).toThrow("Invalid engine evidence structure or field type.");
  s.nodes = []; s.edges = Array(500_000).fill(null);
  expect(() => compileSnapshot(s)).toThrow("Invalid engine evidence structure or field type.");
});
