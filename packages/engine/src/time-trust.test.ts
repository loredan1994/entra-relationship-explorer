import { describe, expect, it } from "vitest";
import { compileSnapshot } from "./model";
import { intersectWindows, reconstructPaths } from "./temporal";
import { analyzeFederation, intersectTrusts, matchesTrust } from "./federation";
import { simulateContinuity, type ContinuityPlan } from "./continuity";
import { edge, query, snapshot } from "./test-support";

const t = (day: number) => `2026-10-${String(day).padStart(2, "0")}T00:00:00.000Z`;
describe("temporal compatibility", () => {
  it("intersects half-open windows and rejects zero-duration overlap", () => {
    expect(intersectWindows([{ startsAt: t(1), endsAt: t(5) }, { startsAt: t(3), endsAt: t(8) }])).toEqual({ startsAt: t(3), endsAt: t(5) });
    expect(intersectWindows([{ startsAt: t(1), endsAt: t(3) }, { startsAt: t(3), endsAt: t(8) }])).toBeNull();
    expect(intersectWindows([])).toBeNull();
    expect(() => intersectWindows([{ startsAt: t(3), endsAt: t(3) }])).toThrow("exclusive end");
  });
  it("does not union edges from different scans into a phantom path", () => {
    const a = snapshot([edge("owner", "person", "client", "OWNS")]); const b = snapshot(); b.id = "second"; b.scannedAt = t(9);
    const q = { ...query, kind: "control-path" as const, principalId: "person", permissionId: undefined };
    const result = reconstructPaths([compileSnapshot(b), compileSnapshot(a)], q);
    expect(result.paths).toEqual([]); expect(result.verdict).toBe("unknown");
  });
  it("detects disjoint validity even when all path edges appear in the same scan", () => {
    const a = edge("owner", "person", "client", "OWNS"), b = edge("grant", "client", "resource");
    a.validity = { startsAt: t(1), endsAt: t(3) }; b.validity = { startsAt: t(3), endsAt: t(5) };
    const result = reconstructPaths([compileSnapshot(snapshot([a, b]))], { ...query, kind: "control-path", principalId: "person" });
    expect(result.verdict).toBe("refuted"); expect(result.paths[0]!.validity).toBe("disjoint");
  });
  it("repeated observations mark the intervening interval uncertain, regardless of audit order", () => {
    const a = snapshot(), b = snapshot(); b.id = "later"; b.scannedAt = t(10);
    const result = reconstructPaths([compileSnapshot(b), compileSnapshot(a)], query);
    expect(result.paths[0]!.uncertainIntervals).toEqual([{ startsAt: a.scannedAt, endsAt: t(10) }]);
    expect(result.auditContext).toBe("not-used-to-infer-continuity"); expect(result.paths[0]!.validity).toBe("unknown");
    expect(() => reconstructPaths([], query)).toThrow("1 to 100");
    expect(() => reconstructPaths([{ ...compileSnapshot(a), tenantId: "other" }], query)).toThrow("Cross-tenant");
  });
});

const trust = { issuer: "https://issuer.example", subject: "repo:example/tool:environment:production", audiences: ["api://AzureADTokenExchange"], unsupported: [] };
describe("exact federation trust semantics", () => {
  it("returns synthetic witnesses for exact overlap", () => {
    expect(intersectTrusts(trust, trust)).toEqual({ verdict: "supported", witness: { issuer: trust.issuer, subject: trust.subject, audience: trust.audiences[0] } });
    expect(matchesTrust(trust, { issuer: trust.issuer, subject: trust.subject, audience: trust.audiences[0]! })).toBe("supported");
  });
  it.each([{ issuer: "https://ISSUER.example" }, { issuer: "https://issuer.example/" }, { subject: "repo:example/tool:environment:staging" }, { subject: "repo:example/Tool:environment:production" }, { audiences: ["different"] }])("keeps case, audience, repository and environment boundaries: %j", difference => {
    expect(intersectTrusts(trust, { ...trust, ...difference }).verdict).toBe("refuted");
  });
  it.each([undefined, { ...trust, unsupported: ["claimsMatchingExpression"] }, { ...trust, audiences: [] }, { ...trust, audiences: ["one", "two"] }, { ...trust, issuer: " https://issuer.example" }])("does not interpret unsupported or malformed trusts", value => {
    expect(intersectTrusts(trust, value).verdict).toBe("unknown");
  });
  it("reports old flattened snapshots as unknown and respects comparison bounds", () => {
    const s = snapshot(); const n = s.nodes.find(n => n.id === "trust")!;
    n.metadata = { issuer: trust.issuer, subject: trust.subject, audiences: trust.audiences.join(", ") };
    expect(analyzeFederation(compileSnapshot(s)).unknownTrusts).toEqual(["trust"]);
    n.federationTrust = trust; s.nodes.push({ ...n, id: "trust2" }, { ...n, id: "trust3" });
    const r = analyzeFederation(compileSnapshot(s), 1); expect(r.comparisons).toHaveLength(1); expect(r.limits.exhausted).toBe(true); expect(r.verdict).toBe("unknown");
  });
});

function rotation() {
  const s = snapshot(); s.nodes[0]!.credentials = [
    { id: "old", kind: "password", label: null, startsAt: t(1), expiresAt: t(5), sourceEndpoint: "/applications" },
    { id: "new", kind: "certificate", label: null, startsAt: t(3), expiresAt: t(10), sourceEndpoint: "/applications" },
  ];
  const plan: ContinuityPlan = { tenantId: s.tenant.tenantId, horizon: { startsAt: t(2), endsAt: t(8) }, clockSkewSeconds: 0,
    deployments: [{ credentialKey: "client/old", availableFrom: t(1) }, { credentialKey: "client/new", availableFrom: t(3) }],
    workloads: [{ id: "worker", credentialKeys: ["client/old", "client/new"], requires: [] }] };
  return { model: compileSnapshot(s), plan };
}
describe("credential continuity under deployment assumptions", () => {
  it("shows metadata overlap and rollback windows without claiming deployed evidence", () => {
    const { model, plan } = rotation(), r = simulateContinuity(model, plan);
    expect(r.verdict).toBe("supported");
    expect(r.intervals.map(i => [i.startsAt, i.endsAt, i.rollbackAvailable])).toEqual([[t(2), t(3), false], [t(3), t(5), true], [t(5), t(8), false]]);
    expect(r.assumptions.join(" ")).toContain("not observed use");
  });
  it("reports a real modeled gap when replacement arrives after expiry", () => {
    const { model, plan } = rotation(); plan.deployments[1]!.availableFrom = t(6);
    expect(simulateContinuity(model, plan).intervals.filter(i => i.verdict === "refuted").map(i => [i.startsAt, i.endsAt])).toEqual([[t(5), t(6)]]);
  });
  it("boundary equality has no gap until a clock-skew budget is applied", () => {
    const { model, plan } = rotation(); plan.deployments[1]!.availableFrom = t(5);
    expect(simulateContinuity(model, plan).verdict).toBe("supported");
    plan.clockSkewSeconds = 60; const gaps = simulateContinuity(model, plan).intervals.filter(i => i.verdict === "refuted");
    expect(gaps[0]!.startsAt).toBe("2026-10-04T23:59:00.000Z"); expect(gaps[0]!.endsAt).toBe("2026-10-05T00:01:00.000Z");
  });
  it("unknown deployment, retired fallback, shared dependencies and cycles remain explicit", () => {
    const { model, plan } = rotation(); plan.deployments[1]!.availableFrom = null;
    expect(simulateContinuity(model, plan).verdict).toBe("unknown");
    plan.deployments[0]!.unavailableFrom = t(4);
    plan.workloads.push({ id: "dependent", credentialKeys: ["client/old"], requires: ["worker"] });
    const r = simulateContinuity(model, plan); expect(r.affectedByCredential["client/new"]).toEqual(["dependent", "worker"]);
    plan.workloads[0]!.requires = ["dependent"]; expect(simulateContinuity(model, plan).missing).toContain("dependency-cycle:dependent");
    expect(() => simulateContinuity(model, { ...plan, tenantId: "other" })).toThrow("Cross-tenant");
    expect(() => simulateContinuity(model, { ...plan, clockSkewSeconds: -1 })).toThrow("clock skew");
  });
});
