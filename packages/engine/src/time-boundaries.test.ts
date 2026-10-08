import { expect, it } from "vitest";
import { analyzeFederation, compileSnapshot, intersectTrusts, matchesTrust, reconstructPaths, simulateContinuity, type ContinuityPlan } from "./index";
import { edge, node, query, snapshot, TIME } from "./test-support";
const instant = (tick: number) => new Date(Date.parse(TIME) + tick * 1800000).toISOString();
const trust = { issuer: "https://issuer.example", subject: "subject", audiences: ["exchange"], unsupported: [] };
it.each([undefined, { ...trust, issuer: "" }, { ...trust, subject: "" }, { ...trust, audiences: [""] }, { ...trust, issuer: "https://issuer.example " }, { ...trust, audiences: ["exchange", "second"] }, { ...trust, unsupported: ["preview"] }])("unknown trusts cannot establish either claims or intersections: %j", value => {
  expect(matchesTrust(value, { issuer: trust.issuer, subject: trust.subject, audience: "exchange" })).toBe("unknown");
  expect(intersectTrusts(value, trust)).toEqual({ verdict: "unknown", witness: null });
  expect(intersectTrusts(trust, value)).toEqual({ verdict: "unknown", witness: null });
});
it.each(["issuer", "subject", "audience"] as const)("a claim mismatch in %s is refuted", key => {
  const claims = { issuer: trust.issuer, subject: trust.subject, audience: "exchange" };
  claims[key] = "different"; expect(matchesTrust(trust, claims)).toBe("refuted");
});
it("compares every unordered trust pair once and respects exact pair budgets", () => {
  const s = snapshot(); s.nodes = ["a", "b", "c"].map(id => ({ ...node(id, "federatedCredential"), federationTrust: trust })); s.edges = [];
  const full = analyzeFederation(compileSnapshot(s), 3);
  expect(full.comparisons.map(p => [p.left, p.right])).toEqual([["a", "b"], ["a", "c"], ["b", "c"]]);
  expect(full).toMatchObject({ verdict: "supported", unknownTrusts: [], missing: [], limits: { steps: 3, maxSteps: 3, exhausted: false } });
  expect(analyzeFederation(compileSnapshot(s), 2)).toMatchObject({ verdict: "unknown", limits: { steps: 2, maxSteps: 2, exhausted: true } });
  s.nodes[2]!.federationTrust = { ...trust, subject: "other" };
  expect(analyzeFederation(compileSnapshot(s)).comparisons.filter(p => p.verdict === "refuted")).toHaveLength(2);
  expect(() => analyzeFederation(compileSnapshot(s), 0)).toThrow("Invalid trust comparisons budget.");
});
it("conflicting trusts and incomplete collection remain unknown, even with a matching pair", () => {
  const s = snapshot([]); s.nodes = [{ ...node("a", "federatedCredential"), federationTrust: trust }, { ...node("b", "federatedCredential"), federationTrust: trust }];
  for (const state of ["denied", "not-enabled"] as const) { s.completion.collectors!.find(c => c.id === "federatedIdentityCredentials")!.state = state; expect(analyzeFederation(compileSnapshot(s)).missing).toContain("coverage:federatedIdentityCredentials"); }
  const coverage = s.completion.collectors!.find(c => c.id === "federatedIdentityCredentials")!; coverage.state = "complete"; coverage.failedEndpoints = ["/failed"];
  expect(analyzeFederation(compileSnapshot(s)).verdict).toBe("unknown");
  coverage.failedEndpoints = []; s.nodes.push({ ...s.nodes[0]!, federationTrust: { ...trust, subject: "conflicting" } });
  expect(analyzeFederation(compileSnapshot(s)).missing).toEqual(["object:a"]);
  expect(analyzeFederation(compileSnapshot(s)).verdict).toBe("unknown");
  s.nodes = []; s.completion.collectors = [];
  expect(analyzeFederation(compileSnapshot(s)).missing).toEqual(["coverage:federatedIdentityCredentials"]);
});

// Independent sampled-time oracle, versus the production interval sweep. Every
// boundary lies on the half-hour grid; verify every segment, not just the verdict.
it.each(Array.from({ length: 48 }, (_, seed) => seed))("rotation interval sweep agrees with point evaluation, seed %d", seed => {
  const s = snapshot();
  const specs = [{ id: "a", start: seed % 3 - 1, end: seed % 4 + 3, deploy: seed % 2, retire: seed % 3 ? null : 3 }, { id: "b", start: 2, end: 9, deploy: seed % 5 + 2, retire: null }];
  s.nodes[0]!.credentials = specs.map(c => ({ id: c.id, kind: "certificate", label: null, startsAt: instant(c.start), expiresAt: instant(c.end), sourceEndpoint: "/applications/client" }));
  const skew = seed % 2;
  const plan: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: skew * 1800,
    deployments: specs.map(c => ({ credentialKey: `client/${c.id}`, availableFrom: instant(c.deploy), ...(c.retire === null ? {} : { unavailableFrom: instant(c.retire) }) })),
    workloads: [{ id: "worker", credentialKeys: ["client/a", "client/b"], requires: [] }] };
  const result = simulateContinuity(compileSnapshot(s), plan);
  for (let tick = 0; tick < 8; tick++) {
    const usable = specs.filter(c => tick >= c.start + skew && tick < c.end - skew && tick >= c.deploy + skew && (c.retire === null || tick < c.retire - skew)).map(c => `client/${c.id}`);
    const interval = result.intervals.find(i => Date.parse(i.startsAt) <= Date.parse(instant(tick)) && Date.parse(i.endsAt) > Date.parse(instant(tick)))!;
    expect(interval.credentials).toEqual(usable); expect(interval.verdict).toBe(usable.length ? "supported" : "refuted"); expect(interval.rollbackAvailable).toBe(usable.length === 2);
  }
  expect(result.intervals[0]!.startsAt).toBe(instant(0)); expect(result.intervals.at(-1)!.endsAt).toBe(instant(8));
  expect(result.intervals.every((i, n) => n === 0 || result.intervals[n - 1]!.endsAt === i.startsAt)).toBe(true);
  expect(result.missing).toEqual([]);
});
it("unknown retirement, credential validity, workload dependencies and source conflicts prevent continuity assurance", () => {
  const s = snapshot(); s.nodes[0]!.credentials = [{ id: "a", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(8), sourceEndpoint: "/applications/client" }];
  const plan: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: [{ credentialKey: "client/a", availableFrom: instant(0), unavailableFrom: null }], workloads: [{ id: "a", credentialKeys: ["client/a"], requires: [] }, { id: "b", credentialKeys: ["client/a"], requires: ["a"] }, { id: "c", credentialKeys: ["client/a"], requires: ["b"] }] };
  const unknown = simulateContinuity(compileSnapshot(s), plan);
  expect(unknown.intervals.map(i => [i.workloadId, i.verdict, i.credentials])).toEqual([["a", "unknown", []], ["b", "unknown", []], ["c", "unknown", []]]);
  expect(unknown.missing).toEqual(["deployment:client/a"]); expect(unknown.affectedByCredential).toEqual({ "client/a": ["a", "b", "c"] });
  delete plan.deployments[0]!.unavailableFrom;
  expect(simulateContinuity(compileSnapshot(s), plan).verdict).toBe("supported");
  s.nodes.push({ ...s.nodes[0]!, credentials: [{ ...s.nodes[0]!.credentials![0]!, expiresAt: instant(4) }] });
  expect(simulateContinuity(compileSnapshot(s), plan)).toMatchObject({ verdict: "unknown", missing: ["object:client"] });
  s.nodes.pop(); s.nodes[0]!.credentials![0]!.startsAt = null;
  expect(simulateContinuity(compileSnapshot(s), plan).missing).toEqual(["credential:client/a:validity"]);
  s.nodes[0]!.credentials![0]!.startsAt = instant(0); s.nodes[0]!.credentials![0]!.expiresAt = null;
  expect(simulateContinuity(compileSnapshot(s), plan).verdict).toBe("unknown");
});
it("propagates a definite dependency outage despite an available own credential", () => {
  const s = snapshot(); s.nodes[0]!.credentials = [{ id: "a", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(2), sourceEndpoint: "/applications/client" }, { id: "b", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(8), sourceEndpoint: "/applications/client" }];
  const plan: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: [{ credentialKey: "client/a", availableFrom: instant(0) }, { credentialKey: "client/b", availableFrom: instant(0) }], workloads: [{ id: "a", credentialKeys: ["client/a"], requires: [] }, { id: "b", credentialKeys: ["client/b"], requires: ["a"] }] };
  const r = simulateContinuity(compileSnapshot(s), plan);
  expect(r.intervals.map(i => [i.workloadId, i.startsAt, i.endsAt, i.verdict])).toEqual([["a", instant(0), instant(2), "supported"], ["a", instant(2), instant(8), "refuted"], ["b", instant(0), instant(2), "supported"], ["b", instant(2), instant(8), "refuted"]]);
  expect(r.affectedByCredential).toEqual({ "client/a": ["a", "b"], "client/b": ["b"] });
});
it("enforces rotation input limits and accepts exact boundaries", () => {
  const plan: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: [], workloads: [] };
  const m = compileSnapshot(snapshot());
  for (const clockSkewSeconds of [NaN, Infinity, -1, 86401]) expect(() => simulateContinuity(m, { ...plan, clockSkewSeconds })).toThrow("Invalid clock skew budget.");
  expect(() => simulateContinuity(m, { ...plan, clockSkewSeconds: 86400 })).not.toThrow();
  expect(() => simulateContinuity(m, { ...plan, horizon: { startsAt: instant(8), endsAt: instant(0) } })).toThrow("Rotation horizon");
  plan.deployments = Array.from({ length: 1000 }, (_, i) => ({ credentialKey: `key-${i}`, availableFrom: null }));
  plan.workloads = Array.from({ length: 200 }, (_, i) => ({ id: `work-${i}`, credentialKeys: [], requires: [] }));
  expect(() => simulateContinuity(m, plan)).not.toThrow();
  expect(() => simulateContinuity(m, { ...plan, workloads: [...plan.workloads, { ...plan.workloads[0]!, id: "over" }] })).toThrow("Rotation plan exceeds input limits.");
  expect(() => simulateContinuity(m, { ...plan, deployments: [plan.deployments[0]!, plan.deployments[0]!] })).toThrow("Duplicate rotation inputs.");
  expect(() => simulateContinuity(m, plan, 0)).toThrow("Invalid continuity steps budget.");
});
it("keeps changed validity, partial sources, and conflicting time paths distinct", () => {
  const first = snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")]); first.id = "a";
  first.edges[0]!.validity = { startsAt: instant(0), endsAt: instant(8) };
  const second = structuredClone(first); second.id = "b"; second.edges[1]!.validity = { startsAt: instant(2), endsAt: instant(4) };
  const q = { ...query, kind: "control-path" as const, principalId: "person" };
  const result = reconstructPaths([compileSnapshot(second), compileSnapshot(first)], q);
  expect(result.paths.map(p => [p.snapshots, p.validity, p.sourceValidity])).toEqual([[["a"], "unknown", { startsAt: instant(0), endsAt: instant(8) }], [["b"], "overlap", { startsAt: instant(2), endsAt: instant(4) }]]);
  expect(result.snapshotIds).toEqual(["a", "b"]); expect(result.collectedAt).toEqual([TIME]); expect(result.limits.steps).toBe(4);
  first.edges[0]!.evidence.completeness = "partial";
  expect(reconstructPaths([compileSnapshot(first)], q)).toMatchObject({ verdict: "unknown", missing: ["relationship:owner:complete-source"] });
  first.edges[0]!.evidence.completeness = "complete"; first.edges.push({ ...first.edges[0]!, evidence: { ...first.edges[0]!.evidence, configured: false } });
  expect(reconstructPaths([compileSnapshot(first)], q).missing).toContain("relationship:owner");
  const model = compileSnapshot(snapshot());
  expect(() => reconstructPaths(Array(100).fill(model), query)).not.toThrow();
  expect(() => reconstructPaths(Array(101).fill(model), query)).toThrow("Temporal analysis requires 1 to 100 snapshots.");
});
it("credential validity can start later than deployment, and retirement is shortened by skew", () => {
  const s = snapshot(); s.nodes[0]!.credentials = [{ id: "a", kind: "password", label: null, startsAt: instant(2), expiresAt: instant(12), sourceEndpoint: "/applications/client" }];
  const p: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(10) }, clockSkewSeconds: 1800, deployments: [{ credentialKey: "client/a", availableFrom: instant(-2), unavailableFrom: instant(8) }], workloads: [{ id: "worker", credentialKeys: ["client/a"], requires: [] }] };
  const result = simulateContinuity(compileSnapshot(s), p);
  expect(result.verdict).toBe("refuted");
  expect(result.intervals.map(i => [i.startsAt, i.endsAt, i.verdict])).toEqual([[instant(0), instant(3), "refuted"], [instant(3), instant(7), "supported"], [instant(7), instant(10), "refuted"]]);
});
it("coalesces unchanged intervals across another workload's boundary and shares dependency evaluation within the budget", () => {
  const s = snapshot(); s.nodes[0]!.credentials = [
    { id: "a", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(8), sourceEndpoint: "/applications/client" },
    { id: "b", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(4), sourceEndpoint: "/applications/client" },
  ];
  const p: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: [{ credentialKey: "client/a", availableFrom: instant(0) }, { credentialKey: "client/b", availableFrom: instant(0) }], workloads: [{ id: "b", credentialKeys: ["client/b"], requires: [] }, { id: "a", credentialKeys: ["client/a"], requires: [] }] };
  expect(simulateContinuity(compileSnapshot(s), p).intervals.map(i => [i.workloadId, i.startsAt, i.endsAt, i.verdict])).toEqual([["a", instant(0), instant(8), "supported"], ["b", instant(0), instant(4), "supported"], ["b", instant(4), instant(8), "refuted"]]);
  p.workloads.push({ id: "c", credentialKeys: ["client/a"], requires: ["a"] }, { id: "d", credentialKeys: ["client/a"], requires: ["c"] });
  const limited = simulateContinuity(compileSnapshot(s), p, 1);
  expect(limited.verdict).toBe("unknown"); expect(limited.intervals.every(i => i.endsAt === instant(4))).toBe(true);
  expect(limited.intervals.find(i => i.workloadId === "c")!.verdict).toBe("unknown");
  const cached = simulateContinuity(compileSnapshot(s), p, 12);
  expect(cached.limits.exhausted).toBe(false); expect(cached.intervals.find(i => i.workloadId === "d")!.verdict).toBe("supported");
});
it("preserves known and unknown workload results and isolates unrelated conflicts", () => {
  const s = snapshot(); s.nodes[0]!.credentials = [{ id: "a", kind: "password", label: null, startsAt: instant(0), expiresAt: instant(8), sourceEndpoint: "/applications/client" }];
  const p: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: [{ credentialKey: "client/a", availableFrom: instant(0) }], workloads: [{ id: "a", credentialKeys: ["client/a"], requires: [] }, { id: "b", credentialKeys: ["resource/unknown"], requires: [] }] };
  s.nodes.push(node("unrelated"), { ...node("unrelated"), label: "conflict" }); s.edges.push({ ...s.edges[0]!, evidence: { ...s.edges[0]!.evidence, configured: false } });
  const r = simulateContinuity(compileSnapshot(s), p);
  expect(r.verdict).toBe("unknown"); expect(r.intervals.map(i => i.verdict)).toEqual(["supported", "unknown"]);
  expect(r.missing).toEqual(["credential:resource/unknown:validity", "deployment:resource/unknown"]);
  p.workloads[1]!.credentialKeys = []; expect(simulateContinuity(compileSnapshot(s), p).intervals[1]!.verdict).toBe("unknown");
  p.workloads[0]!.requires = ["missing"]; expect(simulateContinuity(compileSnapshot(s), p).intervals[0]!.verdict).toBe("unknown");
  p.workloads[0]!.requires = ["b"]; p.workloads[1]!.requires = ["a"];
  expect(simulateContinuity(compileSnapshot(s), p).intervals.map(i => i.verdict)).toEqual(["unknown", "unknown"]);
  s.nodes.push({ ...s.nodes[0]!, credentials: [] }); p.workloads[0]!.requires = []; p.workloads[1]!.requires = [];
  expect(simulateContinuity(compileSnapshot(s), p).missing).toContain("object:client");
});
it("a blocked dependency prevents rollback even when two own credentials overlap", () => {
  const s = snapshot(); s.nodes[0]!.credentials = ["a", "b"].map(id => ({ id, kind: "certificate", label: null, startsAt: instant(0), expiresAt: instant(8), sourceEndpoint: "/applications/client" }));
  const p: ContinuityPlan = { tenantId: query.tenantId, horizon: { startsAt: instant(0), endsAt: instant(8) }, clockSkewSeconds: 0, deployments: ["a", "b"].map(id => ({ credentialKey: `client/${id}`, availableFrom: instant(0) })), workloads: [{ id: "worker", credentialKeys: ["client/a", "client/b"], requires: ["missing"] }] };
  const r = simulateContinuity(compileSnapshot(s), p);
  expect(r.intervals[0]).toMatchObject({ verdict: "unknown", credentials: ["client/a", "client/b"], rollbackAvailable: false });
});
it("distinguishes no overlap, partial overlap and unrelated contradictions in federation results", () => {
  const s = snapshot([]); s.nodes = ["a", "b", "c"].map(id => ({ ...node(id, "federatedCredential"), federationTrust: { ...trust, subject: id } }));
  s.nodes.push(node("ordinary"), { ...node("ordinary"), label: "unrelated conflict" });
  expect(analyzeFederation(compileSnapshot(s))).toMatchObject({ verdict: "refuted", missing: [] });
  s.nodes[1]!.federationTrust!.subject = "a";
  expect(analyzeFederation(compileSnapshot(s))).toMatchObject({ verdict: "supported", missing: [] });
});
