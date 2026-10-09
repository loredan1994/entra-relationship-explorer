import { expect, it } from "vitest";
import { compileSnapshot } from "./model";
import { reconstructPaths } from "./temporal";
import { simulateContinuity, type ContinuityPlan } from "./continuity";
import { edge, query, snapshot } from "./test-support";

const day = (value: number) => `2026-10-${String(value).padStart(2, "0")}T00:00:00.000Z`;
const controlQuery = { ...query, kind: "control-path" as const, principalId: "person" };

function alternatives() {
  const owner = edge("owner", "person", "client", "OWNS");
  owner.validity = { startsAt: day(1), endsAt: day(3) };
  const complete = edge("complete-grant", "client", "resource");
  complete.validity = { startsAt: day(3), endsAt: day(5) };
  const incomplete = edge("partial-grant", "client", "resource");
  incomplete.validity = { startsAt: day(1), endsAt: day(5) };
  incomplete.evidence.completeness = "partial";
  return snapshot([owner, complete, incomplete]);
}

it.each(["partial", "endpoint", "record", "permission"])("a disjoint complete path cannot lend evidence to an overlapping alternative missing %s", missing => {
  const source = alternatives();
  const alternative = source.edges[2]!;
  alternative.evidence.completeness = "complete";
  if (missing === "partial") alternative.evidence.completeness = "partial";
  if (missing === "endpoint") alternative.evidence.sourceEndpoint = "";
  if (missing === "record") alternative.evidence.sourceRecordIds = [];
  if (missing === "permission") delete alternative.permissionIds;
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result.verdict).toBe("unknown");
  expect(result.paths.map(path => path.validity)).toEqual(["disjoint", "overlap"]);
  expect(result.missing).toContain(`relationship:partial-grant:${missing === "permission" ? "permission-ids" : "complete-source"}`);
});

it("retains an independent complete temporal witness while explaining incomplete alternatives", () => {
  const source = alternatives();
  source.edges[1]!.validity = { startsAt: day(2), endsAt: day(5) };
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result.verdict).toBe("supported");
  expect(result.missing).toEqual(["relationship:partial-grant:complete-source"]);
  expect(result.paths.map(path => path.sourceValidity)).toEqual([
    { startsAt: day(2), endsAt: day(3) },
    { startsAt: day(1), endsAt: day(3) },
  ]);
});

it("a complete temporal path cannot settle a proof with a contradictory alternative", () => {
  const source = alternatives();
  source.edges = source.edges.slice(0, 2);
  source.edges[1]!.validity = { startsAt: day(2), endsAt: day(5) };
  const disputed = { ...source.edges[1]!, id: "disputed-grant" };
  source.edges.push(disputed, { ...disputed, evidence: { ...disputed.evidence, configured: false } });
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result.verdict).toBe("unknown");
  expect(result.paths.some(path => path.validity === "overlap")).toBe(true);
  expect(result.missing).toEqual(["relationship:disputed-grant"]);
});

it("a complete temporal path cannot settle a proof with an uncollected intermediate identity", () => {
  const source = alternatives();
  source.edges = source.edges.slice(0, 2);
  source.edges[1]!.validity = { startsAt: day(2), endsAt: day(5) };
  source.edges.push(edge("missing-owner", "person", "uncollected-client", "OWNS"));
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result.verdict).toBe("unknown");
  expect(result.paths.some(path => path.validity === "overlap")).toBe(true);
  expect(result.missing).toEqual(["object:uncollected-client"]);
});

it("cannot refute all temporal alternatives when one lacks complete evidence", () => {
  const source = alternatives();
  source.edges[2]!.validity = { startsAt: day(4), endsAt: day(5) };
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result).toMatchObject({ verdict: "unknown", missing: ["relationship:partial-grant:complete-source"] });
});

it.each([
  { coverage: "partial" as const, overlaps: false, verdict: "unknown" },
  { coverage: "complete" as const, overlaps: false, verdict: "refuted" },
  { coverage: "partial" as const, overlaps: true, verdict: "supported" },
])("preserves $coverage inventory limits with overlap=$overlaps", ({ coverage, overlaps, verdict }) => {
  const source = alternatives();
  source.edges.pop();
  source.completion.collectors!.find(collector => collector.id === "appRoleAssignments")!.state = coverage;
  if (overlaps) source.edges[1]!.validity!.startsAt = day(2);
  const result = reconstructPaths([compileSnapshot(source)], controlQuery);
  expect(result.verdict).toBe(verdict);
  expect(result.missing).toEqual(coverage === "partial" ? ["coverage:appRoleAssignments"] : []);
});

function continuity() {
  const source = snapshot();
  source.nodes[0]!.credentials = [
    { id: "key", kind: "password", label: null, startsAt: day(1), expiresAt: day(2), sourceEndpoint: "/applications/client" },
    { id: "key", kind: "password", label: null, startsAt: day(1), expiresAt: day(10), sourceEndpoint: "/applications/client" },
  ];
  const plan: ContinuityPlan = {
    tenantId: query.tenantId, horizon: { startsAt: day(3), endsAt: day(5) }, clockSkewSeconds: 0,
    deployments: [{ credentialKey: "client/key", availableFrom: day(1) }],
    workloads: [{ id: "worker", credentialKeys: ["client/key"], requires: [] }],
  };
  return { source, plan };
}

it("conflicting duplicate credential metadata is unknown regardless of record order", () => {
  const { source, plan } = continuity();
  const first = simulateContinuity(compileSnapshot(source), plan);
  source.nodes[0]!.credentials!.reverse();
  const reversed = simulateContinuity(compileSnapshot(source), plan);
  expect(first).toEqual(reversed);
  expect(first).toMatchObject({
    verdict: "unknown", missing: ["credential:client/key:conflicting-metadata"],
    intervals: [{ startsAt: day(3), endsAt: day(5), verdict: "unknown", credentials: [], rollbackAvailable: false }],
  });
});

it("identical repeated credential records count once and cannot manufacture rollback", () => {
  const { source, plan } = continuity();
  source.nodes[0]!.credentials = Array(3).fill(source.nodes[0]!.credentials![1]!);
  const result = simulateContinuity(compileSnapshot(source), plan);
  expect(result).toMatchObject({ verdict: "supported", missing: [], intervals: [{ credentials: ["client/key"], rollbackAvailable: false }] });
});

it("a separate unambiguous credential can support continuity without hiding a conflicted alternative", () => {
  const { source, plan } = continuity();
  source.nodes[0]!.credentials!.push({ ...source.nodes[0]!.credentials![1]!, id: "fallback" });
  plan.deployments.push({ credentialKey: "client/fallback", availableFrom: day(1) });
  plan.workloads[0]!.credentialKeys.push("client/fallback");
  const result = simulateContinuity(compileSnapshot(source), plan);
  expect(result).toMatchObject({
    verdict: "supported", missing: ["credential:client/key:conflicting-metadata"],
    intervals: [{ credentials: ["client/fallback"], rollbackAvailable: false }],
  });
});

it("an unrelated credential contradiction does not affect the supplied workload", () => {
  const { source, plan } = continuity();
  source.nodes[0]!.credentials!.push({ ...source.nodes[0]!.credentials![1]!, id: "fallback" });
  plan.deployments = [{ credentialKey: "client/fallback", availableFrom: day(1) }];
  plan.workloads[0]!.credentialKeys = ["client/fallback"];
  expect(simulateContinuity(compileSnapshot(source), plan)).toMatchObject({ verdict: "supported", missing: [] });
});
