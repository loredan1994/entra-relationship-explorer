import { expect, it } from "vitest";
import { simulateContinuity, type ContinuityPlan } from "./continuity";
import { compileSnapshot } from "./model";
import { query, snapshot } from "./test-support";

const at = (seconds: number) => new Date(Date.UTC(2026, 9, 9) + seconds * 1000).toISOString();
const credential = (id: string, starts = 0) => ({ id, kind: "certificate" as const, label: null, startsAt: at(starts), expiresAt: at(1000), sourceEndpoint: "/applications" });
const plan = (): ContinuityPlan => ({ tenantId: query.tenantId, horizon: { startsAt: at(90), endsAt: at(120) }, clockSkewSeconds: 0,
  deployments: [{ credentialKey: "client/key", availableFrom: at(0) }], workloads: [{ id: "worker", credentialKeys: ["client/key"], requires: [] }] });

it("waits through clock skew after credential activation even when deployment was already available", () => {
  const source = snapshot();
  source.nodes[0]!.credentials = [credential("key", 100)];
  const input = plan(); input.clockSkewSeconds = 10;
  const result = simulateContinuity(compileSnapshot(source), input);
  expect(result.verdict).toBe("refuted");
  expect(result.intervals).toEqual([
    { workloadId: "worker", startsAt: at(90), endsAt: at(110), verdict: "refuted", credentials: [], rollbackAvailable: false },
    { workloadId: "worker", startsAt: at(110), endsAt: at(120), verdict: "supported", credentials: ["client/key"], rollbackAvailable: false },
  ]);
});

it("limits an object contradiction to its dependent workload when another identity is sound", () => {
  const source = snapshot();
  source.nodes[0]!.credentials = [credential("key")];
  source.nodes[1]!.credentials = [credential("backup")];
  source.nodes.push({ ...source.nodes[0]!, credentials: [{ ...credential("key"), expiresAt: at(80) }] });
  const input = plan();
  input.deployments.push({ credentialKey: "resource/backup", availableFrom: at(0) });
  input.workloads.push({ id: "independent", credentialKeys: ["resource/backup"], requires: [] });
  const result = simulateContinuity(compileSnapshot(source), input);
  expect(result.verdict).toBe("unknown");
  expect(result.missing).toEqual(["object:client"]);
  expect(result.intervals).toEqual([
    { workloadId: "independent", startsAt: at(90), endsAt: at(120), verdict: "supported", credentials: ["resource/backup"], rollbackAvailable: false },
    { workloadId: "worker", startsAt: at(90), endsAt: at(120), verdict: "unknown", credentials: [], rollbackAvailable: false },
  ]);
});

it("reports unknown deployment rather than treating valid credential metadata as deployment proof", () => {
  const source = snapshot(); source.nodes[0]!.credentials = [credential("key")];
  const input = plan(); input.deployments = [];
  expect(simulateContinuity(compileSnapshot(source), input)).toMatchObject({ verdict: "unknown", missing: ["deployment:client/key"], intervals: [{ verdict: "unknown", credentials: [] }] });
});

it("cannot certify a self-dependent workload despite a valid deployed credential", () => {
  const source = snapshot(); source.nodes[0]!.credentials = [credential("key")];
  const input = plan(); input.workloads[0]!.requires = ["worker"];
  expect(simulateContinuity(compileSnapshot(source), input)).toMatchObject({ verdict: "unknown", missing: ["dependency-cycle:worker"], intervals: [{ verdict: "unknown", rollbackAvailable: false }] });
});
