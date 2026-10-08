import { beforeEach, expect, it, vi } from "vitest";
import type { FindingSeverity, IamFinding } from "./intelligence";
import { snapshot, node } from "./test-support";
const engine = vi.hoisted(() => vi.fn());
vi.mock("./intelligence", () => ({ analyzeTenantIntelligenceHistory: engine }));
import { analyzeFindingLifecycle } from "./finding-lifecycle";
function finding(id: string, severity: FindingSeverity = "high", title = "Same"): IamFinding {
  return { id, severity, title, category: "ownership", evidenceClass: "configured", summary: "Missing owner", whyItMatters: "Accountability", remediation: [], affectedObjectIds: [], edgeIds: [], attackPathId: null, sourceEndpoints: ["/applications/old/owners?x=y", "/servicePrincipals/old"], uncertainty: [] };
}
function history() {
  return [3, 2, 1].map(day => snapshot([], [], { id: String(day), scannedAt: `2026-08-0${day}T00:00:00Z`, completion: { status: "complete", collectedEndpoints: ["/applications/new/owners", "/servicePrincipals/new"], skippedEndpoints: [], errors: [] } }));
}
beforeEach(() => { engine.mockReset(); });
it("orders all severities and lifecycle states and does not duplicate continuing findings", () => {
  const ongoing = finding("ongoing"), returned = finding("returned"), fresh = finding("fresh"), gone = finding("gone");
  const byId: Record<string, IamFinding[]> = { "3": [ongoing, fresh, finding("low", "low"), finding("medium", "medium"), returned, finding("critical", "critical")], "2": [ongoing, gone], "1": [returned] };
  engine.mockImplementation(([s]) => ({ findings: byId[s.id], pathAnalysis: { truncated: false } }));
  const result = analyzeFindingLifecycle(history());
  expect(result.records.map(r => [r.finding.id, r.status])).toEqual([["critical", "new"], ["returned", "returned"], ["fresh", "new"], ["ongoing", "ongoing"], ["gone", "no-longer-detected"], ["medium", "new"], ["low", "new"]]);
  expect(result.counts).toEqual({ new: 4, ongoing: 1, returned: 1, "no-longer-detected": 1, unconfirmed: 0 });
});
it.each(["partial", "missing-one", "unrelated", "truncated", "complete", "no-previous-source"])("establishes disappearance only with sufficient evidence (%s)", mode => {
  const h = history().slice(0, 2), f = finding("gone");
  if (mode === "partial") h[0]!.completion.status = "partial";
  if (mode === "missing-one") h[0]!.completion.collectedEndpoints = ["/applications/new/owners"];
  if (mode === "unrelated") h[0]!.completion.collectedEndpoints = ["/groups/new/owners", "/groups/new"];
  if (mode === "no-previous-source") { h[0]!.completion.collectedEndpoints = []; h[1]!.completion.collectedEndpoints = []; }
  engine.mockImplementation(([s]) => ({ findings: s.id === "3" ? [] : [f], pathAnalysis: { truncated: mode === "truncated" } }));
  expect(analyzeFindingLifecycle(h).records[0]!.status).toBe(["complete", "no-previous-source"].includes(mode) ? "no-longer-detected" : "unconfirmed");
});
it("ranks unconfirmed history below ongoing findings of the same severity", () => {
  engine.mockImplementation(([s]) => ({ findings: s.id === "3" ? [finding("ongoing")] : [finding("ongoing"), finding("gone")], pathAnalysis: { truncated: true } }));
  expect(analyzeFindingLifecycle(history()).records.map(r => r.status)).toEqual(["ongoing", "unconfirmed"]);
});
it("rejects foreign object evidence before invoking the analysis engine", () => {
  const h = history(); h[0]!.nodes = [node({ kind: "user", label: "Foreign", tenantId: "other" })];
  expect(() => analyzeFindingLifecycle(h)).toThrow(); expect(engine).not.toHaveBeenCalled();
});
