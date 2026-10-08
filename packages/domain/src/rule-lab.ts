import { cleanProjectFixture } from "./fixtures";
import { analyzeTenantIntelligenceHistory } from "./intelligence";
import { ENTRA_CONTROL_PATH_RULES } from "./rules";

export interface RuleLabCase {
  schemaVersion: 1; name: string; fixture: "clean-project-v1";
  removeEdgeIds: string[];
  expectations: Array<{ ruleId: string; version: number; minimum: number; maximum: number }>;
}

/** Import only declarative expectations and edge exclusions against a compiled synthetic fixture. */
export function parseRuleLabCase(input: unknown): RuleLabCase {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Expected a rule scenario object.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some(k => !["schemaVersion", "name", "fixture", "removeEdgeIds", "expectations"].includes(k))) throw new Error("Unknown scenario fields are rejected. Executable code and tenant exports are not accepted.");
  if (value.schemaVersion !== 1 || value.fixture !== "clean-project-v1" || typeof value.name !== "string" || !value.name.trim() || value.name.length > 120) throw new Error("Unsupported scenario schema, fixture or name.");
  if (!Array.isArray(value.removeEdgeIds) || value.removeEdgeIds.length > 100 || value.removeEdgeIds.some(id => !cleanProjectFixture.edges.some(e => e.id === id))) throw new Error("Exclusions must reference synthetic fixture edge IDs.");
  if (!Array.isArray(value.expectations) || !value.expectations.length || value.expectations.length > 20) throw new Error("Provide 1–20 rule expectations.");
  for (const raw of value.expectations) {
    if (!raw || typeof raw !== "object") throw new Error("Invalid rule expectation.");
    const e = raw as Record<string, unknown>;
    const rule = ENTRA_CONTROL_PATH_RULES.find(r => r.reference.id === e.ruleId);
    if (Object.keys(e).some(k => !["ruleId", "version", "minimum", "maximum"].includes(k)) || !rule || e.version !== rule.reference.version || !Number.isInteger(e.minimum) || !Number.isInteger(e.maximum) || (e.minimum as number) < 0 || (e.maximum as number) < (e.minimum as number) || (e.maximum as number) > 10000) throw new Error("Unknown rule, version mismatch or invalid expected range.");
  }
  return value as unknown as RuleLabCase;
}

export function replayRuleLabCase(input: unknown) {
  const scenario = parseRuleLabCase(input);
  // Stryker disable next-line StringLiteral: the internal snapshot ID is not returned or used to match findings; time and edges distinguish the replay.
  const snapshotId = "rule-lab-current";
  const current = { ...cleanProjectFixture, id: snapshotId, scannedAt: "2026-08-27T10:00:00Z", edges: cleanProjectFixture.edges.filter(e => !scenario.removeEdgeIds.includes(e.id)) };
  const analysis = analyzeTenantIntelligenceHistory([current, cleanProjectFixture]);
  const results = scenario.expectations.map(expectation => {
    const matches = analysis.findings.filter(f => f.rule?.id === expectation.ruleId);
    return { ...expectation, actual: matches.length, passed: matches.length >= expectation.minimum && matches.length <= expectation.maximum, findings: matches.map(f => ({ id: f.id, sourceEndpoints: f.sourceEndpoints, edgeIds: f.edgeIds })) };
  });
  return { name: scenario.name, fixture: scenario.fixture, synthetic: true, passed: results.every(r => r.passed) && !analysis.pathAnalysis.truncated, results };
}
