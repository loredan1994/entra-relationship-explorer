import { expect, it } from "vitest";
import { parseRuleLabCase, replayRuleLabCase } from "./rule-lab";
import { cleanProjectFixture } from "./fixtures";
const expectation = { ruleId: "ERE-IAM-001", version: 1, minimum: 0, maximum: 10000 };
const base = { schemaVersion: 1, name: "Synthetic contract", fixture: "clean-project-v1", removeEdgeIds: [], expectations: [expectation] };
it.each([null, 0, "value", true, []])("rejects non-object scenarios %j", value => expect(() => parseRuleLabCase(value)).toThrow("Expected a rule scenario object."));
it.each([{ extra: true }, { code: "console.log(1)" }])("rejects unrecognized schema fields", value => expect(() => parseRuleLabCase({ ...base, ...value })).toThrow("Unknown scenario fields are rejected. Executable code and tenant exports are not accepted."));
it.each([{ schemaVersion: 0 }, { fixture: "real-tenant" }, { name: 123 }, { name: "" }, { name: "  " }, { name: "a".repeat(121) }])("rejects unsupported schema, fixture or name (%#)", value => expect(() => parseRuleLabCase({ ...base, ...value })).toThrow("Unsupported scenario schema, fixture or name."));
it.each([null, "edge", [123], ["missing"], Array(101).fill(cleanProjectFixture.edges[0]!.id)])("rejects invalid exclusions (%#)", removeEdgeIds => expect(() => parseRuleLabCase({ ...base, removeEdgeIds })).toThrow("Exclusions must reference synthetic fixture edge IDs."));
it.each([null, {}, [], Array(21).fill(expectation)])("bounds expectation count (%#)", expectations => expect(() => parseRuleLabCase({ ...base, expectations })).toThrow("Provide 1–20 rule expectations."));
it.each([null, 1, false, "rule"])("rejects invalid expectation object %j", value => expect(() => parseRuleLabCase({ ...base, expectations: [value] })).toThrow("Invalid rule expectation."));
it.each([
  { extra: 1 }, { ruleId: "missing" }, { version: 2 }, { minimum: 0.5 }, { maximum: 0.5 },
  { minimum: -1 }, { minimum: 1, maximum: 0 }, { maximum: 10001 }, { minimum: "0" }, { maximum: "1" },
])("rejects unsafe or inconsistent ranges (%#)", patch => expect(() => parseRuleLabCase({ ...base, expectations: [{ ...expectation, ...patch }] })).toThrow("Unknown rule, version mismatch or invalid expected range."));
it("accepts the exact public limits and preserves declarative content", () => {
  const value = { ...base, name: "a".repeat(120), removeEdgeIds: Array(100).fill(cleanProjectFixture.edges[0]!.id), expectations: Array(20).fill(expectation) };
  expect(parseRuleLabCase(value)).toEqual(value);
  expect(parseRuleLabCase({ ...base, expectations: [{ ...expectation, minimum: 10000 }] }).expectations[0]).toMatchObject({ minimum: 10000, maximum: 10000 });
});
it("reports concrete evidence for positive cases and exact zero after removing controls", () => {
  const result = replayRuleLabCase(base);
  expect(result).toMatchObject({ name: "Synthetic contract", fixture: "clean-project-v1", synthetic: true, passed: true });
  const item = result.results[0]!;
  expect(item).toMatchObject(expectation); expect(item.actual).toBeGreaterThan(0);
  expect(item.findings).toHaveLength(item.actual);
  for (const finding of item.findings) {
    expect(finding.id).toBeTruthy(); expect(finding.sourceEndpoints.length).toBeGreaterThan(0);
    expect(finding.edgeIds.length).toBeGreaterThan(0);
    expect(finding.edgeIds.every(id => cleanProjectFixture.edges.some(e => e.id === id))).toBe(true);
  }
  const exact = { ...expectation, minimum: item.actual, maximum: item.actual };
  expect(replayRuleLabCase({ ...base, expectations: [exact] }).passed).toBe(true);
  expect(replayRuleLabCase({ ...base, expectations: [{ ...exact, minimum: 0, maximum: item.actual - 1 }] }).passed).toBe(false);
  expect(replayRuleLabCase({ ...base, expectations: [{ ...exact, minimum: item.actual + 1, maximum: item.actual + 1 }] }).passed).toBe(false);
  const removed = replayRuleLabCase({ ...base, removeEdgeIds: cleanProjectFixture.edges.filter(e => ["OWNS", "FEDERATES_AS"].includes(e.type)).map(e => e.id), expectations: [{ ...expectation, maximum: 0 }] });
  expect(removed.results).toEqual([{ ...expectation, maximum: 0, actual: 0, passed: true, findings: [] }]);
  expect(removed.passed).toBe(true);
});

it("fails the whole replay when one expectation fails even if another passes", () => {
  const actual = replayRuleLabCase(base).results[0]!.actual;
  expect(replayRuleLabCase({ ...base, expectations: [expectation, { ...expectation, minimum: actual + 1 }] })).toMatchObject({ passed: false, results: [{ passed: true }, { passed: false }] });
});
