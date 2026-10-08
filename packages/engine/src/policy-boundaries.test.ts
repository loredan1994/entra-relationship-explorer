import { expect, it } from "vitest";
import type { ConditionalAccessDefinition } from "@entra-explorer/domain";
import { compileSnapshot, evaluatePolicyScenario, findPolicyCounterexamples, type SignInScenario } from "./index";
import { edge, node, policy, snapshot } from "./test-support";
const scenario: SignInScenario = { userId: "person", applicationId: "api", groups: ["team"], platform: "windows", location: "office", trustedLocation: false, clientAppType: "browser", mfa: false, compliantDevice: false, hybridJoinedDevice: false };
const evaluate = (p: Partial<ConditionalAccessDefinition>, s: Partial<SignInScenario> = {}) => { const data = snapshot(); data.nodes.push(policy(p)); return evaluatePolicyScenario(compileSnapshot(data), { ...scenario, ...s }); };
const users = (include: string[], exclude: string[] = [], includeGroups: string[] = [], excludeGroups: string[] = []) => ({ include, exclude, includeGroups, excludeGroups });
// Expected applicability is stated independently for each selector boundary.
const cases: Array<[string, Partial<ConditionalAccessDefinition>, Partial<SignInScenario>, boolean | null]> = [
  ["empty user selector", { users: users([]) }, {}, false],
  ["None user selector", { users: users(["None"]) }, {}, false],
  ["None alongside actual user", { users: users(["None", "person"]) }, {}, true],
  ["other exact user", { users: users(["other"]) }, {}, false],
  ["group union", { users: users([], [], ["missing", "team"]) }, {}, true],
  ["unknown included groups", { users: users([], [], ["team"]) }, { groups: null }, null],
  ["excluded group union", { users: users(["All"], [], [], ["missing", "team"]) }, {}, false],
  ["excluded app", { applications: { include: ["All"], exclude: ["api"] } }, {}, false],
  ["other excluded app", { applications: { include: ["All"], exclude: ["other"] } }, {}, true],
  ["resource alias inclusion", { applications: { include: ["api", "MicrosoftAdminPortals"], exclude: [] } }, {}, null],
  ["resource alias exclusion", { applications: { include: ["All"], exclude: ["Office365"] } }, {}, null],
  ["guest selector", { users: users(["GuestsOrExternalUsers"]) }, {}, null],
  ["guest exclusion", { users: users(["All"], ["GuestsOrExternalUsers"]) }, {}, null],
  ["definite exclusion with unsupported conditions", { users: users(["All"], ["person"]), unsupported: ["risk"] }, {}, false],
  ["all platforms", { platforms: { include: ["all"], exclude: [] } }, { platform: null }, true],
  ["all platforms excluded", { platforms: { include: ["all"], exclude: ["all"] } }, {}, false],
  ["other platform", { platforms: { include: ["linux"], exclude: [] } }, {}, false],
  ["unknown platform", { platforms: { include: ["windows"], exclude: [] } }, { platform: null }, null],
  ["excluded platform", { platforms: { include: ["all"], exclude: ["windows"] } }, {}, false],
  ["unknown exclusion platform", { platforms: { include: ["all"], exclude: ["linux"] } }, { platform: null }, null],
  ["all client types", { clientAppTypes: ["all"] }, { clientAppType: null }, true],
  ["other client type", { clientAppTypes: ["mobileAppsAndDesktopClients"] }, {}, false],
  ["unknown client type", { clientAppTypes: ["browser"] }, { clientAppType: null }, null],
  ["trusted location only", { locations: { include: ["AllTrusted"], exclude: [] } }, {}, false],
  ["trusted location exact", { locations: { include: ["AllTrusted"], exclude: [] } }, { trustedLocation: true, location: null }, true],
  ["trusted location unknown", { locations: { include: ["AllTrusted"], exclude: [] } }, { trustedLocation: null }, null],
  ["literal AllTrusted is not a named location", { locations: { include: ["AllTrusted"], exclude: [] } }, { trustedLocation: false, location: "AllTrusted" }, false],
  ["named location union", { locations: { include: ["office", "AllTrusted"], exclude: [] } }, {}, true],
  ["other named location", { locations: { include: ["remote"], exclude: [] } }, {}, false],
  ["unknown named location", { locations: { include: ["office"], exclude: [] } }, { location: null }, null],
];
it.each(cases)("selector: %s", (_name, policy, scenario, applies) => {
  const result = evaluate(policy, scenario);
  expect(result.policies[0]!.applies).toBe(applies);
  expect(result.decision).toBe(applies === true ? "requirements-unmet" : applies === false ? "permits-under-model" : "unknown");
});
it("hybrid join has three-valued AND/OR semantics, while block is decisive", () => {
  for (const operator of ["AND", "OR"]) for (const mfa of [true, false, null]) for (const hybridJoinedDevice of [true, false, null]) {
    const values = [mfa, hybridJoinedDevice];
    const expected = operator === "AND" ? values.includes(false) ? false : values.includes(null) ? null : true : values.includes(true) ? true : values.includes(null) ? null : false;
    expect(evaluate({ grant: { operator, controls: ["mfa", "domainJoinedDevice"] } }, { mfa, hybridJoinedDevice }).policies[0]!.satisfied).toBe(expected);
    expect(evaluate({ grant: { operator, controls: ["block", "mfa"] } }, { mfa }).decision).toBe("requirements-unmet");
  }
  for (const grant of [null, { operator: "AND", controls: [] }, { operator: "future", controls: ["mfa"] }]) expect(evaluate({ grant }).policies[0]!.satisfied).toBeNull();
});
it("unknown modes and legacy CA records stay unknown but other policy families are ignored", () => {
  expect(evaluate({ state: "future" }).policies[0]!.mode).toBe("unknown"); expect(evaluate({ state: "future" }).decision).toBe("unknown");
  for (const kind of ["authorization", "permissionGrant", "crossTenantAccess"]) {
    const s = snapshot(); const p = node(kind, "policy"); p.metadata = { policyType: kind }; s.nodes.push(p);
    expect(evaluatePolicyScenario(compileSnapshot(s), scenario)).toEqual({ decision: "permits-under-model", policies: [] });
    p.sourceEndpoint = "/identity/conditionalAccess/policies";
    expect(evaluatePolicyScenario(compileSnapshot(s), scenario).policies[0]).toEqual({ id: kind, mode: "unknown", applies: null, satisfied: null, unsupported: ["structured-policy-not-collected"] });
  }
  expect(evaluate({ state: "disabled" }).policies[0]).toEqual({ id: "policy", mode: "disabled", applies: false, satisfied: false, unsupported: [] });
  const s = snapshot(); s.nodes.push(policy(), { ...policy(), label: "Conflicting source" });
  expect(evaluatePolicyScenario(compileSnapshot(s), { ...scenario, mfa: true }).decision).toBe("unknown");
});
it("resolves nested group closure once per encountered user and terminates cycles", () => {
  const s = snapshot([edge("a", "person", "nested", "MEMBER_OF"), edge("b", "nested", "team", "MEMBER_OF"), edge("cycle", "team", "nested", "MEMBER_OF")]);
  s.nodes.push(policy({ users: users([], [], ["team"]) }));
  const intent = { require: "mfa" as const, userIds: ["person"], applicationIds: ["api"] };
  expect(findPolicyCounterexamples(compileSnapshot(s), intent).verdict).toBe("refuted");
  s.edges[1]!.evidence.configured = false;
  const result = findPolicyCounterexamples(compileSnapshot(s), intent);
  expect(result.verdict).toBe("supported"); expect(result.witnesses[0]!.scenario.groups).toEqual(["nested"]);
  s.edges[1]!.evidence.configured = true; s.edges[1]!.evidence.completeness = "partial";
  expect(findPolicyCounterexamples(compileSnapshot(s), intent).verdict).toBe("unknown");
  s.edges[1]!.evidence.completeness = "complete"; s.completion.collectors!.find(c => c.id === "groupMemberships")!.state = "denied";
  expect(findPolicyCounterexamples(compileSnapshot(s), intent).verdict).toBe("unknown");
});
it("generates literal domains and a fresh complement and respects exact scenario limits", () => {
  const s = snapshot(); s.nodes.push(policy({ users: users(["All", "None"], ["outside"]), applications: { include: ["synthetic:other"], exclude: ["excluded-api"] }, platforms: { include: ["all"], exclude: ["linux"] }, locations: { include: ["All", "AllTrusted"], exclude: ["remote"] }, clientAppTypes: ["browser", "all"] }));
  const intent = { require: "block" as const, userIds: ["All"], applicationIds: ["All"] };
  const result = findPolicyCounterexamples(compileSnapshot(s), intent);
  expect(result.domainSize).toBe(4 * 3 * 2 * 2 * 2 * 16);
  expect(result.checked).toBe(result.domainSize); expect(result.limits.exhausted).toBe(false);
  expect(result.witnesses.some(w => w.scenario.applicationId === "synthetic:other:other")).toBe(true);
  expect(findPolicyCounterexamples(compileSnapshot(s), intent, result.domainSize).limits.exhausted).toBe(false);
  expect(findPolicyCounterexamples(compileSnapshot(s), intent, result.domainSize - 1).missing).toContain("budget:policy-scenarios");
  const ids = Array.from({ length: 101 }, (_, i) => `person-${String(i).padStart(3, "0")}`);
  const many = findPolicyCounterexamples(compileSnapshot(snapshot()), { require: "compliantDevice", userIds: ids, applicationIds: ["api"] });
  expect(many.witnesses).toHaveLength(100); expect(many.checked).toBe(1616);
  expect(many.witnesses.map(w => w.scenario.userId)).toEqual(ids.slice(0, 100));
  expect(many.witnesses.every(w => w.scenario.compliantDevice === false && w.scenario.mfa === null)).toBe(true);
});
it("keeps all incomplete scenario counts and validation failures explicit", () => {
  const s = snapshot(); s.completion.collectors = [];
  const result = findPolicyCounterexamples(compileSnapshot(s), { require: "mfa", userIds: ["person"], applicationIds: ["api"] });
  expect(result.unknown).toBe(16); expect(result.missing).toEqual(["supported-complete-policy-conditions"]); expect(result.witnesses).toEqual([]);
  for (const intent of [{ require: "future", userIds: ["All"], applicationIds: ["All"] }, { require: "mfa", userIds: ["All"], applicationIds: [] }]) expect(() => findPolicyCounterexamples(compileSnapshot(snapshot()), intent as Parameters<typeof findPolicyCounterexamples>[1])).toThrow("Invalid policy intent.");
  expect(() => findPolicyCounterexamples(compileSnapshot(s), { require: "block", userIds: ["All"], applicationIds: ["All"] }, 0)).toThrow("policy scenarios budget");
});
