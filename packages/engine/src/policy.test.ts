import { describe, expect, it } from "vitest";
import { compileSnapshot } from "./model";
import { evaluatePolicyScenario, findPolicyCounterexamples, type SignInScenario } from "./policy";
import { policy, snapshot } from "./test-support";

const scenario: SignInScenario = { userId: "person", applicationId: "api", groups: [], platform: "windows", location: "office", trustedLocation: true, clientAppType: "browser", mfa: false, compliantDevice: false, hybridJoinedDevice: false };
function model(...policies: ReturnType<typeof policy>[]) { const s = snapshot(); s.nodes.push(...policies); return compileSnapshot(s); }
describe("published Conditional Access decision tables", () => {
  it("AND requires every grant control; OR requires one", () => {
    for (const operator of ["AND", "OR"]) for (const mfa of [false, true]) for (const compliantDevice of [false, true]) {
      const expected = operator === "AND" ? mfa && compliantDevice : mfa || compliantDevice;
      const result = evaluatePolicyScenario(model(policy({ grant: { operator, controls: ["mfa", "compliantDevice"] } })), { ...scenario, mfa, compliantDevice });
      expect(result.decision).toBe(expected ? "permits-under-model" : "requirements-unmet");
    }
  });
  it("an exclusion overrides inclusion and all enforced policies must be satisfied", () => {
    const excluded = policy({ users: { include: ["All"], exclude: ["person"], includeGroups: [], excludeGroups: [] } });
    expect(evaluatePolicyScenario(model(excluded), scenario).decision).toBe("permits-under-model");
    const block = { ...policy({ grant: { operator: "OR", controls: ["block"] } }), id: "block" };
    expect(evaluatePolicyScenario(model(excluded, block), { ...scenario, mfa: true }).decision).toBe("requirements-unmet");
    excluded.conditionalAccess!.users.exclude = []; excluded.conditionalAccess!.users.excludeGroups = ["team"];
    expect(evaluatePolicyScenario(model(excluded), { ...scenario, groups: ["team"] }).decision).toBe("permits-under-model");
    expect(evaluatePolicyScenario(model(excluded), { ...scenario, groups: null }).decision).toBe("unknown");
  });
  it.each(["disabled", "enabledForReportingButNotEnforced"])("does not enforce %s policies", state => {
    const result = evaluatePolicyScenario(model(policy({ state })), scenario);
    expect(result.decision).toBe("permits-under-model"); expect(result.policies[0]!.mode).toBe(state === "disabled" ? "disabled" : "report-only");
  });
  it("unknown device facts or unsupported conditions cannot create an allowed scenario", () => {
    expect(evaluatePolicyScenario(model(policy({ grant: { operator: "AND", controls: ["compliantDevice"] } })), { ...scenario, compliantDevice: null }).decision).toBe("unknown");
    expect(evaluatePolicyScenario(model(policy({ unsupported: ["conditions.devices.deviceFilter"] })), { ...scenario, mfa: true }).decision).toBe("unknown");
    expect(evaluatePolicyScenario(model(policy({ grant: { operator: "OR", controls: ["unknownFutureControl"] } })), scenario).decision).toBe("unknown");
    expect(evaluatePolicyScenario(model(policy({ users: { include: [], exclude: [], includeGroups: [], excludeGroups: [] }, unsupported: ["users.include"] })), scenario).decision).toBe("unknown");
    expect(evaluatePolicyScenario(model(policy({ applications: { include: ["Office365"], exclude: [] } })), scenario).decision).toBe("unknown");
    const old = policy(); delete old.conditionalAccess; delete old.sourceEndpoint; old.metadata = { policyType: "conditionalAccess" };
    expect(evaluatePolicyScenario(model(old), scenario).decision).toBe("unknown");
  });
  it("matches resource, platform, client and named-location boundaries", () => {
    const p = policy({ applications: { include: ["api"], exclude: [] }, platforms: { include: ["windows"], exclude: [] }, clientAppTypes: ["browser"], locations: { include: ["All"], exclude: ["AllTrusted"] } });
    expect(evaluatePolicyScenario(model(p), scenario).decision).toBe("permits-under-model");
    expect(evaluatePolicyScenario(model(p), { ...scenario, trustedLocation: false }).decision).toBe("requirements-unmet");
    expect(evaluatePolicyScenario(model(p), { ...scenario, trustedLocation: null }).decision).toBe("unknown");
    expect(evaluatePolicyScenario(model(p), { ...scenario, applicationId: "different" }).decision).toBe("permits-under-model");
  });
  it("finds and minimizes an excluded-user counterexample rather than guessing compliance", () => {
    const p = policy({ users: { include: ["All"], exclude: ["person"], includeGroups: [], excludeGroups: [] } });
    const result = findPolicyCounterexamples(model(p), { require: "mfa", userIds: ["person"], applicationIds: ["api"] });
    expect(result.verdict).toBe("supported"); expect(result.witnesses).toHaveLength(1);
    expect(result.witnesses[0]!.scenario).toEqual({ ...scenario, groups: null, platform: null, location: null, trustedLocation: null, clientAppType: null, compliantDevice: null, hybridJoinedDevice: null });
    expect(findPolicyCounterexamples(model(policy()), { require: "mfa", userIds: ["person"], applicationIds: ["api"] }).verdict).toBe("refuted");
  });
  it("does not report proof of safety when coverage or search is incomplete", () => {
    const s = snapshot(); s.completion.collectors!.find(c => c.id === "conditionalAccess")!.state = "denied";
    expect(findPolicyCounterexamples(compileSnapshot(s), { require: "mfa", userIds: ["All"], applicationIds: ["All"] }).verdict).toBe("unknown");
    const bounded = findPolicyCounterexamples(model(policy()), { require: "mfa", userIds: ["All"], applicationIds: ["All"] }, 1);
    expect(bounded.limits.exhausted).toBe(true); expect(bounded.verdict).toBe("unknown");
    expect(() => findPolicyCounterexamples(model(), { require: "mfa", userIds: [], applicationIds: ["All"] })).toThrow("intent");
  });
});
