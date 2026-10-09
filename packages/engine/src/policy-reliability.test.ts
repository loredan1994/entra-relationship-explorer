import { expect, it } from "vitest";
import { compileSnapshot } from "./model";
import { evaluatePolicyScenario, findPolicyCounterexamples, type SignInScenario } from "./policy";
import { edge, node, policy, snapshot } from "./test-support";

const scenario: SignInScenario = { userId: "person", applicationId: "api", groups: [], platform: null, location: null, trustedLocation: null, clientAppType: null, mfa: true, compliantDevice: false, hybridJoinedDevice: null };

it("does not turn a canonical conflicting policy variant into a definite denial", () => {
  const variants = [policy(), policy({ grant: { operator: "AND", controls: ["compliantDevice"] } })];
  for (const records of [variants, [...variants].reverse()]) {
    const s = snapshot([]); s.nodes.push(...records);
    const result = evaluatePolicyScenario(compileSnapshot(s), scenario);
    expect(result).toEqual({ decision: "unknown", policies: [{ id: "policy", mode: "unknown", applies: null, satisfied: null, unsupported: ["conflicting-policy-evidence"] }] });
    const counterexamples = findPolicyCounterexamples(compileSnapshot(s), { require: "mfa", userIds: ["person"], applicationIds: ["api"] });
    expect(counterexamples.verdict).toBe("unknown");
    expect(counterexamples.unknown).toBe(counterexamples.checked);
    expect(counterexamples.witnesses).toEqual([]);
  }
});

it("preserves an independent definite denial alongside a conflicting policy", () => {
  const s = snapshot([]);
  s.nodes.push(policy(), policy({ state: "disabled" }), { ...policy({ grant: { operator: "AND", controls: ["block"] } }), id: "independent-block" });
  const result = evaluatePolicyScenario(compileSnapshot(s), scenario);
  expect(result.decision).toBe("requirements-unmet");
  expect(result.policies.find(p => p.id === "independent-block")).toMatchObject({ mode: "enforced", applies: true, satisfied: false });
  expect(result.policies.find(p => p.id === "policy")).toMatchObject({ mode: "unknown", applies: null, satisfied: null });
});

it("does not treat conflicting group membership as a definite policy inclusion or exclusion", () => {
  const membership = edge("membership", "person", "team", "MEMBER_OF");
  const s = snapshot([membership, { ...membership, evidence: { ...membership.evidence, configured: false } }]);
  s.nodes.push(policy({ users: { include: ["All"], exclude: [], includeGroups: [], excludeGroups: ["team"] } }));
  const intent = { require: "mfa" as const, userIds: ["person"], applicationIds: ["api"] };
  const result = findPolicyCounterexamples(compileSnapshot(s), intent);
  expect(result.verdict).toBe("unknown");
  expect(result.unknown).toBe(result.checked);
  expect(result.witnesses).toEqual([]);
  s.nodes.push({ ...policy({ grant: { operator: "AND", controls: ["block"] } }), id: "independent-block" });
  const blocked = findPolicyCounterexamples(compileSnapshot(s), intent);
  expect(blocked.verdict).toBe("refuted");
  expect(blocked.unknown).toBe(0);
});

it("retains all memberships for a principal with many directly assigned groups", () => {
  const count = 2_000;
  const s = snapshot([]);
  const groups = Array.from({ length: count }, (_, i) => `group-${i}`);
  s.nodes.push(...groups.map(id => node(id, "group")), policy({ users: { include: [], exclude: [], includeGroups: [groups.at(-1)!], excludeGroups: [] } }));
  s.edges = groups.map((id, i) => edge(`membership-${i}`, "person", id, "MEMBER_OF"));
  const result = findPolicyCounterexamples(compileSnapshot(s), { require: "mfa", userIds: ["person"], applicationIds: ["api"] });
  expect(result.verdict).toBe("refuted");
  expect(result.unknown).toBe(0);
  expect(result.limits.exhausted).toBe(false);
});
