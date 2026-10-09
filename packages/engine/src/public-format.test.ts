import { describe, expect, it } from "vitest";
import { analyzeFederation, compareContract, compileSnapshot, evaluateAuthorization, evaluateContract, exportInvestigation, findPolicyCounterexamples, planEvidenceGaps, reconstructPaths, simulateContinuity, solveChanges, type AccessContract, type AuthorizationQuery } from "./index";
import { edge, node, policy, query, snapshot, TIME } from "./test-support";

/**
 * Versioned format contracts supplement the independent solver/decision-table tests.
 * Review changed provenance, assumptions, completeness, budgets and identity projection
 * before accepting an update: these fields are part of the offline replay interface.
 */
describe("version 1 evidence format compatibility", () => {
  it("projects allowlisted facts and leaves labels out of portable evidence", async () => {
    const s = snapshot(); const n = s.nodes[0]!;
    n.appId = "synthetic-app-id"; n.applicationProfile = { signInAudience: "AzureADMyOrg", verifiedPublisherId: "private-publisher", verifiedPublisherName: "Private publisher label", accountEnabled: false, assignmentRequired: true };
    n.credentials = [{ id: "metadata-only", kind: "certificate", label: "Private credential label", startsAt: TIME, expiresAt: "2027-01-01T00:00:00.000Z", sourceEndpoint: "/applications/client" }];
    n.requestedPermissions = [{ resourceAppId: "api", permissionId: "read", kind: "application" }];
    n.metadata = { accessToken: "do-not-project", arbitrary: "do-not-project" };
    s.nodes.find(n => n.id === "trust")!.federationTrust = { issuer: "https://issuer.example", subject: "repo:sample/tool:ref:main", audiences: ["exchange"], unsupported: [] };
    s.nodes.push(policy()); s.completion.collectors![0]!.limits = { maxPagesPerEndpoint: 4, maxItemsPerEndpoint: 20 };
    s.completion.collectors![0]!.window = { startsAt: "2026-10-01T00:00:00.000Z", endsAt: TIME, eventClasses: ["one", "two"] };
    const model = compileSnapshot(s);
    expect(model.nodes.find(n => n.id === "client")!.credentials![0]!.label).toBeNull();
    expect(JSON.stringify(model)).not.toContain("do-not-project");
    expect(model).toMatchSnapshot();
    const packet = await exportInvestigation(model, query);
    expect(JSON.stringify(packet)).not.toContain("metadata-only"); expect(packet.package.proof.verdict).toBe("supported");
    expect(packet).toMatchSnapshot();
  });
  const cases: Array<[string, AuthorizationQuery, ReturnType<typeof snapshot>]> = [];
  cases.push(["application grant", query, snapshot()]);
  const consent = edge("consent", "client", "resource", "CAN_CALL_DELEGATED"); consent.consent = { audience: "single-user", principalId: "person" };
  cases.push(["delegated grant", { ...query, kind: "delegated-permission", userId: "person" }, snapshot([consent])]);
  cases.push(["direct group assignment", { ...query, kind: "assignment", principalId: "person", permissionId: undefined }, snapshot([edge("member", "person", "team", "MEMBER_OF"), edge("assignment", "team", "resource", "ASSIGNED_TO")])]);
  for (const kind of ["active-role", "eligible-role"] as const) {
    const role = edge("role-link", "person", "role", kind === "active-role" ? "ACTIVE_IN_ROLE" : "ELIGIBLE_FOR_ROLE"); role.scope = { directoryScopeId: "/", objectId: null };
    cases.push([kind, { ...query, kind, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: "/" }, snapshot([role])]);
  }
  cases.push(["federated control", { ...query, kind: "control-path", principalId: "trust" }, snapshot([edge("trust-to-app", "trust", "blueprint", "FEDERATES_AS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"), edge("grant", "client", "resource")])]);
  cases.push(["ownership control", { ...query, kind: "control-path", principalId: "person" }, snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")])]);
  const partial = snapshot([]); partial.completion.collectors = []; cases.push(["missing grant inventory", query, partial]);
  cases.push(["complete absence", query, snapshot([])]);
  const conflict = snapshot(); conflict.edges.push({ ...conflict.edges[0]!, permissions: ["Disagrees"], permissionIds: ["different"] }); cases.push(["conflicting source", query, conflict]);
  it.each(cases)("preserves the public proof fields for %s", (_name, q, s) => {
    const proof = evaluateAuthorization(compileSnapshot(s), q); expect(proof.query).toEqual(q); expect(proof.engineVersion).toBe("1.0.3"); expect(proof.ruleVersion).toBe("entra-configured/4"); expect(proof).toMatchSnapshot();
  });
  it("preserves planning alternatives, bounds, protected paths and costs", () => {
    const model = compileSnapshot(snapshot()); const candidate = (id: string, cost: number) => ({ id, cost, removes: [id], description: `Exclude ${id}` });
    const result = solveChanges({ context: model, paths: [{ id: "one", dependencies: ["a", "shared"] }, { id: "two", dependencies: ["b", "shared"] }], candidates: [candidate("shared", 3), candidate("b", 2), candidate("a", 2)], protectedIntegrations: [{ id: "protected", alternatives: [{ id: "keep", dependencies: ["other"] }] }], evidenceComplete: true });
    expect(result.plans.map(p => p.cost)).toEqual([3, 4]);
    expect(result.limits.work).toBeGreaterThan(0); expect(result.limits.work).toBeLessThanOrEqual(result.limits.maxWork);
    // Native sort comparison counts vary across supported Node/V8 versions.
    expect(result).toMatchSnapshot({ limits: { work: expect.any(Number) } });
  });
  it("retains unknown read prerequisites and minimizes shared candidate reads", () => {
    const s = snapshot([]); s.completion.collectors = [];
    const result = planEvidenceGaps(evaluateAuthorization(compileSnapshot(s), query)); expect(result.plans[0]!.mayResolve).toHaveLength(2);
    expect(result).toMatchSnapshot({ limits: { work: expect.any(Number) } });
  });
  it("retains distinct overlap, mismatch and unsupported federation pairs", () => {
    const s = snapshot(), base = { issuer: "https://issuer.example", subject: "sample-production", audiences: ["exchange"], unsupported: [] };
    s.nodes.find(n => n.id === "trust")!.federationTrust = base;
    s.nodes.push({ ...node("trust-2", "federatedCredential"), federationTrust: base }, { ...node("trust-3", "federatedCredential"), federationTrust: { ...base, subject: "sample-staging" } }, node("trust-4", "federatedCredential"));
    const result = analyzeFederation(compileSnapshot(s)); expect(result.comparisons.filter(p => p.verdict === "supported")).toHaveLength(1); expect(result).toMatchSnapshot();
  });
  it("preserves minimized policy scenarios and report-only applicability", () => {
    const s = snapshot(); s.nodes.push(policy({ state: "enabledForReportingButNotEnforced" }));
    const result = findPolicyCounterexamples(compileSnapshot(s), { require: "mfa", userIds: ["person"], applicationIds: ["api"] });
    expect(result.verdict).toBe("supported"); expect(result.witnesses[0]!.scenario.mfa).toBe(false); expect(result).toMatchSnapshot();
  });
  it("preserves time windows, uncertain continuity and collection context", () => {
    const s = snapshot(); s.edges[0]!.validity = { startsAt: "2026-10-01T00:00:00.000Z", endsAt: "2026-10-31T00:00:00.000Z" };
    const later = structuredClone(s); later.id = "later"; later.scannedAt = "2026-10-10T12:00:00.000Z";
    const result = reconstructPaths([compileSnapshot(later), compileSnapshot(s)], query); expect(result.paths[0]!.validity).toBe("overlap"); expect(result).toMatchSnapshot();
  });
  it("retains declared deployment intervals, fallback windows and dependencies", () => {
    const s = snapshot(); s.nodes[0]!.credentials = [{ id: "old", kind: "password", label: null, startsAt: "2026-10-01T00:00:00.000Z", expiresAt: "2026-10-10T00:00:00.000Z", sourceEndpoint: "/applications/client" }, { id: "new", kind: "certificate", label: null, startsAt: "2026-10-08T00:00:00.000Z", expiresAt: "2026-11-01T00:00:00.000Z", sourceEndpoint: "/applications/client" }];
    const result = simulateContinuity(compileSnapshot(s), { tenantId: query.tenantId, horizon: { startsAt: TIME, endsAt: "2026-10-11T00:00:00.000Z" }, clockSkewSeconds: 0,
      deployments: [{ credentialKey: "client/old", availableFrom: "2026-10-01T00:00:00.000Z" }, { credentialKey: "client/new", availableFrom: "2026-10-09T00:00:00.000Z" }], workloads: [{ id: "worker", credentialKeys: ["client/old", "client/new"], requires: [] }] });
    expect(result.verdict).toBe("supported"); expect(result.intervals.some(i => i.rollbackAvailable)).toBe(true); expect(result).toMatchSnapshot();
  });
  it("preserves contract failures and complete semantic additions", () => {
    const s = snapshot(), before = compileSnapshot(s); s.nodes.push(node("rogue")); s.edges.push(edge("rogue-grant", "rogue", "resource"));
    const contract: AccessContract = { version: 1, id: "only-production", tenantId: query.tenantId, kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: ["client"] };
    const report = evaluateContract(compileSnapshot(s), contract); expect(report.status).toBe("fail"); expect(report).toMatchSnapshot();
    const change = compareContract(before, compileSnapshot(s), contract); expect(change.addedPaths).toHaveLength(1); expect(change).toMatchSnapshot();
  });
  it("preserves pseudonymized offline replay format and identity-map separation", async () => {
    const result = await exportInvestigation(compileSnapshot(snapshot()), query, "pseudonymized");
    expect(JSON.stringify(result.package)).not.toContain("synthetic-tenant"); expect(result).toMatchSnapshot();
  });
});
