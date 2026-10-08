import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence } from "./intelligence";
import { analyzeFindingLifecycle } from "./finding-lifecycle";
import { compareSnapshots } from "./comparisons";
import { node, edge, snapshot } from "./test-support";

describe("evidence correctness from the repository review", () => {
  const person = node({ id: "person", kind: "user", label: "App reader" });
  const app = node({ id: "workload", kind: "servicePrincipal", label: "Workload", ownerIds: ["owner"] });
  const api = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph", ownerIds: ["owner"] });
  const grant = edge("CAN_CALL_AS_APP", app, api, { id: "grant", permissions: ["RoleManagement.ReadWrite.Directory"] });

  it("does not turn app use into control, while retaining a real ownership path", () => {
    const assignment = edge("ASSIGNED_TO", person, app);
    const use = snapshot([person, app, api], [assignment, grant]);
    expect(analyzeTenantIntelligence(use).paths.filter(p => p.source.id === person.id)).toEqual([]);
    const owner = snapshot([person, app, api], [edge("OWNS", person, app), grant]);
    expect(analyzeTenantIntelligence(owner).paths.find(p => p.source.id === person.id)?.steps.map(s => s.relationship)).toEqual(["OWNS", "CAN_CALL_AS_APP"]);
  });

  it("stops at API access instead of inheriting the resource's own permissions", () => {
    const downstream = node({ kind: "servicePrincipal", label: "Downstream" });
    const snap = snapshot([person, app, api, downstream], [edge("OWNS", person, app), grant, edge("CAN_CALL_AS_APP", api, downstream, { permissions: ["Directory.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(snap).paths.some(p => p.source.id === person.id && p.target.id === downstream.id)).toBe(false);
  });

  it("does not inherit an application assignment through nested groups", () => {
    const inner = node({ kind: "group", label: "Inner" });
    const outer = node({ kind: "group", label: "Outer" });
    const snap = snapshot([person, inner, outer, app, api], [edge("MEMBER_OF", person, inner), edge("MEMBER_OF", inner, outer), edge("ASSIGNED_TO", outer, app), grant]);
    expect(analyzeTenantIntelligence(snap).paths.filter(p => p.source.id === person.id)).toEqual([]);
  });

  it("keeps an unchanged path unconfirmed when new paths exhaust the analysis budget", () => {
    const role = node({ id: "admin", kind: "directoryRole", label: "Global Administrator" });
    const known = edge("ACTIVE_IN_ROLE", person, role, { id: "known", evidence: { sourceEndpoint: "/roleManagement/directory/roleAssignments" } });
    const before = snapshot([person, role], [known], { id: "before" });
    const others = Array.from({ length: 2000 }, (_, i) => node({ id: `other-${i}`, kind: "user", label: `Other ${i}` }));
    const after = snapshot([...others, person, role], [...others.map(n => edge("ACTIVE_IN_ROLE", n, role)), known], { id: "after", scannedAt: "2026-08-27T10:00:00.000Z" });
    const id = analyzeTenantIntelligence(before).findings.find(f => f.attackPathId)!.id;
    expect(analyzeTenantIntelligence(after).pathAnalysis.truncated).toBe(true);
    expect(analyzeFindingLifecycle([after, before]).records.find(r => r.finding.id === id)?.status).toBe("unconfirmed");
    expect(after.edges.some(e => e.id === known.id)).toBe(true);
  });

  it("distinguishes unavailable evidence from confirmed removal", () => {
    const before = snapshot([app, api], [grant], { id: "before" });
    const after = snapshot([app, api], [], { id: "after", scannedAt: "2026-08-27T10:00:00.000Z" });
    expect(compareSnapshots(before, after).counts.removed).toBe(1);
    after.completion.status = "partial";
    after.completion.skippedEndpoints = ["/servicePrincipals/graph/appRoleAssignedTo"];
    expect(compareSnapshots(before, after).counts).toMatchObject({ removed: 0, unconfirmed: 1 });
  });

  it("does not infer workload dormancy from a successful user-sign-in collection", () => {
    const snap = snapshot([app, api], [grant]);
    snap.completion.collectedEndpoints.push("/auditLogs/signIns");
    expect(analyzeTenantIntelligence(snap).findings.filter(f => f.category === "dormant-access")).toEqual([]);
  });
});
