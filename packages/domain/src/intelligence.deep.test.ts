import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, type FindingSeverity, type IamFinding } from "./intelligence";
import { edge, node, snapshot } from "./test-support";
import type { TenantSnapshot } from "./types";

function findingByCategory(snap: TenantSnapshot, category: IamFinding["category"]): IamFinding | undefined {
  return analyzeTenantIntelligence(snap).findings.find((finding) => finding.category === category);
}

describe("severity of reachable access", () => {
  const caller = () => node({ kind: "servicePrincipal", label: "Caller", metadata: { ownershipExpected: true }, ownerIds: [] });
  const resource = () => node({ kind: "servicePrincipal", label: "Microsoft Graph" });

  function pathSeverityFor(permissions: string[], type: "CAN_CALL_AS_APP" | "CAN_CALL_DELEGATED"): FindingSeverity | undefined {
    const c = caller();
    const r = resource();
    const snap = snapshot([c, r], [edge(type, c, r, { permissions })]);
    return analyzeTenantIntelligence(snap).paths[0]?.severity;
  }

  it("rates directory-escalation application access as critical, delegated as high", () => {
    expect(pathSeverityFor(["RoleManagement.ReadWrite.Directory"], "CAN_CALL_AS_APP")).toBe("critical");
    expect(pathSeverityFor(["RoleManagement.ReadWrite.Directory"], "CAN_CALL_DELEGATED")).toBe("high");
  });

  it("rates tenant write application access as high, delegated as medium", () => {
    expect(pathSeverityFor(["Mail.ReadWrite"], "CAN_CALL_AS_APP")).toBe("high");
    expect(pathSeverityFor(["Mail.ReadWrite"], "CAN_CALL_DELEGATED")).toBe("medium");
  });

  it("rates tenant-wide application reads as medium but does not raise a path for a single scoped read", () => {
    expect(pathSeverityFor(["Directory.Read.All"], "CAN_CALL_AS_APP")).toBe("medium");
    // A delegated .All read is not escalation, write, nor app+.All → no path.
    expect(pathSeverityFor(["Directory.Read.All"], "CAN_CALL_DELEGATED")).toBeUndefined();
  });

  it("does not invent a path from a scoped single-resource read", () => {
    expect(pathSeverityFor(["User.Read"], "CAN_CALL_AS_APP")).toBeUndefined();
  });

  it("separates Global Administrator role activation from ordinary roles", () => {
    const person = node({ kind: "user", label: "Operator" });
    const globalAdmin = node({ kind: "directoryRole", label: "Global Administrator" });
    const helpdesk = node({ kind: "directoryRole", label: "Helpdesk Administrator" });
    const critical = snapshot([person, globalAdmin], [edge("ACTIVE_IN_ROLE", person, globalAdmin)]);
    const high = snapshot([person, helpdesk], [edge("ACTIVE_IN_ROLE", person, helpdesk)]);
    expect(analyzeTenantIntelligence(critical).paths[0]?.severity).toBe("critical");
    expect(analyzeTenantIntelligence(high).paths[0]?.severity).toBe("high");
  });

  it("rates eligibility below active membership", () => {
    const person = node({ kind: "user", label: "Operator" });
    const globalAdmin = node({ kind: "directoryRole", label: "Global Administrator" });
    const eligible = snapshot([person, globalAdmin], [edge("ELIGIBLE_FOR_ROLE", person, globalAdmin)]);
    expect(analyzeTenantIntelligence(eligible).paths[0]?.severity).toBe("high");
  });
});

describe("attack path structure", () => {
  const person = node({ kind: "user", label: "Maya Chen" });
  const app = node({ kind: "servicePrincipal", label: "Orchestrator", metadata: { ownershipExpected: true } });
  const graph = node({ kind: "servicePrincipal", label: "Microsoft Graph" });
  const own = edge("OWNS", person, app);
  const call = edge("CAN_CALL_AS_APP", app, graph, { permissions: ["Application.ReadWrite.All"] });
  const snap = snapshot([person, app, graph], [own, call]);

  // Both the person and the unowned Orchestrator are candidate origins, and paths of
  // equal severity sort shortest-first, so the multi-step path is selected by origin.
  const fromPerson = () => analyzeTenantIntelligence(snap).paths.find((path) => path.source.label === "Maya Chen")!;

  it("threads a multi-step path from origin to powerful access with configured evidence", () => {
    const path = fromPerson();
    expect(path.source.label).toBe("Maya Chen");
    expect(path.target.label).toBe("Microsoft Graph");
    expect(path.title).toBe("Maya Chen can reach Microsoft Graph");
    expect(path.steps.map((step) => step.relationship)).toEqual(["OWNS", "CAN_CALL_AS_APP"]);
    expect(path.steps.every((step) => step.evidenceClass === "configured")).toBe(true);
    expect(path.severity).toBe("critical");
  });

  it("names concrete prerequisites, MITRE techniques, and mitigations", () => {
    const path = fromPerson();
    expect(path.prerequisites[0]).toContain("Maya Chen");
    expect(path.attackMappings).toEqual([
      { id: "T1098", name: "Account Manipulation" },
      { id: "T1078.004", name: "Valid Accounts: Cloud Accounts" },
    ]);
    expect(path.mitigations.some((line) => line.includes("Application.ReadWrite.All") && line.includes("Microsoft Graph"))).toBe(true);
    expect(path.mitigations.some((line) => line.toLowerCase().includes("re-scan"))).toBe(true);
  });

  it("marks a complete snapshot as medium confidence and a partial one as low", () => {
    expect(analyzeTenantIntelligence(snap).paths[0]!.confidence).toBe("medium");
    const partial = snapshot(snap.nodes, snap.edges, {
      completion: { status: "partial", collectedEndpoints: ["/applications"], skippedEndpoints: [], errors: [] },
    });
    const partialPath = analyzeTenantIntelligence(partial).paths[0]!;
    expect(partialPath.confidence).toBe("low");
    expect(partialPath.uncertainty.some((line) => line.includes("partial"))).toBe(true);
  });

  it("orders paths by severity, then length, without duplicates", () => {
    const paths = analyzeTenantIntelligence(snap).paths;
    const ids = paths.map((path) => path.id);
    expect(new Set(ids).size).toBe(ids.length);
    const order: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    for (let index = 1; index < paths.length; index += 1) {
      expect(order[paths[index - 1]!.severity]).toBeLessThanOrEqual(order[paths[index]!.severity]);
    }
  });

  it("does not traverse observed-call edges when inferring possibilities", () => {
    const a = node({ kind: "servicePrincipal", label: "A", ownerIds: [] });
    const b = node({ kind: "servicePrincipal", label: "B" });
    const observedOnly = snapshot([a, b], [edge("OBSERVED_CALL", a, b, { permissions: ["Mail.ReadWrite"] })]);
    expect(analyzeTenantIntelligence(observedOnly).paths).toHaveLength(0);
  });
});

describe("application permission findings", () => {
  function appFinding(permissions: string[]): IamFinding {
    const caller = node({ kind: "servicePrincipal", label: "Automation", metadata: { ownershipExpected: true }, ownerIds: ["owner-1"] });
    const graph = node({ kind: "servicePrincipal", label: "Microsoft Graph" });
    const snap = snapshot([caller, graph], [edge("CAN_CALL_AS_APP", caller, graph, { permissions })]);
    return analyzeTenantIntelligence(snap).findings.find((finding) => finding.title === "Automation can act without a signed-in person")!;
  }

  it("escalates to critical for directory-changing permissions", () => {
    expect(appFinding(["AppRoleAssignment.ReadWrite.All"]).severity).toBe("critical");
  });

  it("rates write or tenant-wide application permissions as high", () => {
    expect(appFinding(["Mail.ReadWrite"]).severity).toBe("high");
    expect(appFinding(["Directory.Read.All"]).severity).toBe("high");
  });

  it("rates a narrow application read as medium and lists the exact permission", () => {
    const finding = appFinding(["User.Read"]);
    expect(finding.severity).toBe("medium");
    expect(finding.summary).toBe("Configured application access: User.Read.");
    expect(finding.evidenceClass).toBe("configured");
    expect(finding.whyItMatters).toContain("workload identity");
    expect(finding.uncertainty[0]).toContain("does not prove token theft");
  });
});

describe("delegated consent findings", () => {
  function delegatedFinding(permissions: string[]): IamFinding {
    const caller = node({ kind: "servicePrincipal", label: "Expense Reporter", metadata: { ownershipExpected: true }, ownerIds: ["owner-1"] });
    const graph = node({ kind: "servicePrincipal", label: "Microsoft Graph" });
    const snap = snapshot([caller, graph], [edge("CAN_CALL_DELEGATED", caller, graph, { permissions })]);
    return analyzeTenantIntelligence(snap).findings.find((finding) => finding.category === "oauth-consent")!;
  }

  it("rates delegated write as high and delegated read as medium", () => {
    expect(delegatedFinding(["Mail.ReadWrite"]).severity).toBe("high");
    expect(delegatedFinding(["Mail.Read"]).severity).toBe("medium");
  });

  it("explains consent phishing risk and points at removal", () => {
    const finding = delegatedFinding(["Mail.Read"]);
    expect(finding.title).toBe("Delegated consent lets Expense Reporter act for a signed-in person");
    expect(finding.whyItMatters).toContain("tricked into authorizing");
    expect(finding.remediation.some((line) => line.toLowerCase().includes("remove consent"))).toBe(true);
  });
});

describe("ownership, credential, and identity findings", () => {
  it("flags an application with no recorded owner as medium", () => {
    const orphan = node({ kind: "application", label: "Orphan App", ownerIds: [] });
    const finding = findingByCategory(snapshot([orphan], []), "ownership")!;
    expect(finding.title).toBe("Orphan App has no recorded owner");
    expect(finding.severity).toBe("medium");
    expect(finding.evidenceClass).toBe("configured");
    expect(finding.affectedObjectIds).toEqual([orphan.id]);
  });

  it("does not flag ownership for a service principal that is not expected to have an owner", () => {
    const firstParty = node({ kind: "servicePrincipal", label: "Microsoft Graph", ownerIds: [] });
    expect(findingByCategory(snapshot([firstParty], []), "ownership")).toBeUndefined();
  });

  it("rates an expired credential above an expiring one", () => {
    const expired = node({ kind: "application", label: "Legacy", ownerIds: ["o"], credential: { status: "expired", expiresAt: "2025-01-01T00:00:00Z" } });
    const expiring = node({ kind: "application", label: "Soon", ownerIds: ["o"], credential: { status: "expiring", expiresAt: "2027-01-01T00:00:00Z" } });
    expect(findingByCategory(snapshot([expired], []), "application-credential")!.severity).toBe("high");
    expect(findingByCategory(snapshot([expiring], []), "application-credential")!.severity).toBe("medium");
  });

  it("ignores healthy and absent credentials", () => {
    const healthy = node({ kind: "application", label: "Healthy", ownerIds: ["o"], credential: { status: "healthy", expiresAt: "2028-01-01T00:00:00Z" } });
    expect(findingByCategory(snapshot([healthy], []), "application-credential")).toBeUndefined();
  });

  it("cites the service principal endpoint for a workload credential finding", () => {
    const workload = node({
      kind: "servicePrincipal", label: "Reporting Workload", ownerIds: ["o"],
      metadata: { ownershipExpected: true }, credential: { status: "expiring", expiresAt: "2027-01-01T00:00:00Z" },
    });
    const finding = findingByCategory(snapshot([workload], []), "application-credential")!;
    expect(finding.sourceEndpoints).toEqual(["/servicePrincipals"]);
    expect(finding.title).toBe("Reporting Workload has an expiring credential");
  });

  it("cites the application endpoint for an application credential finding", () => {
    const registration = node({
      kind: "application", label: "Legacy App", ownerIds: ["o"],
      credential: { status: "expired", expiresAt: "2025-01-01T00:00:00Z" },
    });
    expect(findingByCategory(snapshot([registration], []), "application-credential")!.sourceEndpoints).toEqual(["/applications"]);
  });

  it("flags external identities and managed identities distinctly", () => {
    const guest = node({ kind: "user", label: "Partner Person", isExternal: true });
    const managed = node({ kind: "managedIdentity", label: "Deploy MI", risk: { level: "high", reason: "Broad access." } });
    expect(findingByCategory(snapshot([guest], []), "guest-exposure")!.severity).toBe("medium");
    const managedFinding = findingByCategory(snapshot([managed], []), "managed-identity")!;
    expect(managedFinding.severity).toBe("high");
    expect(managedFinding.title).toBe("Managed identity exposure: Deploy MI");
  });

  it("flags a disabled Conditional Access policy but not an enabled one", () => {
    const disabled = node({ kind: "policy", label: "Block legacy auth", metadata: { policyType: "conditionalAccess", state: "disabled" } });
    const enabled = node({ kind: "policy", label: "Require MFA", metadata: { policyType: "conditionalAccess", state: "enabled" } });
    expect(findingByCategory(snapshot([disabled], []), "conditional-access")!.severity).toBe("medium");
    expect(findingByCategory(snapshot([enabled], []), "conditional-access")).toBeUndefined();
  });

  it("names a Conditional Access policy with no recorded state as not enabled", () => {
    const stateless = node({ kind: "policy", label: "Unlabelled policy", metadata: { policyType: "conditionalAccess" } });
    const finding = findingByCategory(snapshot([stateless], []), "conditional-access")!;
    expect(finding.title).toBe("Conditional Access policy is not enabled: Unlabelled policy");
  });

  it("raises cross-tenant trust severity when device or MFA claims are trusted", () => {
    const trusting = node({ kind: "externalTenant", label: "Partner Tenant", metadata: { trustsMfa: true } });
    const plain = node({ kind: "externalTenant", label: "Vendor Tenant", metadata: {} });
    expect(findingByCategory(snapshot([trusting], []), "cross-tenant")!.severity).toBe("high");
    expect(findingByCategory(snapshot([plain], []), "cross-tenant")!.severity).toBe("medium");
  });
});

describe("PIM eligibility finding", () => {
  it("rates eligibility for a privileged role as high and a lesser role as medium", () => {
    const person = node({ kind: "user", label: "Eng" });
    const priv = node({ kind: "directoryRole", label: "Privileged Role Administrator" });
    const lesser = node({ kind: "directoryRole", label: "Reports Reader" });
    const privSnap = snapshot([person, priv], [edge("ELIGIBLE_FOR_ROLE", person, priv)]);
    const lesserSnap = snapshot([person, lesser], [edge("ELIGIBLE_FOR_ROLE", person, lesser)]);
    expect(findingByCategory(privSnap, "privilege-path")).toBeDefined();
    const privPim = analyzeTenantIntelligence(privSnap).findings.find((f) => f.id.startsWith("finding-pim"))!;
    const lesserPim = analyzeTenantIntelligence(lesserSnap).findings.find((f) => f.id.startsWith("finding-pim"))!;
    expect(privPim.severity).toBe("high");
    expect(lesserPim.severity).toBe("medium");
    expect(privPim.uncertainty[0]).toContain("does not prove the role was activated");
  });
});

describe("dormant access finding", () => {
  it("is only produced when a sign-in activity window was collected", () => {
    const caller = node({ kind: "servicePrincipal", label: "Idle App", metadata: { ownershipExpected: true }, ownerIds: ["o"] });
    const graph = node({ kind: "servicePrincipal", label: "Microsoft Graph" });
    const call = edge("CAN_CALL_AS_APP", caller, graph, { permissions: ["User.Read"] });
    const withoutActivity = snapshot([caller, graph], [call]);
    expect(findingByCategory(withoutActivity, "dormant-access")).toBeUndefined();

    const withActivity = snapshot([caller, graph], [call], {
      completion: { status: "complete", collectedEndpoints: ["/servicePrincipals", "/auditLogs/signIns"], skippedEndpoints: [], errors: [] },
    });
    const dormant = findingByCategory(withActivity, "dormant-access")!;
    expect(dormant.severity).toBe("medium");
    expect(dormant.evidenceClass).toBe("inferred");
    expect(dormant.uncertainty[0]).toContain("not proof");
  });

  it("does not flag a source that has an observed call", () => {
    const caller = node({ kind: "servicePrincipal", label: "Busy App", metadata: { ownershipExpected: true }, ownerIds: ["o"] });
    const graph = node({ kind: "servicePrincipal", label: "Microsoft Graph" });
    const snap = snapshot([caller, graph], [
      edge("CAN_CALL_AS_APP", caller, graph, { permissions: ["User.Read"] }),
      edge("OBSERVED_CALL", caller, graph),
    ], {
      completion: { status: "complete", collectedEndpoints: ["/servicePrincipals", "/auditLogs/signIns"], skippedEndpoints: [], errors: [] },
    });
    expect(findingByCategory(snap, "dormant-access")).toBeUndefined();
  });
});

describe("coverage finding and counts", () => {
  it("marks skipped endpoints missing and escalates severity for a partial snapshot", () => {
    const complete = snapshot([node({ kind: "application", label: "A", ownerIds: ["o"] })], [], {
      completion: { status: "complete", collectedEndpoints: ["/applications"], skippedEndpoints: ["/auditLogs/signIns"], errors: [] },
    });
    const partial = snapshot([node({ kind: "application", label: "A", ownerIds: ["o"] })], [], {
      completion: { status: "partial", collectedEndpoints: ["/applications"], skippedEndpoints: ["/auditLogs/signIns"], errors: ["429 throttled"] },
    });
    expect(findingByCategory(complete, "coverage")!.severity).toBe("low");
    const partialCoverage = findingByCategory(partial, "coverage")!;
    expect(partialCoverage.severity).toBe("high");
    expect(partialCoverage.evidenceClass).toBe("missing");
    expect(partialCoverage.summary).toContain("1 endpoint patterns were skipped and 1 collection errors");
  });

  it("does not raise a coverage finding when nothing was skipped and no error occurred", () => {
    const clean = snapshot([node({ kind: "application", label: "A", ownerIds: ["o"] })], [], {
      completion: { status: "complete", collectedEndpoints: ["/applications"], skippedEndpoints: [], errors: [] },
    });
    expect(findingByCategory(clean, "coverage")).toBeUndefined();
  });

  it("tallies severity and evidence counts to match the finding list", () => {
    const person = node({ kind: "user", label: "Maya" });
    const app = node({ kind: "servicePrincipal", label: "App", metadata: { ownershipExpected: true }, ownerIds: [] });
    const graph = node({ kind: "servicePrincipal", label: "Graph" });
    const snap = snapshot([person, app, graph], [
      edge("OWNS", person, app),
      edge("CAN_CALL_AS_APP", app, graph, { permissions: ["Directory.ReadWrite.All"] }),
    ]);
    const intelligence = analyzeTenantIntelligence(snap);
    const summed = intelligence.counts.critical + intelligence.counts.high + intelligence.counts.medium + intelligence.counts.low;
    expect(summed).toBe(intelligence.findings.length);
    const evidenceSummed = intelligence.evidence.configured + intelligence.evidence.inferred + intelligence.evidence.observed + intelligence.evidence.missing;
    expect(evidenceSummed).toBe(intelligence.findings.length);
    expect(intelligence.generatedAt).toBe(snap.scannedAt);
  });
});

describe("permission lists with more than one entry", () => {
  const caller = () => node({ id: "sp-caller", kind: "servicePrincipal", label: "Caller", metadata: { ownershipExpected: true }, ownerIds: [] });
  const resource = () => node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });

  function analyze(type: "CAN_CALL_AS_APP" | "CAN_CALL_DELEGATED", permissions: string[]) {
    const c = caller();
    const r = resource();
    return analyzeTenantIntelligence(snapshot([c, r], [edge(type, c, r, { id: "edge-1", permissions })]));
  }

  it("rates a mixed application grant by its most powerful permission", () => {
    // One escalation among ordinary reads still makes the grant critical.
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Directory.ReadWrite.All"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("critical");
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Mail.ReadWrite"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("high");
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Directory.Read.All"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("high");
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Api.Read"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("medium");
  });

  it("rates a mixed delegated grant by its most powerful permission", () => {
    expect(analyze("CAN_CALL_DELEGATED", ["User.Read", "Mail.ReadWrite"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("high");
    expect(analyze("CAN_CALL_DELEGATED", ["User.Read", "Api.Read"]).findings.find((f) => f.category === "oauth-consent")?.severity).toBe("medium");
  });

  it("walks a path from a mixed permission list by its most powerful permission", () => {
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Directory.ReadWrite.All"]).paths[0]?.severity).toBe("critical");
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Mail.ReadWrite"]).paths[0]?.severity).toBe("high");
    expect(analyze("CAN_CALL_AS_APP", ["User.Read", "Directory.Read.All"]).paths[0]?.severity).toBe("medium");
    expect(analyze("CAN_CALL_DELEGATED", ["User.Read", "Directory.ReadWrite.All"]).paths[0]?.severity).toBe("high");
  });

  it("lists every permission it saw in the summary and in the mitigation", () => {
    const result = analyze("CAN_CALL_AS_APP", ["Directory.ReadWrite.All", "Mail.Read"]);
    expect(result.findings.find((f) => f.category === "oauth-consent")?.summary).toContain("Directory.ReadWrite.All, Mail.Read");
    expect(result.paths[0]?.mitigations[0]).toContain("Directory.ReadWrite.All, Mail.Read");
  });

  it("says configured access when a walked relationship names no permission", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const role = node({ id: "role-1", kind: "directoryRole", label: "Global Administrator" });
    const result = analyzeTenantIntelligence(snapshot([person, role], [edge("ACTIVE_IN_ROLE", person, role)]));
    expect(result.paths[0]?.mitigations[0]).toContain("configured access");
  });

  it("raises no path from a relationship type that carries no reachable access", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const app = node({ id: "app-1", kind: "application", label: "App", ownerIds: ["user-1"] });
    // OWNS is traversable but is not itself an access grant, whatever permissions it names.
    const owns = snapshot([person, app], [edge("OWNS", person, app, { permissions: ["Directory.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(owns).paths).toEqual([]);
  });
});

describe("path narration", () => {
  const person = () => node({ id: "user-1", kind: "user", label: "Avery" });
  // Owned, so the walk starts at the person rather than at the workload identity itself.
  const worker = () => node({ id: "sp-1", kind: "servicePrincipal", label: "Orchestrator", metadata: { ownershipExpected: true }, ownerIds: ["user-1"] });
  const api = () => node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });

  it("explains an application call, a delegated call, and any other step differently", () => {
    const start = person();
    const middle = worker();
    const target = api();
    const appPath = analyzeTenantIntelligence(snapshot([start, middle, target], [
      edge("OWNS", start, middle, { plainLabel: "Owns" }),
      edge("CAN_CALL_AS_APP", middle, target, { permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(appPath.steps.map((step) => step.explanation)).toEqual([
      "Avery owns Orchestrator.",
      "Orchestrator is configured to call Microsoft Graph as the application.",
    ]);
    const delegatedPath = analyzeTenantIntelligence(snapshot([start, target], [
      edge("CAN_CALL_DELEGATED", start, target, { permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(delegatedPath.steps[0]?.explanation).toBe("Avery is configured to call Microsoft Graph for a signed-in person.");
  });

  it("lowercases the plain label of a step that is neither kind of call", () => {
    const start = person();
    const middle = worker();
    const target = api();
    const path = analyzeTenantIntelligence(snapshot([start, middle, target], [
      edge("OWNS", start, middle, { plainLabel: "OWNS AND CONTROLS" }),
      edge("CAN_CALL_AS_APP", middle, target, { permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(path.steps[0]?.explanation).toBe("Avery owns and controls Orchestrator.");
  });

  it("names both ends of every step by id and label", () => {
    const start = person();
    const target = api();
    const path = analyzeTenantIntelligence(snapshot([start, target], [
      edge("CAN_CALL_DELEGATED", start, target, { id: "edge-1", permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(path.steps[0]).toMatchObject({
      index: 0, edgeId: "edge-1",
      source: { id: "user-1", label: "Avery" },
      target: { id: "sp-api", label: "Microsoft Graph" },
      relationship: "CAN_CALL_DELEGATED", evidenceClass: "configured",
    });
  });

  it("never walks back through the identity it started from", () => {
    const start = person();
    const middle = worker();
    // The only powerful relationship points back at the origin, so there is nothing to report:
    // reaching yourself is not an escalation.
    const cycle = analyzeTenantIntelligence(snapshot([start, middle], [
      edge("OWNS", start, middle, { id: "edge-owns" }),
      edge("CAN_CALL_AS_APP", middle, start, { id: "edge-back", permissions: ["Directory.ReadWrite.All"] }),
    ]));
    expect(cycle.paths).toEqual([]);
    // The same shape, but ending somewhere else, is reported in full.
    const target = api();
    const onward = analyzeTenantIntelligence(snapshot([start, middle, target], [
      edge("OWNS", start, middle, { id: "edge-owns" }),
      edge("CAN_CALL_AS_APP", middle, target, { id: "edge-onward", permissions: ["Directory.ReadWrite.All"] }),
    ]));
    expect(onward.paths.map((item) => item.steps.map((step) => step.edgeId))).toEqual([["edge-owns", "edge-onward"]]);
  });

  it("orders a more severe path first even when the titles would sort the other way", () => {
    const early = node({ id: "user-a", kind: "user", label: "Avery" });
    const late = node({ id: "user-z", kind: "user", label: "Zed" });
    const api1 = node({ id: "sp-1", kind: "servicePrincipal", label: "Alpha API" });
    const api2 = node({ id: "sp-2", kind: "servicePrincipal", label: "Zulu API" });
    const result = analyzeTenantIntelligence(snapshot([early, late, api1, api2], [
      edge("CAN_CALL_DELEGATED", early, api1, { permissions: ["Mail.ReadWrite"] }),
      edge("CAN_CALL_AS_APP", late, api2, { permissions: ["Directory.ReadWrite.All"] }),
    ]));
    expect(result.paths.map((path) => path.severity)).toEqual(["critical", "medium"]);
    expect(result.paths.map((path) => path.title)).toEqual([
      "Zed can reach Zulu API",
      "Avery can reach Alpha API",
    ]);
  });
});

describe("dormant access coverage window", () => {
  const caller = () => node({ id: "sp-1", kind: "servicePrincipal", label: "Caller", metadata: { ownershipExpected: true }, ownerIds: ["o"] });
  const api = () => node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });

  function withCollected(collectedEndpoints: string[]) {
    const c = caller();
    const r = api();
    return analyzeTenantIntelligence(snapshot([c, r], [edge("CAN_CALL_AS_APP", c, r, { id: "edge-1", permissions: ["Api.Read"] })], {
      completion: { status: "complete", collectedEndpoints, skippedEndpoints: [], errors: [] },
    }));
  }

  it("recognises the sign-in window by the start of the endpoint, query string and all", () => {
    const withQuery = withCollected(["/applications", "/auditLogs/signIns?$top=250&$filter=createdDateTime%20ge%202026-07-27"]);
    const dormant = withQuery.findings.find((finding) => finding.category === "dormant-access")!;
    expect(dormant.sourceEndpoints).toEqual(["/test-endpoint", "/auditLogs/signIns?$top=250&$filter=createdDateTime%20ge%202026-07-27"]);
  });

  it("does not read an endpoint that merely ends with the sign-in path as activity coverage", () => {
    expect(withCollected(["/applications", "/beta/auditLogs/signIns"]).findings.some((finding) => finding.category === "dormant-access")).toBe(false);
  });

  it("flags a delegated grant as dormant as readily as an application one", () => {
    const c = caller();
    const r = api();
    const result = analyzeTenantIntelligence(snapshot([c, r], [edge("CAN_CALL_DELEGATED", c, r, { id: "edge-1", permissions: ["Mail.Read"] })], {
      completion: { status: "complete", collectedEndpoints: ["/auditLogs/signIns"], skippedEndpoints: [], errors: [] },
    }));
    expect(result.findings.find((finding) => finding.category === "dormant-access")?.edgeIds).toEqual(["edge-1"]);
  });

  it("does not call a relationship dormant when it is neither kind of call", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const app = node({ id: "app-1", kind: "application", label: "App", ownerIds: ["user-1"] });
    const result = analyzeTenantIntelligence(snapshot([person, app], [edge("OWNS", person, app)], {
      completion: { status: "complete", collectedEndpoints: ["/auditLogs/signIns"], skippedEndpoints: [], errors: [] },
    }));
    expect(result.findings.some((finding) => finding.category === "dormant-access")).toBe(false);
  });
});

describe("finding wording that carries meaning", () => {
  it("states both prerequisites of every inferred path", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const api = node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });
    const path = analyzeTenantIntelligence(snapshot([person, api], [
      edge("CAN_CALL_DELEGATED", person, api, { permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(path.prerequisites).toEqual([
      "An attacker first controls Avery or a session/credential able to act as it.",
      "Every configured relationship shown in the path remains effective at the time of attempted use.",
    ]);
  });

  it("lists every delegated permission in the consent summary", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const api = node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });
    const finding = analyzeTenantIntelligence(snapshot([person, api], [
      edge("CAN_CALL_DELEGATED", person, api, { permissions: ["Mail.Read", "User.Read"] }),
    ])).findings.find((item) => item.category === "oauth-consent")!;
    expect(finding.summary).toBe("Configured delegated access: Mail.Read, User.Read.");
  });

  it("caveats an ownership finding only when the snapshot itself was partial", () => {
    const orphan = node({ id: "app-1", kind: "application", label: "Orphan", ownerIds: [] });
    const complete = analyzeTenantIntelligence(snapshot([orphan], [])).findings.find((item) => item.category === "ownership")!;
    expect(complete.uncertainty).toEqual([]);
    const partial = analyzeTenantIntelligence(snapshot([orphan], [], {
      completion: { status: "partial", collectedEndpoints: ["/applications"], skippedEndpoints: ["/servicePrincipals"], errors: [] },
    })).findings.find((item) => item.category === "ownership")!;
    expect(partial.uncertainty).toEqual(["Owner collection may be incomplete in this partial snapshot."]);
  });

  it("rates a managed identity by the risk the snapshot recorded for it", () => {
    const high = node({ id: "mi-1", kind: "managedIdentity", label: "Broad MI", risk: { level: "high", reason: "Broad access." } });
    const review = node({ id: "mi-2", kind: "managedIdentity", label: "Quiet MI", risk: { level: "review", reason: "Worth a look." } });
    const low = node({ id: "mi-3", kind: "managedIdentity", label: "Calm MI", risk: { level: "low", reason: "Nothing notable." } });
    const severities = analyzeTenantIntelligence(snapshot([high, review, low], [])).findings
      .filter((finding) => finding.category === "managed-identity")
      .map((finding) => finding.severity);
    expect(severities).toEqual(["high", "medium", "medium"]);
  });

  it("raises a Conditional Access finding only for a policy object", () => {
    const impostor = node({ id: "sp-1", kind: "servicePrincipal", label: "Not a policy", metadata: { policyType: "conditionalAccess", state: "disabled" } });
    const categories = analyzeTenantIntelligence(snapshot([impostor], [])).findings.map((finding) => finding.category);
    expect(categories).not.toContain("conditional-access");
  });
});
