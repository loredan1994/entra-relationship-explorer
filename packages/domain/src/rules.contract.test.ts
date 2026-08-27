import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, analyzeTenantIntelligenceHistory } from "./intelligence";
import { ENTRA_CONTROL_PATH_RULES } from "./rules";
import { edge, node, snapshot, TENANT } from "./test-support";
import type { TenantSnapshot } from "./types";

function ownedApplicationPath(permission = "RoleManagement.ReadWrite.Directory", scannedAt = "2026-08-27T10:00:00.000Z"): TenantSnapshot {
  const person = node({ id: "user-owner", kind: "user", label: "Maya" });
  const workload = node({ id: "sp-automation", kind: "servicePrincipal", label: "Automation", ownerIds: [person.id], metadata: { ownershipExpected: true } });
  const graph = node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
  return snapshot([person, workload, graph], [
    edge("OWNS", person, workload, { id: "owner-edge", evidence: { sourceEndpoint: "/servicePrincipals/sp-automation/owners" } }),
    edge("CAN_CALL_AS_APP", workload, graph, { id: "grant-edge", permissions: [permission], evidence: { sourceEndpoint: "/servicePrincipals/sp-graph/appRoleAssignedTo" } }),
  ], { id: `snapshot-${scannedAt.slice(8, 10)}`, scannedAt });
}

function federatedPath(issuer: string, scannedAt: string): TenantSnapshot {
  const credential = node({ id: "federated-credential:app-1:fic-1", kind: "federatedCredential", label: "GitHub main", metadata: { credentialId: "fic-1", parentId: "app-1", parentType: "application", issuer, subject: "repo:example/project:ref:refs/heads/main", audiences: "api://AzureADTokenExchange" } });
  const application = node({ id: "app-1", kind: "application", label: "Release app", ownerIds: ["owner"] });
  const workload = node({ id: "sp-1", kind: "servicePrincipal", label: "Release workload", ownerIds: ["owner"], metadata: { ownershipExpected: true } });
  const graph = node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
  return snapshot([credential, application, workload, graph], [
    edge("FEDERATES_AS", credential, application, { id: "federates", evidence: { sourceEndpoint: "/applications/app-1/federatedIdentityCredentials" } }),
    edge("INSTANTIATES_AS", application, workload, { id: "instantiates", evidence: { sourceEndpoint: "/servicePrincipals" } }),
    edge("CAN_CALL_AS_APP", workload, graph, { id: "grant", permissions: ["Application.ReadWrite.All"], evidence: { sourceEndpoint: "/servicePrincipals/sp-graph/appRoleAssignedTo" } }),
  ], { id: `snapshot-${scannedAt.slice(8, 10)}`, scannedAt });
}

function scopedRolePath(directoryScopeId: string, scannedAt: string): TenantSnapshot {
  const person = node({ id: "scoped-admin", kind: "user", label: "Scoped admin" });
  const role = node({ id: "user-admin-role", kind: "directoryRole", label: "User Administrator" });
  const assignment = edge("ACTIVE_IN_ROLE", person, role, { id: "scoped-role-edge", permissions: [directoryScopeId] });
  return snapshot([person, role], [{ ...assignment, scope: { directoryScopeId, objectId: directoryScopeId === "/" ? null : "au-finance" } }], { id: `snapshot-${scannedAt.slice(8, 10)}`, scannedAt });
}

function expectNoRule(intelligence: ReturnType<typeof analyzeTenantIntelligence>, ruleId: string): void {
  expect(intelligence.findings.every((finding) => typeof finding === "object" && typeof finding.id === "string")).toBe(true);
  expect(intelligence.findings.some((finding) => finding.rule?.id === ruleId)).toBe(false);
}

describe("Entra Control Path Rules catalog", () => {
  it("publishes four unique, versioned, repository-trusted rules with evidence and references", () => {
    expect(ENTRA_CONTROL_PATH_RULES.map((rule) => ({ ...rule.reference, scope: rule.scope }))).toEqual([
      { id: "ERE-IAM-001", version: 1, title: "Privileged application control path", scope: "snapshot", requiredCoverage: ["application ownership or workload federation", "application identity instantiation", "application permission or Entra role assignment"], references: ["https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview", "https://attack.mitre.org/techniques/T1098/"] },
      { id: "ERE-IAM-002", version: 1, title: "Privilege path amplification", scope: "history", requiredCoverage: ["the same relationship path in consecutive snapshots", "unchanged tenant boundary", "complete evidence for every compared path step"], references: ["https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices"] },
      { id: "ERE-IAM-003", version: 1, title: "Privileged federated trust rewired", scope: "history", requiredCoverage: ["federated identity credentials in consecutive snapshots", "the parent workload's effective privileged path"], references: ["https://learn.microsoft.com/en-us/graph/api/application-list-federatedidentitycredentials?view=graph-rest-1.0", "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"] },
      { id: "ERE-IAM-004", version: 1, title: "Privileged workload lacks accountable control", scope: "snapshot", requiredCoverage: ["application or service-principal owners", "the workload's effective application permissions and Entra roles"], references: ["https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems"] },
    ]);
    expect(new Set(ENTRA_CONTROL_PATH_RULES.map((rule) => rule.reference.id)).size).toBe(4);
    for (const rule of ENTRA_CONTROL_PATH_RULES) {
      expect(rule.reference.version).toBe(1);
      expect(rule.reference.requiredCoverage.length).toBeGreaterThan(0);
      expect(rule.reference.references.every((reference) => reference.startsWith("https://"))).toBe(true);
    }
  });
});

describe("ERE-IAM-001 privileged application control path", () => {
  it("replaces the generic path finding with a focused, evidence-backed rule result", () => {
    const intelligence = analyzeTenantIntelligence(ownedApplicationPath());
    const path = intelligence.paths.find((item) => item.source.id === "user-owner")!;
    const focused = intelligence.findings.find((finding) => finding.rule?.id === "ERE-IAM-001")!;
    expect(focused).toMatchObject({ severity: "critical", evidenceClass: "inferred", attackPathId: path.id, edgeIds: ["owner-edge", "grant-edge"] });
    expect(focused.title).toContain("Automation");
    expect(focused.prerequisites?.[0]).toContain("Maya");
    expect(focused.requiredCoverage).toEqual(ENTRA_CONTROL_PATH_RULES[0]!.reference.requiredCoverage);
    expect(intelligence.findings.filter((finding) => finding.attackPathId === path.id)).toHaveLength(1);
    expect(intelligence.findings.some((finding) => finding.rule?.id === "ERE-IAM-004")).toBe(false);
  });

  it("does not relabel an ordinary direct role assignment as application control", () => {
    const person = node({ id: "person", kind: "user", label: "Admin" });
    const role = node({ id: "role", kind: "directoryRole", label: "Global Administrator" });
    const intelligence = analyzeTenantIntelligence(snapshot([person, role], [edge("ACTIVE_IN_ROLE", person, role, { id: "role-edge" })]));
    expect(intelligence.findings.some((finding) => finding.rule?.id === "ERE-IAM-001")).toBe(false);
    expect(intelligence.findings.some((finding) => finding.attackPathId === intelligence.paths[0]?.id)).toBe(true);
  });

  it("covers high-severity federation and rejects non-control and medium paths", () => {
    const federated = analyzeTenantIntelligence(federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z")).findings.find((finding) => finding.rule?.id === "ERE-IAM-001")!;
    expect(federated.category).toBe("federated-identity");
    expect(federated.title).toBe("GitHub main can control privileged access through Release app");
    const medium = ownedApplicationPath("Directory.Read.All");
    expect(analyzeTenantIntelligence(medium).findings.some((finding) => finding.rule?.id === "ERE-IAM-001")).toBe(false);
  });

  it("recognizes active and eligible Entra roles reached through application control", () => {
    const owner = node({ id: "owner", kind: "user", label: "Owner" });
    const application = node({ id: "app", kind: "application", label: "Admin registration" });
    const workload = node({ id: "sp", kind: "servicePrincipal", label: "Admin workload" });
    const role = node({ id: "role", kind: "directoryRole", label: "Global Administrator" });
    for (const relationship of ["ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as const) {
      const current = snapshot([owner, application, workload, role], [edge("OWNS", owner, application), edge("INSTANTIATES_AS", application, workload), edge(relationship, workload, role)]);
      const finding = analyzeTenantIntelligence(current).findings.find((item) => item.rule?.id === "ERE-IAM-001")!;
      expect(finding.title).toBe("Owner can control privileged access through Admin registration");
      expect(finding.severity).toBe(relationship === "ACTIVE_IN_ROLE" ? "critical" : "high");
    }
  });

  it("recognizes a privileged managed identity reached through federation", () => {
    const credential = node({ id: "federated-credential:mi:fic", kind: "federatedCredential", label: "Deployment trust" });
    const managed = node({ id: "mi", kind: "managedIdentity", label: "Deployment identity", ownerIds: ["owner"] });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const current = snapshot([credential, managed, graph], [edge("FEDERATES_AS", credential, managed), edge("CAN_CALL_AS_APP", managed, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(current).findings.find((item) => item.rule?.id === "ERE-IAM-001")!.title).toBe("Deployment trust can control privileged access through Deployment identity");
  });

  it("selects the actual control step and excludes powerful delegated terminal access", () => {
    const person = node({ id: "person", kind: "user", label: "Person" });
    const group = node({ id: "group", kind: "group", label: "Operators" });
    const application = node({ id: "app", kind: "application", label: "Controlled app" });
    const workload = node({ id: "sp", kind: "servicePrincipal", label: "Controlled workload" });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const baseEdges = [edge("MEMBER_OF", person, group), edge("OWNS", group, application), edge("INSTANTIATES_AS", application, workload)];
    const applicationAccess = snapshot([person, group, application, workload, graph], [...baseEdges, edge("CAN_CALL_AS_APP", workload, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(applicationAccess).findings.find((item) => item.rule?.id === "ERE-IAM-001" && item.title.startsWith("Person "))!.title).toBe("Person can control privileged access through Controlled app");
    const delegatedAccess = snapshot([person, group, application, workload, graph], [...baseEdges, edge("CAN_CALL_DELEGATED", workload, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expectNoRule(analyzeTenantIntelligence(delegatedAccess), "ERE-IAM-001");
    const assigned = snapshot([person, workload, graph], [edge("ASSIGNED_TO", person, workload), edge("CAN_CALL_AS_APP", workload, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expectNoRule(analyzeTenantIntelligence(assigned), "ERE-IAM-001");
    const policy = node({ id: "policy", kind: "policy", label: "Policy" });
    const indirect = snapshot([person, policy, application, workload, graph], [edge("OWNS", person, policy), edge("OWNS", policy, application), edge("INSTANTIATES_AS", application, workload), edge("CAN_CALL_AS_APP", workload, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(indirect).findings.find((item) => item.rule?.id === "ERE-IAM-001")!.title).toBe("Person can control privileged access through Controlled app");
  });
});

describe("ERE-IAM-002 privilege path amplification", () => {
  it("reports an existing path whose terminal permission becomes more powerful", () => {
    const before = ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z");
    const current = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(finding.summary).toContain("severity increased from medium to high");
    expect(finding.summary).toContain("terminal permissions added: Mail.ReadWrite");
    expect(finding.summary).toContain("snapshot-26");
    expect(finding.uncertainty[0]).toMatch(/configured change.*not.*exercised/i);
  });

  it("does not call an unchanged path amplified", () => {
    const before = ownedApplicationPath("Mail.ReadWrite", "2026-08-26T10:00:00.000Z");
    const current = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    expectNoRule(analyzeTenantIntelligenceHistory([current, before]), "ERE-IAM-002");
  });

  it("preserves partial-snapshot uncertainty when reporting amplification", () => {
    const before = ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z");
    const base = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    const current = { ...base, completion: { ...base.completion, status: "partial" as const, errors: ["permission endpoint incomplete"] } };
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(finding.uncertainty).toContain("The latest snapshot is partial, so other path changes may be missing.");
  });

  it("detects a stable role edge whose raw scope expands to the tenant root", () => {
    const before = scopedRolePath("/administrativeUnits/au-finance", "2026-08-26T10:00:00.000Z");
    const current = scopedRolePath("/", "2026-08-27T10:00:00.000Z");
    expect(analyzeTenantIntelligence(before).paths[0]!.steps[0]!.scope).toEqual({ directoryScopeId: "/administrativeUnits/au-finance", objectId: "au-finance" });
    expect(analyzeTenantIntelligence(current).paths[0]!.steps[0]!.scope).toEqual({ directoryScopeId: "/", objectId: null });
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(finding.summary).toBe("terminal permissions added: /; directory scope expanded to the tenant root. This is a change between snapshot-26 and snapshot-27.");
    expect(finding.edgeIds).toEqual(["scoped-role-edge"]);
  });

  it("does not compare a current path that was absent from the prior snapshot", () => {
    const current = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    const before = snapshot([], [], { id: "snapshot-26", scannedAt: "2026-08-26T10:00:00.000Z" });
    expectNoRule(analyzeTenantIntelligenceHistory([current, before]), "ERE-IAM-002");
  });

  it("classifies amplified federated paths as federated identity findings", () => {
    const before = federatedPath("https://issuer.example", "2026-08-26T10:00:00.000Z");
    const currentBase = federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z");
    const beforeMedium = { ...before, edges: before.edges.map((item) => item.id === "grant" ? { ...item, permissions: ["Directory.Read.All"] } : item) };
    const finding = analyzeTenantIntelligenceHistory([currentBase, beforeMedium]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(finding.category).toBe("federated-identity");
  });

  it("sorts multiple added terminal permissions deterministically", () => {
    const before = ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z");
    const currentBase = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    const current = { ...currentBase, edges: currentBase.edges.map((item) => item.id === "grant-edge" ? { ...item, permissions: ["User.ReadWrite.All", "Mail.ReadWrite"] } : item) };
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(finding.summary).toContain("terminal permissions added: Mail.ReadWrite, User.ReadWrite.All");
  });

  it("does not describe unchanged or non-root scope as tenant-wide expansion", () => {
    const beforeRoot = scopedRolePath("/", "2026-08-26T10:00:00.000Z");
    const currentRootBase = scopedRolePath("/", "2026-08-27T10:00:00.000Z");
    const currentRoot = { ...currentRootBase, edges: currentRootBase.edges.map((item) => ({ ...item, permissions: ["new"] })) };
    const rootFinding = analyzeTenantIntelligenceHistory([currentRoot, { ...beforeRoot, edges: beforeRoot.edges.map((item) => ({ ...item, permissions: ["old"] })) }]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(rootFinding.summary).not.toContain("tenant root");
    const beforeScoped = scopedRolePath("/administrativeUnits/finance", "2026-08-26T10:00:00.000Z");
    const currentScopedBase = scopedRolePath("/administrativeUnits/hr", "2026-08-27T10:00:00.000Z");
    const currentScoped = { ...currentScopedBase, edges: currentScopedBase.edges.map((item) => ({ ...item, permissions: ["new"] })) };
    const scopedFinding = analyzeTenantIntelligenceHistory([currentScoped, { ...beforeScoped, edges: beforeScoped.edges.map((item) => ({ ...item, permissions: ["old"] })) }]).findings.find((item) => item.rule?.id === "ERE-IAM-002")!;
    expect(scopedFinding.summary).not.toContain("tenant root");
  });

  it("detects root expansion on the final step of a multi-step path", () => {
    const person = node({ id: "person-scope", kind: "user", label: "Person" });
    const group = node({ id: "group-scope", kind: "group", label: "Operators" });
    const role = node({ id: "role-scope", kind: "directoryRole", label: "User Administrator" });
    const make = (scope: string, scannedAt: string) => {
      const membership = edge("MEMBER_OF", person, group, { id: "membership" });
      const assignment = edge("ACTIVE_IN_ROLE", group, role, { id: "assignment", permissions: [scope] });
      return snapshot([person, group, role], [membership, { ...assignment, scope: { directoryScopeId: scope, objectId: scope === "/" ? null : "au-finance" } }], { id: `snapshot-${scannedAt.slice(8, 10)}`, scannedAt });
    };
    const findings = analyzeTenantIntelligenceHistory([make("/", "2026-08-27T10:00:00.000Z"), make("/administrativeUnits/au-finance", "2026-08-26T10:00:00.000Z")]).findings.filter((item) => item.rule?.id === "ERE-IAM-002");
    expect(findings.some((finding) => finding.summary.includes("directory scope expanded to the tenant root") && finding.edgeIds.length === 2)).toBe(true);
  });
});

describe("ERE-IAM-003 privileged federation trust rewired", () => {
  it("reports changed trust metadata only when the credential reaches powerful access", () => {
    const before = federatedPath("https://token.actions.githubusercontent.com", "2026-08-26T10:00:00.000Z");
    const current = federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z");
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-003")!;
    expect(finding).toMatchObject({ severity: "critical", evidenceClass: "inferred", affectedObjectIds: expect.arrayContaining(["federated-credential:app-1:fic-1", "sp-graph"]) });
    expect(finding.summary).toContain("issuer changed");
    expect(finding.uncertainty.join(" ")).toMatch(/does not prove.*token/i);
  });

  it("does not report an unchanged trust", () => {
    const before = federatedPath("https://issuer.example", "2026-08-26T10:00:00.000Z");
    const current = federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z");
    expect(analyzeTenantIntelligenceHistory([current, before]).findings.some((item) => item.rule?.id === "ERE-IAM-003")).toBe(false);
  });

  it("states that related trust evidence may be missing in a partial snapshot", () => {
    const before = federatedPath("https://token.actions.githubusercontent.com", "2026-08-26T10:00:00.000Z");
    const base = federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z");
    const current = { ...base, completion: { ...base.completion, status: "partial" as const, errors: ["federation endpoint incomplete"] } };
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-003")!;
    expect(finding.uncertainty).toContain("The latest snapshot is partial, so related trust evidence may be missing.");
  });

  it("requires the same credential node and a currently powerful path", () => {
    const before = federatedPath("https://old.example", "2026-08-26T10:00:00.000Z");
    const current = federatedPath("https://new.example", "2026-08-27T10:00:00.000Z");
    expectNoRule(analyzeTenantIntelligenceHistory([{ ...current, nodes: current.nodes.filter((item) => item.kind !== "federatedCredential") }, before]), "ERE-IAM-003");
    const wrongKind = { ...before, nodes: before.nodes.map((item) => item.kind === "federatedCredential" ? { ...item, kind: "user" as const } : item) };
    expectNoRule(analyzeTenantIntelligenceHistory([current, wrongKind]), "ERE-IAM-003");
    const lowCurrent = { ...current, edges: current.edges.map((item) => item.id === "grant" ? { ...item, permissions: ["User.Read"] } : item) };
    expectNoRule(analyzeTenantIntelligenceHistory([lowCurrent, before]), "ERE-IAM-003");
  });

  it("binds a rewired credential to its own path when another powerful path ranks first", () => {
    const before = federatedPath("https://old.example", "2026-08-26T10:00:00.000Z");
    const currentBase = federatedPath("https://new.example", "2026-08-27T10:00:00.000Z");
    const admin = node({ id: "admin", kind: "user", label: "Admin" });
    const role = node({ id: "role", kind: "directoryRole", label: "Global Administrator" });
    const current = { ...currentBase, nodes: [admin, role, ...currentBase.nodes], edges: [edge("ACTIVE_IN_ROLE", admin, role, { id: "admin-role" }), ...currentBase.edges] };
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-003")!;
    expect(finding.attackPathId).toBe("path-e91c50d9");
    expect(finding.affectedObjectIds).not.toContain("admin");
  });

  it("handles a federated node with absent metadata conservatively", () => {
    const before = federatedPath("https://old.example", "2026-08-26T10:00:00.000Z");
    const currentBase = federatedPath("https://new.example", "2026-08-27T10:00:00.000Z");
    const current = { ...currentBase, nodes: currentBase.nodes.map((item) => item.kind === "federatedCredential" ? { ...item, metadata: undefined } : item) };
    const finding = analyzeTenantIntelligenceHistory([current, before]).findings.find((item) => item.rule?.id === "ERE-IAM-003")!;
    expect(finding.summary).toContain("issuer, subject, audiences, parentId changed");
  });

  it("fingerprints every trust selector field, including a previously absent value", () => {
    const before = federatedPath("https://old.example", "2026-08-26T10:00:00.000Z");
    const currentBase = federatedPath("https://new.example", "2026-08-27T10:00:00.000Z");
    const beforeWithoutSelectors = { ...before, nodes: before.nodes.map((item) => item.kind === "federatedCredential" ? { ...item, metadata: { credentialId: "fic-1" } } : item) };
    const current = { ...currentBase, nodes: currentBase.nodes.map((item) => item.kind === "federatedCredential" ? { ...item, metadata: { ...item.metadata, subject: "repo:new", audiences: "api://new", parentId: "app-2" } } : item) };
    const finding = analyzeTenantIntelligenceHistory([current, beforeWithoutSelectors]).findings.find((item) => item.rule?.id === "ERE-IAM-003")!;
    expect(finding.summary).toBe("issuer, subject, audiences, parentId changed while this credential can reach Microsoft Graph.");
    expect(finding.id).toBe("finding-ere-iam-003-39a74861");
  });
});

describe("ERE-IAM-004 privileged workload lacks accountable control", () => {
  it("combines the ownership gap and powerful path without leaving a duplicate generic owner finding", () => {
    const workload = node({ id: "sp-unowned", kind: "servicePrincipal", label: "Unowned automation", ownerIds: [], metadata: { ownershipExpected: true } });
    const graph = node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const current = snapshot([workload, graph], [edge("CAN_CALL_AS_APP", workload, graph, { id: "grant", permissions: ["Application.ReadWrite.All"] })]);
    const ownership = analyzeTenantIntelligence(current).findings.filter((finding) => finding.category === "ownership");
    expect(ownership).toHaveLength(1);
    expect(ownership[0]).toEqual({
      id: "finding-ere-iam-004-7bc64b40", title: "Unowned automation has powerful access without a recorded owner", category: "ownership", severity: "critical", evidenceClass: "inferred", summary: "No accountable owner was collected for this workload, and its configured path reaches Microsoft Graph.", whyItMatters: "A powerful workload without an accountable owner is harder to validate, retire, and contain when its credential, federation, or hosting environment is compromised.", remediation: ["Assign current business and technical owners and confirm the workload is still required.", "Review and remove unnecessary permissions, roles, credentials, and federation through the approved Entra change process."], affectedObjectIds: ["sp-unowned", "sp-graph"], edgeIds: ["grant"], attackPathId: "path-b155676d", sourceEndpoints: ["/servicePrincipals/sp-unowned/owners", "/test-endpoint"], uncertainty: ["No recorded owner is an accountability gap, not proof that the workload is abandoned or compromised."], prerequisites: ["An attacker first controls Unowned automation or a session/credential able to act as it.", "Every configured relationship shown in the path remains effective at the time of attempted use."], rule: ENTRA_CONTROL_PATH_RULES[3]!.reference, requiredCoverage: ENTRA_CONTROL_PATH_RULES[3]!.reference.requiredCoverage,
    });
  });

  it("keeps an ordinary unowned application on the existing hygiene finding", () => {
    const application = node({ id: "app", kind: "application", label: "No access app", ownerIds: [] });
    const ownership = analyzeTenantIntelligence(snapshot([application], [])).findings.find((finding) => finding.category === "ownership")!;
    expect(ownership.rule).toBeUndefined();
    expect(ownership.severity).toBe("medium");
  });

  it("attributes an unowned enterprise workload to its application registration and preserves instantiation evidence", () => {
    const application = node({ id: "app-unowned", kind: "application", label: "Release registration", ownerIds: [] });
    const workload = node({ id: "sp-release", kind: "servicePrincipal", label: "Release workload", ownerIds: ["enterprise-app-owner"] });
    const graph = node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const decoyApplication = node({ id: "app-decoy", kind: "application", label: "Decoy registration", ownerIds: ["owner"] });
    const decoyWorkload = node({ id: "sp-decoy", kind: "servicePrincipal", label: "Decoy workload", ownerIds: ["owner"] });
    const current = snapshot([application, workload, graph, decoyApplication, decoyWorkload], [
      edge("INSTANTIATES_AS", decoyApplication, decoyWorkload, { id: "decoy-unrelated" }),
      edge("INSTANTIATES_AS", application, decoyWorkload, { id: "decoy-source" }),
      edge("ASSIGNED_TO", application, workload, { id: "decoy-wrong-type", evidence: { sourceEndpoint: "/wrong-type" } }),
      edge("INSTANTIATES_AS", application, workload, { id: "instance-edge", evidence: { sourceEndpoint: "/servicePrincipals" } }),
      edge("CAN_CALL_AS_APP", workload, graph, { id: "grant-edge", permissions: ["Application.ReadWrite.All"], evidence: { sourceEndpoint: "/servicePrincipals/sp-graph/appRoleAssignedTo" } }),
    ]);
    const finding = analyzeTenantIntelligence(current).findings.find((item) => item.rule?.id === "ERE-IAM-004")!;
    expect(finding.title).toBe("Release registration has powerful access without a recorded owner");
    expect(finding.affectedObjectIds).toEqual(["app-unowned", "sp-release", "sp-graph"]);
    expect(finding.edgeIds).toEqual(["instance-edge", "grant-edge"]);
    expect(finding.sourceEndpoints).toEqual(["/applications/app-unowned/owners", "/servicePrincipals", "/servicePrincipals/sp-graph/appRoleAssignedTo"]);
  });

  it("covers managed-identity ownership, partial evidence, non-powerful access, and duplicate paths", () => {
    const managed = node({ id: "mi", kind: "managedIdentity", label: "Build identity", ownerIds: [], metadata: { ownershipExpected: true } });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const exchange = node({ id: "exchange", kind: "servicePrincipal", label: "Exchange" });
    const base = snapshot([managed, graph, exchange], [edge("CAN_CALL_AS_APP", managed, graph, { id: "grant-a", permissions: ["Application.ReadWrite.All"] }), edge("CAN_CALL_AS_APP", managed, exchange, { id: "grant-b", permissions: ["Mail.ReadWrite"] })]);
    const partial = { ...base, completion: { ...base.completion, status: "partial" as const, errors: ["owners incomplete"] } };
    const findings = analyzeTenantIntelligence(partial).findings.filter((item) => item.rule?.id === "ERE-IAM-004");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.sourceEndpoints[0]).toBe("/servicePrincipals/mi/owners");
    expect(findings[0]!.uncertainty).toContain("Owner or privilege evidence may be incomplete in this partial snapshot.");
    const owned = { ...base, nodes: base.nodes.map((item) => item.id === managed.id ? { ...item, ownerIds: ["owner"] } : item) };
    expect(analyzeTenantIntelligence(owned).findings.some((item) => item.rule?.id === "ERE-IAM-004")).toBe(false);
    const medium = { ...base, edges: base.edges.map((item) => ({ ...item, permissions: ["Directory.Read.All"] })) };
    expect(analyzeTenantIntelligence(medium).findings.some((item) => item.rule?.id === "ERE-IAM-004")).toBe(false);
  });

  it("does not assign ownership accountability to a first-party service principal", () => {
    const firstParty = node({ id: "first-party", kind: "servicePrincipal", label: "Microsoft service", ownerIds: [] });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const current = snapshot([firstParty, graph], [edge("CAN_CALL_AS_APP", firstParty, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(current).findings.some((item) => item.rule?.id === "ERE-IAM-004")).toBe(false);
  });

  it("treats only an application connected by INSTANTIATES_AS as an unowned registration", () => {
    const policy = node({ id: "not-an-app", kind: "policy", label: "Not an application", ownerIds: [] });
    const application = node({ id: "unowned-app", kind: "application", label: "Unowned app", ownerIds: [] });
    const workload = node({ id: "owned-sp", kind: "servicePrincipal", label: "Owned workload", ownerIds: ["owner"] });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const grant = edge("CAN_CALL_AS_APP", workload, graph, { permissions: ["Application.ReadWrite.All"] });
    const wrongSourceKind = snapshot([policy, workload, graph], [edge("INSTANTIATES_AS", policy, workload), grant]);
    expect(analyzeTenantIntelligence(wrongSourceKind).paths.some((path) => path.source.id === workload.id)).toBe(false);
    const wrongRelationship = snapshot([application, workload, graph], [edge("ASSIGNED_TO", application, workload), grant]);
    expect(analyzeTenantIntelligence(wrongRelationship).paths.some((path) => path.source.id === workload.id)).toBe(false);
  });

  it("does not hold a managed identity accountable unless ownership is expected", () => {
    const managed = node({ id: "mi-untracked", kind: "managedIdentity", label: "Platform identity", ownerIds: [] });
    const graph = node({ id: "graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const current = snapshot([managed, graph], [edge("CAN_CALL_AS_APP", managed, graph, { permissions: ["Application.ReadWrite.All"] })]);
    expect(analyzeTenantIntelligence(current).findings.some((item) => item.rule?.id === "ERE-IAM-004")).toBe(false);
  });
});

describe("history safety and determinism", () => {
  it("keeps the complete public rule output stable", () => {
    const one = analyzeTenantIntelligence(ownedApplicationPath()).findings.find((item) => item.rule?.id === "ERE-IAM-001");
    const two = analyzeTenantIntelligenceHistory([ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z"), ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z")]).findings.find((item) => item.rule?.id === "ERE-IAM-002");
    const three = analyzeTenantIntelligenceHistory([federatedPath("https://issuer.example", "2026-08-27T10:00:00.000Z"), federatedPath("https://token.actions.githubusercontent.com", "2026-08-26T10:00:00.000Z")]).findings.find((item) => item.rule?.id === "ERE-IAM-003");
    expect({ one, two, three }).toEqual({
      one: {
        id: "finding-ere-iam-001-c3600b51", title: "Maya can control privileged access through Automation", category: "privilege-path", severity: "critical", evidenceClass: "inferred",
        summary: "2-stage configured control path reaches Microsoft Graph.", whyItMatters: "Control of the starting principal could make the application identity's powerful configured access available without granting a new permission first.",
        remediation: ["Review and remove unnecessary RoleManagement.ReadWrite.Directory access to Microsoft Graph.", "Reduce control of Maya and ensure an accountable owner reviews the relationship.", "Re-scan after remediation and verify that the configured path no longer exists."],
        affectedObjectIds: ["user-owner", "sp-automation", "sp-graph"], edgeIds: ["owner-edge", "grant-edge"], attackPathId: "path-a490bdac", sourceEndpoints: ["/servicePrincipals/sp-automation/owners", "/servicePrincipals/sp-graph/appRoleAssignedTo"],
        uncertainty: ["This is an inferred possibility built from configured relationships; it is not evidence that exploitation occurred.", "No activity evidence was collected for the final permission."], prerequisites: ["An attacker first controls Maya or a session/credential able to act as it.", "Every configured relationship shown in the path remains effective at the time of attempted use."],
        rule: ENTRA_CONTROL_PATH_RULES[0]!.reference, requiredCoverage: ENTRA_CONTROL_PATH_RULES[0]!.reference.requiredCoverage,
      },
      two: {
        id: "finding-ere-iam-002-fc1566cb", title: "Privilege increased along Maya → Microsoft Graph", category: "privilege-path", severity: "high", evidenceClass: "inferred",
        summary: "severity increased from medium to high; terminal permissions added: Mail.ReadWrite. This is a change between snapshot-26 and snapshot-27.", whyItMatters: "An existing configured route now ends in broader or more severe access than it did in the immediately preceding retained snapshot.",
        remediation: ["Confirm that the privilege increase was approved and remains necessary.", "Inspect every changed relationship, then remove unintended access through the approved Entra change process."], affectedObjectIds: ["user-owner", "sp-automation", "sp-graph"], edgeIds: ["owner-edge", "grant-edge"], attackPathId: "path-a490bdac", sourceEndpoints: ["/servicePrincipals/sp-automation/owners", "/servicePrincipals/sp-graph/appRoleAssignedTo"],
        uncertainty: ["This comparison proves a configured change, not that the added privilege was exercised."], prerequisites: ["An attacker first controls Maya or a session/credential able to act as it.", "Every configured relationship shown in the path remains effective at the time of attempted use."], rule: ENTRA_CONTROL_PATH_RULES[1]!.reference, requiredCoverage: ENTRA_CONTROL_PATH_RULES[1]!.reference.requiredCoverage,
      },
      three: {
        id: "finding-ere-iam-003-61dd7d9f", title: "Privileged federated trust changed: GitHub main", category: "federated-identity", severity: "critical", evidenceClass: "inferred",
        summary: "issuer changed while this credential can reach Microsoft Graph.", whyItMatters: "Changing a privileged workload trust can transfer which external token identity is able to authenticate as the application or managed identity.", remediation: ["Confirm the issuer, subject, audience, parent workload, and approving owner against the deployment system that should hold this trust.", "Remove an unintended federated credential through the approved Entra change process and re-scan."], affectedObjectIds: ["federated-credential:app-1:fic-1", "app-1", "sp-1", "sp-graph"], edgeIds: ["federates", "instantiates", "grant"], attackPathId: "path-e91c50d9", sourceEndpoints: ["/applications/app-1/federatedIdentityCredentials", "/servicePrincipals", "/servicePrincipals/sp-graph/appRoleAssignedTo"], uncertainty: ["The configuration changed, but this does not prove that a matching external token was issued or used."], prerequisites: ["An attacker can obtain an external token whose issuer and subject exactly match GitHub main.", "Every configured relationship shown in the path remains effective at the time of attempted use."], rule: ENTRA_CONTROL_PATH_RULES[2]!.reference, requiredCoverage: ENTRA_CONTROL_PATH_RULES[2]!.reference.requiredCoverage,
      },
    });
  });
  it("rejects empty, cross-tenant, and incorrectly ordered histories", () => {
    expect(() => analyzeTenantIntelligenceHistory([])).toThrow(/at least one/i);
    const current = ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z");
    const before = ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z");
    expect(() => analyzeTenantIntelligenceHistory([before, current])).toThrow(/newest to oldest/i);
    const otherTenant = "d0000000-0000-4000-8000-000000000000";
    const other = { ...before, tenant: { tenantId: otherTenant, tenantLabel: "Other" }, nodes: before.nodes.map((item) => ({ ...item, tenantId: otherTenant })), edges: before.edges.map((item) => ({ ...item, tenantId: otherTenant })) };
    expect(() => analyzeTenantIntelligenceHistory([current, other])).toThrow(/same tenant/i);
    expect(current.tenant.tenantId).toBe(TENANT);
  });

  it("returns the same rule identities for the same ordered history", () => {
    const history = [ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z"), ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z")];
    const first = analyzeTenantIntelligenceHistory(history).findings.filter((item) => item.rule).map((item) => item.id);
    const second = analyzeTenantIntelligenceHistory(history).findings.filter((item) => item.rule).map((item) => item.id);
    expect(second).toEqual(first);
  });

  it("evaluates only rules in the requested snapshot or history scope", () => {
    const history = [ownedApplicationPath("Mail.ReadWrite", "2026-08-27T10:00:00.000Z"), ownedApplicationPath("Directory.Read.All", "2026-08-26T10:00:00.000Z")];
    expect(analyzeTenantIntelligence(history[0]!).findings.filter((item) => item.rule).map((item) => item.rule!.id)).toEqual(["ERE-IAM-001"]);
    expect(analyzeTenantIntelligenceHistory(history).findings.filter((item) => item.rule).map((item) => item.rule!.id)).toEqual(["ERE-IAM-002", "ERE-IAM-001"]);
    const current = analyzeTenantIntelligence(history[0]!);
    expect(ENTRA_CONTROL_PATH_RULES[1]!.evaluate({ current: history[0]!, previous: null, paths: current.paths, previousPaths: current.paths })).toEqual([]);
  });
});
