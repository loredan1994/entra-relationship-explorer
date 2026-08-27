import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, type IamFinding } from "./intelligence";
import { edge, node, snapshot } from "./test-support";
import type { DirectoryNode, TenantSnapshot } from "./types";

const graph = () => node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
const escalating = ["Directory.ReadWrite.All"];

/** A snapshot exercising every finding category at once. */
function richSnapshot(): TenantSnapshot {
  const person = node({ id: "user-1", kind: "user", label: "Avery Analyst" });
  const guest = node({ id: "user-2", kind: "user", label: "Partner Person", isExternal: true });
  const orphanApp = node({ id: "app-1", kind: "application", label: "Orphan App", ownerIds: [] });
  const expiringApp = node({ id: "app-2", kind: "application", label: "Legacy App", ownerIds: ["o"], credential: { status: "expired", expiresAt: "2025-01-01T00:00:00.000Z" } });
  const worker = node({ id: "sp-1", kind: "servicePrincipal", label: "Orchestrator", metadata: { ownershipExpected: true }, ownerIds: [] });
  const managed = node({ id: "mi-1", kind: "managedIdentity", label: "Deploy MI", risk: { level: "high", reason: "Broad access." } });
  const role = node({ id: "role-1", kind: "directoryRole", label: "Global Administrator" });
  const policy = node({ id: "policy-1", kind: "policy", label: "Block legacy auth", metadata: { policyType: "conditionalAccess", state: "disabled" } });
  const partner = node({ id: "ext-1", kind: "externalTenant", label: "Partner Tenant", metadata: { trustsMfa: true } });
  const api = graph();
  return snapshot(
    [person, guest, orphanApp, expiringApp, worker, managed, role, policy, partner, api],
    [
      edge("OWNS", person, worker),
      edge("CAN_CALL_AS_APP", worker, api, { permissions: escalating }),
      edge("CAN_CALL_DELEGATED", person, api, { permissions: ["Mail.Read"] }),
      edge("ELIGIBLE_FOR_ROLE", person, role),
    ],
    {
      completion: {
        status: "partial",
        collectedEndpoints: ["/applications", "/servicePrincipals", "/auditLogs/signIns"],
        skippedEndpoints: ["/identity/conditionalAccess/policies"],
        errors: ["throttled"],
      },
    },
  );
}

describe("every finding is explainable", () => {
  const findings = analyzeTenantIntelligence(richSnapshot()).findings;

  it("produces a finding for every category the snapshot exercises", () => {
    expect(new Set(findings.map((finding) => finding.category))).toEqual(new Set<IamFinding["category"]>([
      "privilege-path", "oauth-consent", "ownership", "application-credential",
      "guest-exposure", "managed-identity", "conditional-access", "cross-tenant", "dormant-access", "coverage",
    ]));
  });

  it.each([
    ["title", (finding: IamFinding) => finding.title],
    ["summary", (finding: IamFinding) => finding.summary],
    ["whyItMatters", (finding: IamFinding) => finding.whyItMatters],
  ])("gives every finding a non-empty %s", (_field, read) => {
    for (const finding of findings) {
      expect(read(finding).trim().length, `${finding.id}: ${finding.category}`).toBeGreaterThan(0);
    }
  });

  it("gives every finding at least one concrete remediation step", () => {
    for (const finding of findings) {
      expect(finding.remediation.length, finding.id).toBeGreaterThan(0);
      for (const step of finding.remediation) expect(step.trim().length, finding.id).toBeGreaterThan(0);
    }
  });

  it("states the uncertainty of every finding, so configured access is never read as proof", () => {
    for (const finding of findings) {
      expect(finding.uncertainty.length, `${finding.id} (${finding.category})`).toBeGreaterThan(0);
      for (const line of finding.uncertainty) expect(line.trim().length, finding.id).toBeGreaterThan(0);
    }
  });

  it("names the affected objects and the endpoint each finding came from", () => {
    for (const finding of findings) {
      if (finding.category !== "coverage") {
        expect(finding.affectedObjectIds.length, finding.id).toBeGreaterThan(0);
        expect(finding.sourceEndpoints.length, finding.id).toBeGreaterThan(0);
      }
      for (const endpoint of finding.sourceEndpoints) expect(endpoint.startsWith("/"), `${finding.id}: ${endpoint}`).toBe(true);
    }
  });

  it("gives every finding a distinct identifier, stable for a given snapshot", () => {
    const ids = findings.map((finding) => finding.id);
    expect(new Set(ids).size).toBe(ids.length);
    // Re-analyzing the same snapshot must reproduce the ids exactly; the builders
    // mint fresh edge ids per call, so the snapshot itself has to be reused.
    const snap = richSnapshot();
    expect(analyzeTenantIntelligence(snap).findings.map((finding) => finding.id))
      .toEqual(analyzeTenantIntelligence(snap).findings.map((finding) => finding.id));
  });

  it("links a privilege-path finding to its attack path and nothing else to one", () => {
    for (const finding of findings) {
      if (finding.category === "privilege-path" && finding.id.startsWith("finding-path")) {
        expect(finding.attackPathId, finding.id).not.toBeNull();
        expect(finding.edgeIds.length, finding.id).toBeGreaterThan(0);
      }
    }
  });

  it("classifies each finding's evidence honestly", () => {
    const classOf = (predicate: (finding: IamFinding) => boolean) => findings.find(predicate)!.evidenceClass;
    // A walked path is inferred; the PIM eligibility sharing its category is configured.
    expect(classOf((finding) => finding.id.startsWith("finding-path"))).toBe("inferred");
    expect(classOf((finding) => finding.id.startsWith("finding-pim"))).toBe("configured");
    expect(classOf((finding) => finding.category === "oauth-consent")).toBe("configured");
    expect(classOf((finding) => finding.category === "dormant-access")).toBe("inferred");
    expect(classOf((finding) => finding.category === "coverage")).toBe("missing");
  });
});

describe("which identities can start a path", () => {
  const api = graph();
  const call = (source: DirectoryNode) => edge("CAN_CALL_AS_APP", source, api, { permissions: escalating });
  const pathsFrom = (origin: DirectoryNode) => analyzeTenantIntelligence(snapshot([origin, api], [call(origin)])).paths;

  it("always starts from a person or a group", () => {
    expect(pathsFrom(node({ kind: "user", label: "Person", ownerIds: ["owner"] }))).toHaveLength(1);
    expect(pathsFrom(node({ kind: "group", label: "Team", ownerIds: ["owner"] }))).toHaveLength(1);
  });

  it("starts from a workload identity only when it is unowned or its credential expired", () => {
    const owned = node({ kind: "servicePrincipal", label: "Owned", ownerIds: ["owner"], credential: { status: "healthy", expiresAt: "2030-01-01T00:00:00.000Z" } });
    expect(pathsFrom(owned)).toHaveLength(0);
    expect(pathsFrom({ ...owned, ownerIds: [] })).toHaveLength(1);
    expect(pathsFrom({ ...owned, credential: { status: "expired", expiresAt: "2020-01-01T00:00:00.000Z" } })).toHaveLength(1);
  });

  it("applies the same rule to a managed identity", () => {
    const managed = node({ kind: "managedIdentity", label: "MI", ownerIds: ["owner"], credential: { status: "healthy", expiresAt: "2030-01-01T00:00:00.000Z" } });
    expect(pathsFrom(managed)).toHaveLength(0);
    expect(pathsFrom({ ...managed, ownerIds: [] })).toHaveLength(1);
  });

  it("does not start from a role, policy, app role, or blueprint object", () => {
    for (const kind of ["directoryRole", "policy", "appRole", "application", "externalTenant"] as const) {
      expect(pathsFrom(node({ kind, label: kind, ownerIds: [] })), kind).toHaveLength(0);
    }
  });

  it("treats an expiring credential as owned, not as a starting point", () => {
    const expiring = node({ kind: "servicePrincipal", label: "Soon", ownerIds: ["owner"], credential: { status: "expiring", expiresAt: "2026-09-01T00:00:00.000Z" } });
    expect(pathsFrom(expiring)).toHaveLength(0);
  });
});

describe("traversal limits", () => {
  /** A chain of `length` owned service principals ending at a powerful call. */
  function chain(length: number): TenantSnapshot {
    const origin = node({ id: "user-1", kind: "user", label: "Origin" });
    const hops = Array.from({ length }, (_, index) => node({ id: `hop-${index}`, kind: "servicePrincipal", label: `Hop ${index}`, ownerIds: ["owner"], credential: { status: "healthy", expiresAt: "2030-01-01T00:00:00.000Z" } }));
    const api = graph();
    const nodes = [origin, ...hops, api];
    const edges = [
      edge("OWNS", origin, hops[0]!),
      ...hops.slice(0, -1).map((hop, index) => edge("OWNS", hop, hops[index + 1]!)),
      edge("CAN_CALL_AS_APP", hops.at(-1)!, api, { permissions: escalating }),
    ];
    return snapshot(nodes, edges);
  }

  it("reports a path that sits exactly at the depth limit", () => {
    // Five relationships from the origin is the deepest chain the walk reports.
    const paths = analyzeTenantIntelligence(chain(4)).paths.filter((path) => path.source.id === "user-1");
    expect(paths[0]?.steps).toHaveLength(5);
  });

  it("stops before reporting a path longer than the depth limit", () => {
    const paths = analyzeTenantIntelligence(chain(5)).paths.filter((path) => path.source.id === "user-1");
    expect(paths).toHaveLength(0);
  });

  it("terminates on a cycle rather than revisiting a node", () => {
    const origin = node({ id: "user-1", kind: "user", label: "Origin" });
    const a = node({ id: "sp-a", kind: "servicePrincipal", label: "A", ownerIds: ["o"] });
    const b = node({ id: "sp-b", kind: "servicePrincipal", label: "B", ownerIds: ["o"] });
    const api = graph();
    const snap = snapshot([origin, a, b, api], [
      edge("OWNS", origin, a),
      edge("OWNS", a, b),
      edge("OWNS", b, a),
      edge("CAN_CALL_AS_APP", b, api, { permissions: escalating }),
    ]);
    const paths = analyzeTenantIntelligence(snap).paths;
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      const visited = [path.steps[0]!.source.id, ...path.steps.map((step) => step.target.id)];
      expect(new Set(visited).size, path.title).toBe(visited.length);
    }
  });

  it("never includes an observed-activity edge as a step", () => {
    const origin = node({ id: "user-1", kind: "user", label: "Origin" });
    const a = node({ id: "sp-a", kind: "servicePrincipal", label: "A", ownerIds: ["o"] });
    const api = graph();
    const snap = snapshot([origin, a, api], [
      edge("OBSERVED_CALL", origin, a),
      edge("OWNS", origin, a),
      edge("CAN_CALL_AS_APP", a, api, { permissions: escalating }),
    ]);
    for (const path of analyzeTenantIntelligence(snap).paths) {
      expect(path.steps.every((step) => step.relationship !== "OBSERVED_CALL")).toBe(true);
    }
  });
});

describe("path uncertainty", () => {
  const origin = node({ id: "user-1", kind: "user", label: "Origin" });
  const api = graph();

  function pathFor(options: { observed?: boolean; partial?: boolean }) {
    const call = edge("CAN_CALL_AS_APP", origin, api, {
      permissions: escalating,
      evidence: options.observed ? { observed: { lastSeenAt: "2026-08-20T00:00:00.000Z", windowStartsAt: "2026-07-21T00:00:00.000Z" } } : {},
    });
    const snap = snapshot([origin, api], [call], options.partial ? {
      completion: { status: "partial", collectedEndpoints: [], skippedEndpoints: [], errors: ["throttled"] },
    } : {});
    return analyzeTenantIntelligence(snap).paths[0]!;
  }

  it("always says the path is an inference rather than observed exploitation", () => {
    expect(pathFor({}).uncertainty[0]).toContain("not evidence that exploitation occurred");
  });

  it("notes when no activity evidence backs the final permission", () => {
    expect(pathFor({}).uncertainty.some((line) => line.includes("No activity evidence"))).toBe(true);
  });

  it("drops that note once activity evidence exists for the final permission", () => {
    expect(pathFor({ observed: true }).uncertainty.some((line) => line.includes("No activity evidence"))).toBe(false);
  });

  it("warns that a partial snapshot may hide shorter or additional paths", () => {
    expect(pathFor({ partial: true }).uncertainty.some((line) => line.includes("partial"))).toBe(true);
    expect(pathFor({}).uncertainty.some((line) => line.includes("partial"))).toBe(false);
  });

  it("accumulates every applicable caveat", () => {
    expect(pathFor({ partial: true }).uncertainty).toHaveLength(3);
    expect(pathFor({ observed: true }).uncertainty).toHaveLength(1);
  });
});

describe("path ordering", () => {
  it("puts a more severe path before a less severe one", () => {
    const person = node({ id: "user-1", kind: "user", label: "Person" });
    const critical = node({ id: "sp-1", kind: "servicePrincipal", label: "Critical target" });
    const medium = node({ id: "sp-2", kind: "servicePrincipal", label: "Medium target" });
    const snap = snapshot([person, critical, medium], [
      edge("CAN_CALL_AS_APP", person, medium, { permissions: ["Directory.Read.All"] }),
      edge("CAN_CALL_AS_APP", person, critical, { permissions: escalating }),
    ]);
    expect(analyzeTenantIntelligence(snap).paths.map((path) => path.severity)).toEqual(["critical", "medium"]);
  });

  it("puts a shorter path before a longer one of equal severity", () => {
    const person = node({ id: "user-1", kind: "user", label: "Person" });
    const hop = node({ id: "sp-hop", kind: "servicePrincipal", label: "Hop", ownerIds: ["o"] });
    const api = graph();
    const snap = snapshot([person, hop, api], [
      edge("OWNS", person, hop),
      edge("CAN_CALL_AS_APP", hop, api, { permissions: escalating }),
      edge("CAN_CALL_AS_APP", person, api, { permissions: escalating }),
    ]);
    const lengths = analyzeTenantIntelligence(snap).paths.map((path) => path.steps.length);
    expect(lengths).toEqual([...lengths].sort((a, b) => a - b));
  });

  it("breaks a remaining tie by title, so the order never drifts between runs", () => {
    const zed = node({ id: "user-z", kind: "user", label: "Zed" });
    const abe = node({ id: "user-a", kind: "user", label: "Abe" });
    const api = graph();
    const snap = snapshot([zed, abe, api], [
      edge("CAN_CALL_AS_APP", zed, api, { permissions: escalating }),
      edge("CAN_CALL_AS_APP", abe, api, { permissions: escalating }),
    ]);
    expect(analyzeTenantIntelligence(snap).paths.map((path) => path.source.label)).toEqual(["Abe", "Zed"]);
  });
});

describe("severity boundaries", () => {
  const person = node({ id: "user-1", kind: "user", label: "Person" });

  function roleSeverity(label: string, type: "ACTIVE_IN_ROLE" | "ELIGIBLE_FOR_ROLE") {
    const role = node({ kind: "directoryRole", label });
    return analyzeTenantIntelligence(snapshot([person, role], [edge(type, person, role)])).paths[0]?.severity;
  }

  it("treats both named privileged roles as the top tier", () => {
    expect(roleSeverity("Global Administrator", "ACTIVE_IN_ROLE")).toBe("critical");
    expect(roleSeverity("Privileged Role Administrator", "ACTIVE_IN_ROLE")).toBe("critical");
    expect(roleSeverity("Global Administrator", "ELIGIBLE_FOR_ROLE")).toBe("high");
  });

  it("matches a privileged role name regardless of case or surrounding words", () => {
    expect(roleSeverity("global administrator", "ACTIVE_IN_ROLE")).toBe("critical");
    expect(roleSeverity("Contoso Global Administrator (custom)", "ACTIVE_IN_ROLE")).toBe("critical");
  });

  it("rates an ordinary role below a privileged one", () => {
    expect(roleSeverity("Reports Reader", "ACTIVE_IN_ROLE")).toBe("high");
    expect(roleSeverity("Reports Reader", "ELIGIBLE_FOR_ROLE")).toBe("medium");
  });

  it("raises no path for a relationship that grants no reachable access", () => {
    const target = node({ kind: "servicePrincipal", label: "Target" });
    for (const type of ["OWNS", "MEMBER_OF", "INSTANTIATES_AS", "GOVERNED_BY", "EXPOSES_APP_ROLE"] as const) {
      expect(analyzeTenantIntelligence(snapshot([person, target], [edge(type, person, target)])).paths, type).toHaveLength(0);
    }
  });
});

/**
 * A finding is only actionable if it says exactly which objects and relationships it came
 * from, and only trustworthy if the same snapshot always produces the same identifiers —
 * saved review decisions are keyed by them. This pins the whole record for every category.
 */
describe("finding provenance", () => {
  function scenario(): TenantSnapshot {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const guest = node({ id: "user-2", kind: "user", label: "Partner", isExternal: true });
    const orphan = node({ id: "app-1", kind: "application", label: "Orphan App", ownerIds: [] });
    const legacy = node({ id: "app-2", kind: "application", label: "Legacy App", ownerIds: ["user-1"], credential: { status: "expired", expiresAt: "2025-01-01T00:00:00.000Z" } });
    const worker = node({ id: "sp-1", kind: "servicePrincipal", label: "Orchestrator", metadata: { ownershipExpected: true }, ownerIds: ["user-1"] });
    const api = node({ id: "sp-graph", kind: "servicePrincipal", label: "Microsoft Graph" });
    const managed = node({ id: "mi-1", kind: "managedIdentity", label: "Deploy MI", ownerIds: ["user-1"], metadata: { ownershipExpected: true }, risk: { level: "high", reason: "Broad." } });
    const role = node({ id: "role-1", kind: "directoryRole", label: "Global Administrator" });
    const policy = node({ id: "policy-1", kind: "policy", label: "Block legacy", metadata: { policyType: "conditionalAccess", state: "disabled" } });
    const partner = node({ id: "ext-1", kind: "externalTenant", label: "Partner Tenant", metadata: { trustsMfa: true } });
    return snapshot(
      [person, guest, orphan, legacy, worker, api, managed, role, policy, partner],
      [
        edge("CAN_CALL_AS_APP", worker, api, { id: "edge-app", permissions: ["Directory.ReadWrite.All"], evidence: { sourceEndpoint: "/servicePrincipals/sp-graph/appRoleAssignedTo" } }),
        edge("CAN_CALL_DELEGATED", person, api, { id: "edge-delegated", permissions: ["Mail.Read"], evidence: { sourceEndpoint: "/oauth2PermissionGrants" } }),
        edge("ELIGIBLE_FOR_ROLE", person, role, { id: "edge-pim", evidence: { sourceEndpoint: "/roleManagement/directory/roleEligibilitySchedules" } }),
      ],
      {
        id: "snapshot-fixed",
        completion: {
          status: "partial",
          collectedEndpoints: ["/applications", "/auditLogs/signIns?$top=250"],
          skippedEndpoints: ["/identity/conditionalAccess/policies"],
          errors: ["throttled"],
        },
      },
    );
  }

  const findings = analyzeTenantIntelligence(scenario()).findings;
  const byId = (id: string) => findings.find((finding) => finding.id === id);

  it.each([
    ["finding-path-a0ab35f7", "privilege-path", "high", "inferred", ["user-1", "role-1"], ["edge-pim"], "path-a0ab35f7", ["/roleManagement/directory/roleEligibilitySchedules"]],
    ["finding-app-permission-6dd4e036", "oauth-consent", "critical", "configured", ["sp-1", "sp-graph"], ["edge-app"], null, ["/servicePrincipals/sp-graph/appRoleAssignedTo"]],
    ["finding-consent-65f66300", "oauth-consent", "medium", "configured", ["user-1", "sp-graph"], ["edge-delegated"], null, ["/oauth2PermissionGrants"]],
    ["finding-pim-a0ab35f7", "privilege-path", "high", "configured", ["user-1", "role-1"], ["edge-pim"], null, ["/roleManagement/directory/roleEligibilitySchedules"]],
    ["finding-dormant-6dd4e036", "dormant-access", "medium", "inferred", ["sp-1", "sp-graph"], ["edge-app"], null, ["/servicePrincipals/sp-graph/appRoleAssignedTo", "/auditLogs/signIns?$top=250"]],
    ["finding-owner-e0204d06", "ownership", "medium", "configured", ["app-1"], [], null, ["/applications/app-1/owners"]],
    ["finding-credential-df204b73", "application-credential", "high", "configured", ["app-2"], [], null, ["/applications"]],
    ["finding-guest-f8537e2d", "guest-exposure", "medium", "configured", ["user-2"], [], null, ["/users"]],
    ["finding-managed-3b2b2501", "managed-identity", "high", "configured", ["mi-1"], [], null, ["/servicePrincipals"]],
    ["finding-ca-f615da65", "conditional-access", "medium", "configured", ["policy-1"], [], null, ["/identity/conditionalAccess/policies"]],
    ["finding-cross-tenant-695e7b1e", "cross-tenant", "high", "configured", ["ext-1"], [], null, ["/policies/crossTenantAccessPolicy/partners"]],
    ["finding-coverage-dc4f50fa", "coverage", "high", "missing", [], [], null, ["/identity/conditionalAccess/policies"]],
  ])("records %s against the objects and relationships behind it", (id, category, severity, evidenceClass, objectIds, edgeIds, attackPathId, endpoints) => {
    expect(byId(id), id).toBeDefined();
    expect(byId(id)).toMatchObject({ category, severity, evidenceClass, affectedObjectIds: objectIds, edgeIds, attackPathId, sourceEndpoints: endpoints });
  });

  it("finds every category the snapshot exercises and nothing beyond it", () => {
    expect(findings.map((finding) => finding.id).sort()).toEqual([
      "finding-app-permission-6dd4e036", "finding-ca-f615da65", "finding-consent-65f66300", "finding-coverage-dc4f50fa",
      "finding-credential-df204b73", "finding-cross-tenant-695e7b1e", "finding-dormant-65f66300", "finding-dormant-6dd4e036",
      "finding-guest-f8537e2d", "finding-managed-3b2b2501", "finding-owner-e0204d06", "finding-path-a0ab35f7", "finding-pim-a0ab35f7",
    ]);
  });

  it("names the same finding identically on a re-analysis of the same snapshot", () => {
    const again = analyzeTenantIntelligence(scenario()).findings.map((finding) => finding.id);
    expect(again).toEqual(findings.map((finding) => finding.id));
  });
});

describe("which objects raise which finding", () => {
  const api = () => node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });
  const categoriesOf = (snap: TenantSnapshot) => new Set(analyzeTenantIntelligence(snap).findings.map((finding) => finding.category));

  it("holds only applications and owner-expecting workload identities accountable for ownership", () => {
    const accountable = [
      node({ id: "app-1", kind: "application", label: "App", ownerIds: [] }),
      node({ id: "sp-1", kind: "servicePrincipal", label: "Workload", metadata: { ownershipExpected: true }, ownerIds: [] }),
      node({ id: "mi-1", kind: "managedIdentity", label: "Deploy", metadata: { ownershipExpected: true }, ownerIds: [] }),
    ];
    expect(analyzeTenantIntelligence(snapshot(accountable, [])).findings.filter((finding) => finding.category === "ownership").map((finding) => finding.affectedObjectIds.flat()))
      .toEqual([["app-1"], ["sp-1"], ["mi-1"]]);
    const notAccountable = [
      // Ownership is expected of workload identities, not of people or groups, whatever
      // metadata a snapshot happens to carry.
      node({ id: "user-1", kind: "user", label: "Person", ownerIds: [], metadata: { ownershipExpected: true } }),
      node({ id: "group-1", kind: "group", label: "Group", ownerIds: [], metadata: { ownershipExpected: true } }),
      node({ id: "policy-2", kind: "policy", label: "Policy", ownerIds: [], metadata: { ownershipExpected: true } }),
      node({ id: "sp-2", kind: "servicePrincipal", label: "First party", ownerIds: [] }),
      node({ id: "mi-2", kind: "managedIdentity", label: "Unmanaged", ownerIds: [] }),
      node({ id: "role-2", kind: "directoryRole", label: "Role", ownerIds: [] }),
    ];
    expect(categoriesOf(snapshot(notAccountable, []))).not.toContain("ownership");
  });

  it("does not raise an ownership finding for an identity that already has an owner", () => {
    const owned = node({ id: "app-1", kind: "application", label: "App", ownerIds: ["user-1"] });
    expect(categoriesOf(snapshot([owned], []))).not.toContain("ownership");
  });

  it("cites the owners endpoint of the object kind it found", () => {
    const app = node({ id: "app-1", kind: "application", label: "App", ownerIds: [] });
    const workload = node({ id: "sp-1", kind: "servicePrincipal", label: "Workload", metadata: { ownershipExpected: true }, ownerIds: [] });
    const findings = analyzeTenantIntelligence(snapshot([app, workload], [])).findings.filter((finding) => finding.category === "ownership");
    expect(findings.map((finding) => finding.sourceEndpoints)).toEqual([["/applications/app-1/owners"], ["/servicePrincipals/sp-1/owners"]]);
  });

  it("raises a credential finding only for an application or an owner-expecting workload", () => {
    const credential = { status: "expiring" as const, expiresAt: "2027-01-01T00:00:00.000Z" };
    const eligible = [
      node({ id: "app-1", kind: "application", label: "App", ownerIds: ["o"], credential }),
      node({ id: "sp-1", kind: "servicePrincipal", label: "Workload", metadata: { ownershipExpected: true }, ownerIds: ["o"], credential }),
    ];
    expect(analyzeTenantIntelligence(snapshot(eligible, [])).findings.filter((finding) => finding.category === "application-credential")).toHaveLength(2);
    const ignored = [
      node({ id: "sp-2", kind: "servicePrincipal", label: "First party", ownerIds: ["o"], credential }),
      node({ id: "mi-1", kind: "managedIdentity", label: "Deploy", metadata: { ownershipExpected: true }, ownerIds: ["o"], credential }),
      node({ id: "user-1", kind: "user", label: "Person", ownerIds: ["o"], credential }),
    ];
    expect(categoriesOf(snapshot(ignored, []))).not.toContain("application-credential");
  });

  it("raises a guest finding only for an external person", () => {
    expect(categoriesOf(snapshot([node({ id: "user-1", kind: "user", label: "Local" })], []))).not.toContain("guest-exposure");
    expect(categoriesOf(snapshot([node({ id: "group-1", kind: "group", label: "External group", isExternal: true })], []))).not.toContain("guest-exposure");
    expect(categoriesOf(snapshot([node({ id: "user-2", kind: "user", label: "Guest", isExternal: true })], []))).toContain("guest-exposure");
  });

  it("raises a managed-identity finding only for a managed identity", () => {
    expect(categoriesOf(snapshot([node({ id: "sp-1", kind: "servicePrincipal", label: "Workload" })], []))).not.toContain("managed-identity");
    expect(categoriesOf(snapshot([node({ id: "mi-1", kind: "managedIdentity", label: "Deploy" })], []))).toContain("managed-identity");
  });

  it("raises a Conditional Access finding only for a Conditional Access policy", () => {
    const crossTenant = node({ id: "policy-1", kind: "policy", label: "Partner policy", metadata: { policyType: "crossTenantAccess", state: "configured" } });
    expect(categoriesOf(snapshot([crossTenant], []))).not.toContain("conditional-access");
  });

  it("raises a cross-tenant finding only for a partner tenant", () => {
    expect(categoriesOf(snapshot([node({ id: "policy-1", kind: "policy", label: "Partner policy", metadata: { policyType: "crossTenantAccess" } })], []))).not.toContain("cross-tenant");
    expect(categoriesOf(snapshot([node({ id: "ext-1", kind: "externalTenant", label: "Partner" })], []))).toContain("cross-tenant");
  });

  it("raises a consent finding only for a relationship that actually carries permissions", () => {
    const caller = node({ id: "sp-1", kind: "servicePrincipal", label: "Caller" });
    const resource = api();
    for (const type of ["CAN_CALL_AS_APP", "CAN_CALL_DELEGATED"] as const) {
      const empty = snapshot([caller, resource], [edge(type, caller, resource, { permissions: [] })]);
      expect(categoriesOf(empty), type).not.toContain("oauth-consent");
      const carried = snapshot([caller, resource], [edge(type, caller, resource, { permissions: ["Api.Read"] })]);
      expect(categoriesOf(carried), type).toContain("oauth-consent");
    }
  });

  it("raises a PIM finding only for an eligibility, not for an active membership", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const role = node({ id: "role-1", kind: "directoryRole", label: "Helpdesk Administrator" });
    const active = analyzeTenantIntelligence(snapshot([person, role], [edge("ACTIVE_IN_ROLE", person, role)])).findings;
    expect(active.some((finding) => finding.id.startsWith("finding-pim"))).toBe(false);
    const eligible = analyzeTenantIntelligence(snapshot([person, role], [edge("ELIGIBLE_FOR_ROLE", person, role)])).findings;
    expect(eligible.some((finding) => finding.id.startsWith("finding-pim"))).toBe(true);
  });

  it("raises a coverage finding for a recorded error even when nothing was skipped", () => {
    const withError = snapshot([], [], {
      completion: { status: "complete", collectedEndpoints: ["/applications"], skippedEndpoints: [], errors: ["/applications: throttled"] },
    });
    const finding = analyzeTenantIntelligence(withError).findings.find((item) => item.category === "coverage")!;
    expect(finding.severity).toBe("low");
    expect(finding.summary).toContain("0 endpoint patterns were skipped and 1 collection errors");
    expect(finding.sourceEndpoints).toEqual([]);
  });
});

describe("identifier format", () => {
  it("pads a short hash so every identifier is the same width", () => {
    // "app-10" hashes to a value whose hex form starts with a zero.
    const orphan = node({ id: "app-10", kind: "application", label: "Orphan", ownerIds: [] });
    const finding = analyzeTenantIntelligence(snapshot([orphan], [])).findings.find((item) => item.category === "ownership")!;
    expect(finding.id).toBe("finding-owner-08d98c02");
  });

  it("separates the parts of a multi-step identifier so two paths cannot collide", () => {
    const person = node({ id: "user-1", kind: "user", label: "Avery" });
    const middle = node({ id: "sp-1", kind: "servicePrincipal", label: "Orchestrator", metadata: { ownershipExpected: true }, ownerIds: ["user-1"] });
    const api = node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });
    const path = analyzeTenantIntelligence(snapshot([person, middle, api], [
      edge("OWNS", person, middle, { id: "edge-18" }),
      edge("CAN_CALL_AS_APP", middle, api, { id: "edge-b", permissions: ["Directory.ReadWrite.All"] }),
    ])).paths[0]!;
    expect(path.id).toBe("path-0ae73e8e");
  });
});

describe("directory escalation permissions", () => {
  const caller = () => node({ id: "sp-1", kind: "servicePrincipal", label: "Caller", metadata: { ownershipExpected: true }, ownerIds: [] });
  const api = () => node({ id: "sp-api", kind: "servicePrincipal", label: "Microsoft Graph" });

  it.each([
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
  ])("treats %s as directory escalation for an application-only grant", (permission) => {
    const c = caller();
    const r = api();
    const result = analyzeTenantIntelligence(snapshot([c, r], [edge("CAN_CALL_AS_APP", c, r, { permissions: [permission] })]));
    expect(result.paths[0]?.severity).toBe("critical");
    expect(result.findings.find((finding) => finding.category === "oauth-consent")?.severity).toBe("critical");
  });

  it("does not treat the matching read permission as escalation", () => {
    const c = caller();
    const r = api();
    const result = analyzeTenantIntelligence(snapshot([c, r], [edge("CAN_CALL_AS_APP", c, r, { permissions: ["User.Read.All"] })]));
    expect(result.paths[0]?.severity).toBe("medium");
  });
});
