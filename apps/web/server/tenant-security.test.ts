import { cleanProjectFixture, type RelationshipEdge, type TenantSnapshot } from "@entra-explorer/domain";
import { describe, expect, it } from "vitest";
import { analyzeTenantSecurity, isEscalation, isTenantWide, isWriteCapable } from "./tenant-security";

const base = cleanProjectFixture;

function withGrant(permissions: string[], type: RelationshipEdge["type"] = "CAN_CALL_AS_APP"): TenantSnapshot {
  const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
  return {
    ...base,
    edges: [{ ...template, id: "edge-under-test", type, permissions }],
  };
}

describe("permission classification", () => {
  it("recognises write-capable permission values", () => {
    expect(["Api.Write", "Directory.ReadWrite.All", "Mail.Send"].every(isWriteCapable)).toBe(true);
    expect(["Api.Read", "Directory.Read.All", "User.Read"].some(isWriteCapable)).toBe(false);
  });

  it("recognises tenant-wide and directory-changing permissions", () => {
    expect(isTenantWide("Directory.Read.All")).toBe(true);
    expect(isTenantWide("Api.Read")).toBe(false);
    expect(isEscalation("AppRoleAssignment.ReadWrite.All")).toBe(true);
    expect(isEscalation("RoleManagement.ReadWrite.Directory")).toBe(true);
    expect(isEscalation("Api.Write")).toBe(false);
  });
});

describe("exposure rules", () => {
  it("treats an app-only grant that can assign permissions as the highest exposure", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["AppRoleAssignment.ReadWrite.All"])).grants;
    expect(grant?.exposure).toBe("high");
    expect(grant?.reason).toContain("widen its own access");
  });

  it("treats an app-only tenant-wide write as high exposure", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Files.ReadWrite.All"])).grants;
    expect(grant?.exposure).toBe("high");
  });

  it("ranks the same permission lower when it needs a signed-in person", () => {
    const appOnly = analyzeTenantSecurity(withGrant(["AppRoleAssignment.ReadWrite.All"])).grants[0];
    const delegated = analyzeTenantSecurity(withGrant(["AppRoleAssignment.ReadWrite.All"], "CAN_CALL_DELEGATED")).grants[0];
    expect(appOnly?.exposure).toBe("high");
    expect(delegated?.exposure).toBe("review");
  });

  it("does not flag a scoped read as exposure", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Api.Read"])).grants;
    expect(grant?.exposure).toBe("low");
    expect(grant?.writeCapable).toEqual([]);
  });

  it("flags an app-only tenant-wide read for review without calling it a write", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Directory.Read.All"])).grants;
    expect(grant?.exposure).toBe("review");
    expect(grant?.reason).toContain("Reads across the whole tenant");
  });

  it("orders the most exposed grant first", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      edges: [
        { ...base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!, id: "low", permissions: ["Api.Read"] },
        { ...base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!, id: "high", permissions: ["Directory.ReadWrite.All"] },
      ],
    };
    expect(analyzeTenantSecurity(snapshot).grants.map((grant) => grant.edgeId)).toEqual(["high", "low"]);
  });
});

describe("the escalation permission list", () => {
  it.each([
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
  ])("treats %s as directory escalation, whatever the case", (permission) => {
    expect(isEscalation(permission)).toBe(true);
    expect(isEscalation(permission.toLowerCase())).toBe(true);
    expect(analyzeTenantSecurity(withGrant([permission])).grants[0]?.exposure).toBe("high");
  });

  it("does not treat a neighbouring read permission as escalation", () => {
    for (const permission of ["Directory.Read.All", "User.Read.All", "Group.Read.All", "Application.Read.All"]) {
      expect(isEscalation(permission), permission).toBe(false);
    }
  });
});

describe("grant provenance", () => {
  it("names the caller and the resource on each side of the grant", () => {
    const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const caller = { ...base.nodes[0]!, id: "caller-1", label: "Expense Reporter", kind: "servicePrincipal" as const, credential: undefined };
    const resource = { ...base.nodes[0]!, id: "resource-1", label: "Microsoft Graph", kind: "servicePrincipal" as const, credential: undefined };
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [caller, resource],
      edges: [{ ...template, id: "edge-1", sourceId: caller.id, targetId: resource.id, permissions: ["Api.Read"] }],
    };
    const [grant] = analyzeTenantSecurity(snapshot).grants;
    expect(grant?.caller).toEqual({ id: "caller-1", label: "Expense Reporter", kind: "servicePrincipal" });
    expect(grant?.resource).toEqual({ id: "resource-1", label: "Microsoft Graph", kind: "servicePrincipal" });
    expect(grant?.edgeId).toBe("edge-1");
    expect(grant?.sourceEndpoint).toBe(template.evidence.sourceEndpoint);
  });
});

describe("reasons that list more than one permission", () => {
  it("joins every escalation permission a delegated grant carries", () => {
    const [grant] = analyzeTenantSecurity(
      withGrant(["Directory.ReadWrite.All", "Group.ReadWrite.All"], "CAN_CALL_DELEGATED"),
    ).grants;
    expect(grant?.reason).toBe("Can change the directory as the signed-in person using Directory.ReadWrite.All and Group.ReadWrite.All.");
  });

  it("joins every tenant-wide write an app-only grant carries", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Files.ReadWrite.All", "Mail.ReadWrite.All"])).grants;
    expect(grant?.reason).toBe("Runs as itself and can write across the whole tenant using Files.ReadWrite.All and Mail.ReadWrite.All.");
  });

  it("joins every narrow write an app-only grant carries", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Mail.Send", "Api.Write"])).grants;
    expect(grant?.reason).toBe("Runs as itself, with no signed-in person, and can write using Mail.Send and Api.Write.");
  });

  it("joins every narrow write a delegated grant carries", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Mail.Send", "Api.Write"], "CAN_CALL_DELEGATED")).grants;
    expect(grant?.reason).toBe("Can write on behalf of a signed-in person using Mail.Send and Api.Write.");
  });

  it("joins every tenant-wide read an app-only grant carries", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Directory.Read.All", "Files.Read.All"])).grants;
    expect(grant?.reason).toBe("Reads across the whole tenant as itself using Directory.Read.All and Files.Read.All.");
  });
});

describe("accountability and credentials", () => {
  it("lists applications and identities with no recorded owner", () => {
    const view = analyzeTenantSecurity(base);
    expect(view.ownership.map((gap) => gap.label)).toContain("Expense Reporter");
    expect(view.ownership.every((gap) => gap.kind === "application" || gap.kind === "servicePrincipal")).toBe(true);
  });

  it("reports expiring credentials with the days remaining", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: base.nodes.map((node, index) =>
        index === 0 ? { ...node, credential: { status: "expiring" as const, expiresAt: "2026-09-05T00:00:00Z" } } : node,
      ),
    };
    const [issue] = analyzeTenantSecurity(snapshot, Date.parse("2026-08-26T00:00:00Z")).credentials;
    expect(issue?.status).toBe("expiring");
    expect(issue?.daysRemaining).toBe(10);
  });

  it("ignores healthy credentials and applications that have none", () => {
    expect(analyzeTenantSecurity(base).credentials).toEqual([]);
  });
});

describe("the fixture tenant", () => {
  it("summarises the configured grants without inventing activity", () => {
    const view = analyzeTenantSecurity(base);
    expect(view.summary.applicationGrants).toBe(1);
    expect(view.summary.delegatedGrants).toBe(1);
    expect(view.summary.writeCapableGrants).toBe(1);
    expect(view.grants.every((grant) => grant.scannedAt === base.scannedAt)).toBe(true);
  });
});

describe("delegated exposure wording", () => {
  it("describes a delegated write as acting on behalf of a signed-in person", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Mail.ReadWrite"], "CAN_CALL_DELEGATED")).grants;
    expect(grant?.exposure).toBe("review");
    expect(grant?.reason).toBe("Can write on behalf of a signed-in person using Mail.ReadWrite.");
  });

  it("describes an app-only narrow write as running with no signed-in person", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Mail.ReadWrite"])).grants;
    expect(grant?.reason).toBe("Runs as itself, with no signed-in person, and can write using Mail.ReadWrite.");
  });

  it("does not raise a delegated tenant-wide read above low exposure", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Directory.Read.All"], "CAN_CALL_DELEGATED")).grants;
    expect(grant?.exposure).toBe("low");
    expect(grant?.reason).toBe("Read-only access to a single resource.");
  });

  it("names every escalation permission it found", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All"])).grants;
    expect(grant?.reason).toContain("AppRoleAssignment.ReadWrite.All and Directory.ReadWrite.All");
    expect(grant?.escalation).toEqual(["AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All"]);
  });

  it("describes a delegated escalation without claiming it widens its own access", () => {
    const [grant] = analyzeTenantSecurity(withGrant(["Directory.ReadWrite.All"], "CAN_CALL_DELEGATED")).grants;
    expect(grant?.reason).toBe("Can change the directory as the signed-in person using Directory.ReadWrite.All.");
    expect(grant?.reason).not.toContain("widen its own access");
  });

  it("counts a grant with no permissions at all as low exposure", () => {
    const [grant] = analyzeTenantSecurity(withGrant([])).grants;
    expect(grant?.exposure).toBe("low");
    expect(grant?.permissions).toEqual([]);
  });
});

describe("credential ordering", () => {
  it("puts the nearest expiry first and sorts an unknown expiry last", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "later", label: "Later", credential: { status: "expiring" as const, expiresAt: "2026-12-01T00:00:00Z" } },
        { ...base.nodes[0]!, id: "unknown", label: "Unknown", credential: { status: "expired" as const, expiresAt: null } },
        { ...base.nodes[0]!, id: "sooner", label: "Sooner", credential: { status: "expired" as const, expiresAt: "2026-01-01T00:00:00Z" } },
      ],
    };
    const issues = analyzeTenantSecurity(snapshot, Date.parse("2026-08-26T00:00:00Z")).credentials;
    expect(issues.map((issue) => issue.id)).toEqual(["sooner", "later", "unknown"]);
    expect(issues.at(-1)?.daysRemaining).toBeNull();
  });

  it("sorts an unknown expiry last even when the snapshot lists it first", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "unknown", label: "Unknown", credential: { status: "expired" as const, expiresAt: null } },
        { ...base.nodes[0]!, id: "later", label: "Later", credential: { status: "expiring" as const, expiresAt: "2026-12-01T00:00:00Z" } },
      ],
    };
    const issues = analyzeTenantSecurity(snapshot, Date.parse("2026-08-26T00:00:00Z")).credentials;
    expect(issues.map((issue) => issue.id)).toEqual(["later", "unknown"]);
  });

  it("treats an unparseable expiry as unknown rather than a date", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [{ ...base.nodes[0]!, id: "bad", credential: { status: "expiring" as const, expiresAt: "not-a-date" } }],
    };
    expect(analyzeTenantSecurity(snapshot).credentials[0]?.daysRemaining).toBeNull();
  });

  it("reports a negative day count for a credential that already expired", () => {
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [{ ...base.nodes[0]!, id: "gone", credential: { status: "expired" as const, expiresAt: "2026-08-16T00:00:00Z" } }],
    };
    expect(analyzeTenantSecurity(snapshot, Date.parse("2026-08-26T00:00:00Z")).credentials[0]?.daysRemaining).toBe(-10);
  });
});

describe("summary tallies", () => {
  it("counts application, delegated, write-capable, and escalation grants separately", () => {
    const appTemplate = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const snapshot: TenantSnapshot = {
      ...base,
      edges: [
        { ...appTemplate, id: "app-escalation", type: "CAN_CALL_AS_APP", permissions: ["Directory.ReadWrite.All"] },
        { ...appTemplate, id: "app-read", type: "CAN_CALL_AS_APP", permissions: ["Api.Read"] },
        { ...appTemplate, id: "delegated-write", type: "CAN_CALL_DELEGATED", permissions: ["Mail.Send"] },
      ],
    };
    expect(analyzeTenantSecurity(snapshot).summary).toMatchObject({
      applicationGrants: 2,
      delegatedGrants: 1,
      // The escalating grant and the delegated Mail.Send both write; the plain read does not.
      writeCapableGrants: 2,
      escalationGrants: 1,
    });
  });

  it("counts no escalation when nothing in the tenant can change the directory", () => {
    const view = analyzeTenantSecurity(withGrant(["Api.Read"]));
    expect(view.summary.escalationGrants).toBe(0);
    expect(view.summary.writeCapableGrants).toBe(0);
  });
});

describe("ownership ranking", () => {
  it("ranks an unowned identity with more grants ahead of one with fewer", () => {
    const view = analyzeTenantSecurity(base);
    for (let index = 1; index < view.ownership.length; index += 1) {
      expect(view.ownership[index - 1]!.grantCount).toBeGreaterThanOrEqual(view.ownership[index]!.grantCount);
    }
  });

  it("carries the snapshot envelope onto the view", () => {
    const view = analyzeTenantSecurity(base);
    expect(view).toMatchObject({
      mode: base.mode,
      tenantLabel: base.tenant.tenantLabel,
      scannedAt: base.scannedAt,
      completion: base.completion.status,
    });
  });

  it("orders review items with the highest level first", () => {
    const view = analyzeTenantSecurity(base);
    const levels = view.review.map((item) => item.level);
    expect(levels.indexOf("review") === -1 || levels.lastIndexOf("high") < levels.indexOf("review")).toBe(true);
  });
});

describe("deterministic ordering", () => {
  function nodesWith(entries: Array<Partial<TenantSnapshot["nodes"][number]>>): TenantSnapshot {
    const template = base.nodes[0]!;
    return { ...base, edges: [], nodes: entries.map((entry, index) => ({ ...template, id: `n-${index}`, ...entry })) };
  }

  it("ranks unowned identities by grant count, breaking ties by label", () => {
    const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "busy", label: "Busy", kind: "application", ownerIds: [], credential: undefined },
        { ...base.nodes[0]!, id: "zed", label: "Zed", kind: "application", ownerIds: [], credential: undefined },
        { ...base.nodes[0]!, id: "abe", label: "Abe", kind: "application", ownerIds: [], credential: undefined },
        { ...base.nodes[0]!, id: "target", label: "Target", kind: "servicePrincipal", ownerIds: ["o"], credential: undefined },
      ],
      edges: [
        { ...template, id: "g1", sourceId: "busy", targetId: "target", permissions: ["Api.Read"] },
        { ...template, id: "g2", sourceId: "busy", targetId: "target", permissions: ["Api.Write"] },
      ],
    };
    expect(analyzeTenantSecurity(snapshot).ownership.map((gap) => gap.label)).toEqual(["Busy", "Abe", "Zed"]);
  });

  it("breaks a tie between equally exposed grants by caller label", () => {
    const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "zed", label: "Zed", kind: "application", ownerIds: ["o"], credential: undefined },
        { ...base.nodes[0]!, id: "abe", label: "Abe", kind: "application", ownerIds: ["o"], credential: undefined },
        { ...base.nodes[0]!, id: "target", label: "Target", kind: "servicePrincipal", ownerIds: ["o"], credential: undefined },
      ],
      edges: [
        { ...template, id: "g-zed", sourceId: "zed", targetId: "target", permissions: ["Api.Read"] },
        { ...template, id: "g-abe", sourceId: "abe", targetId: "target", permissions: ["Api.Read"] },
      ],
    };
    const grants = analyzeTenantSecurity(snapshot).grants;
    expect(grants.map((grant) => grant.exposure)).toEqual(["low", "low"]);
    expect(grants.map((grant) => grant.caller.label)).toEqual(["Abe", "Zed"]);
  });

  it("orders grants by exposure before label, whichever way the snapshot lists them", () => {
    const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const build = (first: string, second: string): TenantSnapshot => ({
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "abe", label: "Abe", kind: "application", ownerIds: ["o"], credential: undefined },
        { ...base.nodes[0]!, id: "zed", label: "Zed", kind: "application", ownerIds: ["o"], credential: undefined },
        { ...base.nodes[0]!, id: "target", label: "Target", kind: "servicePrincipal", ownerIds: ["o"], credential: undefined },
      ],
      // "Abe" sorts first by label but only reads; "Zed" can widen its own access.
      edges: [
        { ...template, id: `g-${first}`, sourceId: first, targetId: "target", permissions: first === "zed" ? ["AppRoleAssignment.ReadWrite.All"] : ["Api.Read"] },
        { ...template, id: `g-${second}`, sourceId: second, targetId: "target", permissions: second === "zed" ? ["AppRoleAssignment.ReadWrite.All"] : ["Api.Read"] },
      ],
    });
    for (const snapshot of [build("abe", "zed"), build("zed", "abe")]) {
      expect(analyzeTenantSecurity(snapshot).grants.map((grant) => grant.caller.label)).toEqual(["Zed", "Abe"]);
    }
  });

  it("lifts a high review item above a review one from either starting order", () => {
    const highFirst = nodesWith([
      { id: "h", label: "Alpha", risk: { level: "high", reason: "h" } },
      { id: "r", label: "Beta", risk: { level: "review", reason: "r" } },
    ]);
    const reviewFirst = nodesWith([
      { id: "r", label: "Alpha", risk: { level: "review", reason: "r" } },
      { id: "h", label: "Beta", risk: { level: "high", reason: "h" } },
    ]);
    expect(analyzeTenantSecurity(highFirst).review.map((item) => item.id)).toEqual(["h", "r"]);
    expect(analyzeTenantSecurity(reviewFirst).review.map((item) => item.id)).toEqual(["h", "r"]);
  });

  it("ranks by grant count even when the busier identity is listed second", () => {
    const template = base.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")!;
    const snapshot: TenantSnapshot = {
      ...base,
      nodes: [
        { ...base.nodes[0]!, id: "quiet", label: "Quiet", kind: "application", ownerIds: [], credential: undefined },
        { ...base.nodes[0]!, id: "busy", label: "Busy", kind: "application", ownerIds: [], credential: undefined },
        { ...base.nodes[0]!, id: "target", label: "Target", kind: "servicePrincipal", ownerIds: ["o"], credential: undefined },
      ],
      edges: [
        { ...template, id: "q1", sourceId: "quiet", targetId: "target", permissions: ["Api.Read"] },
        { ...template, id: "b1", sourceId: "busy", targetId: "target", permissions: ["Api.Read"] },
        { ...template, id: "b2", sourceId: "busy", targetId: "target", permissions: ["Api.Write"] },
      ],
    };
    expect(analyzeTenantSecurity(snapshot).ownership.map((gap) => [gap.id, gap.grantCount]))
      .toEqual([["busy", 2], ["quiet", 1]]);
  });

  it("holds only applications and owner-expecting service principals accountable", () => {
    const snapshot = nodesWith([
      { id: "person", label: "Person", kind: "user", ownerIds: [], metadata: { ownershipExpected: true }, credential: undefined },
      { id: "managed", label: "Deploy MI", kind: "managedIdentity", ownerIds: [], metadata: { ownershipExpected: true }, credential: undefined },
      { id: "group", label: "Group", kind: "group", ownerIds: [], credential: undefined },
      { id: "app", label: "App", kind: "application", ownerIds: [], credential: undefined },
    ]);
    expect(analyzeTenantSecurity(snapshot).ownership.map((gap) => gap.id)).toEqual(["app"]);
  });

  it("puts every high review item before every review item, sorting each group by label", () => {
    const snapshot = nodesWith([
      { id: "r-zed", label: "Zed", risk: { level: "review", reason: "r" } },
      { id: "r-abe", label: "Abe", risk: { level: "review", reason: "r" } },
      { id: "h-zed", label: "Zebra", risk: { level: "high", reason: "h" } },
      { id: "h-abe", label: "Alpha", risk: { level: "high", reason: "h" } },
      { id: "low", label: "Quiet", risk: { level: "low", reason: "l" } },
    ]);
    const review = analyzeTenantSecurity(snapshot).review;
    expect(review.map((item) => item.label)).toEqual(["Alpha", "Zebra", "Abe", "Zed"]);
    // The low-risk node is excluded entirely rather than sorted to the end.
    expect(review.map((item) => item.id)).not.toContain("low");
  });

  it("omits a low-risk object from the review list entirely", () => {
    const snapshot = nodesWith([{ id: "only", label: "Quiet", risk: { level: "low", reason: "nothing to see" } }]);
    expect(analyzeTenantSecurity(snapshot).review).toEqual([]);
  });

  it("carries the reason and kind onto each review item", () => {
    const snapshot = nodesWith([{ id: "one", label: "Risky", kind: "managedIdentity", risk: { level: "high", reason: "Broad access." } }]);
    expect(analyzeTenantSecurity(snapshot).review[0]).toEqual({ id: "one", label: "Risky", kind: "managedIdentity", level: "high", reason: "Broad access." });
  });

  it("counts an unowned identity once per summary, however many grants it has", () => {
    const snapshot = nodesWith([
      { id: "a", label: "A", kind: "application", ownerIds: [], credential: undefined },
      { id: "b", label: "B", kind: "application", ownerIds: ["owner"], credential: undefined },
    ]);
    const view = analyzeTenantSecurity(snapshot);
    expect(view.summary.unowned).toBe(1);
    expect(view.ownership).toHaveLength(1);
    expect(view.ownership[0]!.grantCount).toBe(0);
  });

  it("reports the appId of an unowned application, or null when it has none", () => {
    const snapshot = nodesWith([
      { id: "a", label: "A", kind: "application", ownerIds: [], appId: "app-guid", credential: undefined },
      { id: "b", label: "B", kind: "application", ownerIds: [], appId: undefined, credential: undefined },
    ]);
    const gaps = analyzeTenantSecurity(snapshot).ownership;
    expect(gaps.find((gap) => gap.id === "a")!.appId).toBe("app-guid");
    expect(gaps.find((gap) => gap.id === "b")!.appId).toBeNull();
  });

  it("does not hold a service principal accountable unless ownership is expected", () => {
    const snapshot = nodesWith([
      { id: "first-party", label: "Microsoft Graph", kind: "servicePrincipal", ownerIds: [], metadata: {}, credential: undefined },
      { id: "local", label: "Local App", kind: "servicePrincipal", ownerIds: [], metadata: { ownershipExpected: true }, credential: undefined },
    ]);
    expect(analyzeTenantSecurity(snapshot).ownership.map((gap) => gap.id)).toEqual(["local"]);
  });
});
