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
