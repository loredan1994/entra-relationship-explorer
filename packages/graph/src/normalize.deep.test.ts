import { describe, expect, it } from "vitest";
import { assertTenantBoundary, type RelationshipEdge, type TenantSnapshot } from "@entra-explorer/domain";
import { normalizeTenantScan } from "./normalize";
import {
  SCANNED_AT,
  TENANT,
  application,
  assignment,
  conditionalAccessPolicy,
  crossTenantPartner,
  directoryObject,
  grant,
  rawScan,
  roleDefinition,
  roleSchedule,
  servicePrincipal,
  signIn,
  sourced,
} from "./test-support";
import type { GraphCredentialMetadata } from "./types";

const nodeById = (snapshot: TenantSnapshot, id: string) => snapshot.nodes.find((node) => node.id === id);
const edgesOfType = (snapshot: TenantSnapshot, type: RelationshipEdge["type"]) =>
  snapshot.edges.filter((edge) => edge.type === type);

describe("snapshot envelope", () => {
  it("derives a readable tenant label and generates a snapshot id when none is supplied", () => {
    const snapshot = normalizeTenantScan(rawScan());
    expect(snapshot.tenant.tenantLabel).toBe(`Tenant ${TENANT.slice(0, 8)}`);
    expect(snapshot.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(snapshot.mode).toBe("tenant");
    expect(snapshot.scannedAt).toBe(SCANNED_AT);
  });

  it("prefers a caller-supplied label and id, ignoring surrounding whitespace", () => {
    const snapshot = normalizeTenantScan(rawScan(), { tenantLabel: "  Contoso  ", snapshotId: "snapshot-7" });
    expect(snapshot.tenant.tenantLabel).toBe("Contoso");
    expect(snapshot.id).toBe("snapshot-7");
  });

  it("falls back to the derived label when the supplied label is only whitespace", () => {
    const snapshot = normalizeTenantScan(rawScan(), { tenantLabel: "   " });
    expect(snapshot.tenant.tenantLabel).toBe(`Tenant ${TENANT.slice(0, 8)}`);
  });

  it("marks the snapshot partial only when the scan recorded an error", () => {
    expect(normalizeTenantScan(rawScan({ skippedEndpoints: ["/auditLogs/signIns"] })).completion.status).toBe("complete");
    const partial = normalizeTenantScan(rawScan({ errors: [{ endpoint: "/users", code: "Forbidden", message: "denied detail" }] }));
    expect(partial.completion.status).toBe("partial");
    expect(partial.completion.errors).toEqual(["/users: Forbidden"]);
  });

  it("collapses duplicate endpoint entries in the coverage lists", () => {
    const snapshot = normalizeTenantScan(rawScan({
      collectedEndpoints: ["/applications", "/applications", "/servicePrincipals"],
      skippedEndpoints: ["/users", "/users"],
    }));
    expect(snapshot.completion.collectedEndpoints).toEqual(["/applications", "/servicePrincipals"]);
    expect(snapshot.completion.skippedEndpoints).toEqual(["/users"]);
  });

  it("keeps every emitted record inside a single tenant boundary", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "shared", displayName: "App" }))],
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "shared", displayName: "SP" }))],
      roleDefinitions: [sourced(roleDefinition({ id: "role-1", displayName: "Global Administrator" }))],
      roleAssignments: [sourced(roleSchedule({ id: "ra-1", principalId: "sp-1", roleDefinitionId: "role-1" }))],
    }));
    expect(() => assertTenantBoundary(snapshot)).not.toThrow();
    expect(snapshot.nodes.every((node) => node.tenantId === TENANT)).toBe(true);
    expect(snapshot.edges.every((edge) => edge.tenantId === TENANT)).toBe(true);
  });
});

describe("credential lifecycle", () => {
  const credential = (endDateTime: string | null): GraphCredentialMetadata => ({ keyId: `key-${endDateTime}`, endDateTime });

  function appWithCredentials(credentials: GraphCredentialMetadata[], ownerIds: string[] = []) {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App", passwordCredentials: credentials }))],
      applicationOwners: ownerIds.map((id) => ({ ...sourced(directoryObject({ id, displayName: "Owner" })), targetId: "app-1" })),
    }));
    return nodeById(snapshot, "app-1")!;
  }

  it("reports no credential when none is present or none carries an expiry", () => {
    expect(appWithCredentials([]).credential).toEqual({ status: "none", expiresAt: null });
    expect(appWithCredentials([credential(null)]).credential).toEqual({ status: "none", expiresAt: null });
  });

  it("reports an expiry that has already passed as expired", () => {
    const node = appWithCredentials([credential("2026-08-01T00:00:00.000Z")]);
    expect(node.credential).toEqual({ status: "expired", expiresAt: "2026-08-01T00:00:00.000Z" });
    expect(node.risk).toEqual({ level: "high", reason: "A credential expired on 2026-08-01T00:00:00.000Z." });
  });

  it("treats an expiry exactly at scan time as already expired", () => {
    expect(appWithCredentials([credential(SCANNED_AT)]).credential?.status).toBe("expired");
  });

  it("reports an expiry inside 90 days as expiring and beyond it as healthy", () => {
    const inside = new Date(Date.parse(SCANNED_AT) + 89 * 86_400_000).toISOString();
    const outside = new Date(Date.parse(SCANNED_AT) + 91 * 86_400_000).toISOString();
    expect(appWithCredentials([credential(inside)]).credential?.status).toBe("expiring");
    expect(appWithCredentials([credential(inside)]).risk.level).toBe("review");
    expect(appWithCredentials([credential(outside)]).credential?.status).toBe("healthy");
  });

  it("treats the 90-day boundary itself as expiring", () => {
    const boundary = new Date(Date.parse(SCANNED_AT) + 90 * 86_400_000).toISOString();
    expect(appWithCredentials([credential(boundary)]).credential?.status).toBe("expiring");
  });

  it("reports the earliest expiry when several credentials exist", () => {
    const node = appWithCredentials([
      credential("2027-06-01T00:00:00.000Z"),
      credential("2026-12-01T00:00:00.000Z"),
      credential("2028-01-01T00:00:00.000Z"),
    ]);
    expect(node.credential?.expiresAt).toBe("2026-12-01T00:00:00.000Z");
  });

  it("ignores an unparseable expiry timestamp", () => {
    expect(appWithCredentials([credential("not-a-date")]).credential).toEqual({ status: "none", expiresAt: null });
  });

  it("rates a healthy owned application low and an unowned one for review", () => {
    const healthy = new Date(Date.parse(SCANNED_AT) + 400 * 86_400_000).toISOString();
    expect(appWithCredentials([credential(healthy)], ["owner-1"]).risk).toEqual({
      level: "low",
      reason: "An owner is recorded and no credential expires within 90 days.",
    });
    expect(appWithCredentials([credential(healthy)], []).risk).toEqual({
      level: "review",
      reason: "No owner was returned in this scan.",
    });
  });

  it("lets an expired credential outrank a missing owner in the stated reason", () => {
    expect(appWithCredentials([credential("2020-01-01T00:00:00.000Z")], []).risk.level).toBe("high");
  });
});

describe("application and identity nodes", () => {
  it("classifies a managed identity separately from an ordinary enterprise application", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "mi-1", appId: "mi-app", displayName: "Deploy MI", servicePrincipalType: "ManagedIdentity" })),
        sourced(servicePrincipal({ id: "sp-1", appId: "sp-app", displayName: "Vendor SaaS", servicePrincipalType: "Application" })),
      ],
    }));
    const managed = nodeById(snapshot, "mi-1")!;
    expect(managed.kind).toBe("managedIdentity");
    expect(managed.description).toContain("Managed workload identity");
    expect(managed.metadata?.ownershipExpected).toBe(true);
    expect(nodeById(snapshot, "sp-1")!.kind).toBe("servicePrincipal");
  });

  it("matches the managed-identity type without regard to letter case", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "mi-1", appId: "a", displayName: "MI", servicePrincipalType: "managedidentity" }))],
    }));
    expect(nodeById(snapshot, "mi-1")!.kind).toBe("managedIdentity");
  });

  it("does not expect a local owner for a publisher-managed first-party identity", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-graph", appId: "first-party", displayName: "Microsoft Graph", publisherName: "Microsoft" }))],
    }));
    const node = nodeById(snapshot, "sp-graph")!;
    expect(node.metadata?.ownershipExpected).toBe(false);
    expect(node.publisher).toBe("Microsoft");
    expect(node.risk).toEqual({
      level: "low",
      reason: "This tenant-local enterprise application is publisher-managed; a local owner is not expected.",
    });
  });

  it("expects an owner once a matching local blueprint exists for the same appId", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "shared", displayName: "Blueprint" }))],
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "shared", displayName: "Runtime" }))],
    }));
    expect(nodeById(snapshot, "sp-1")!.metadata?.ownershipExpected).toBe(true);
    expect(nodeById(snapshot, "sp-1")!.risk.level).toBe("review");
  });

  it("carries the publisher domain from the blueprint onto the application node", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App", publisherDomain: "contoso.test" }))],
    }));
    expect(nodeById(snapshot, "app-1")).toMatchObject({ kind: "application", appId: "a", publisher: "contoso.test" });
  });

  it("records each owner once even when the scan returns duplicates", () => {
    const owner = { ...sourced(directoryObject({ id: "owner-1", displayName: "Owner" })), targetId: "app-1" };
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App" }))],
      applicationOwners: [owner, owner],
    }));
    expect(nodeById(snapshot, "app-1")!.ownerIds).toEqual(["owner-1"]);
    expect(edgesOfType(snapshot, "OWNS")).toHaveLength(1);
  });
});

describe("app roles", () => {
  const resource = servicePrincipal({
    id: "sp-api", appId: "api", displayName: "Payroll API",
    appRoles: [
      { id: "role-read", value: "Api.Read", displayName: "Read", isEnabled: true },
      { id: "role-legacy", value: null, displayName: "Legacy role", isEnabled: false },
      { id: "role-bare-identifier", value: null, displayName: null, isEnabled: true },
    ],
  });

  it("exposes one node per app role, naming it by value, display name, or truncated id", () => {
    const snapshot = normalizeTenantScan(rawScan({ servicePrincipals: [sourced(resource)] }));
    expect(nodeById(snapshot, "app-role:sp-api:role-read")!.label).toBe("Api.Read");
    expect(nodeById(snapshot, "app-role:sp-api:role-legacy")!.label).toBe("Legacy role");
    expect(nodeById(snapshot, "app-role:sp-api:role-bare-identifier")!.label).toBe("App role role-bar");
  });

  it("marks a disabled role for review while an enabled one carries no advisory", () => {
    const snapshot = normalizeTenantScan(rawScan({ servicePrincipals: [sourced(resource)] }));
    expect(nodeById(snapshot, "app-role:sp-api:role-legacy")!.risk).toEqual({
      level: "review",
      reason: "The role is disabled but may remain referenced by assignments.",
    });
    expect(nodeById(snapshot, "app-role:sp-api:role-read")!.risk.level).toBe("low");
    expect(nodeById(snapshot, "app-role:sp-api:role-read")!.metadata).toMatchObject({
      appRoleId: "role-read", resourceServicePrincipalId: "sp-api", enabled: true,
    });
  });

  it("draws an EXPOSES_APP_ROLE edge from the resource to each role it publishes", () => {
    const snapshot = normalizeTenantScan(rawScan({ servicePrincipals: [sourced(resource)] }));
    const exposed = edgesOfType(snapshot, "EXPOSES_APP_ROLE");
    expect(exposed).toHaveLength(3);
    expect(exposed.every((edge) => edge.sourceId === "sp-api")).toBe(true);
    expect(exposed.find((edge) => edge.targetId === "app-role:sp-api:role-read")?.permissions).toEqual(["Api.Read"]);
  });

  it("draws GRANTED_APP_ROLE only when the assignment names a role the resource actually exposes", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource), sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "granted", appRoleId: "role-read", principalId: "sp-client", resourceId: "sp-api" })),
        sourced(assignment({ id: "phantom", appRoleId: "role-unknown", principalId: "sp-client", resourceId: "sp-api" })),
      ],
    }));
    const granted = edgesOfType(snapshot, "GRANTED_APP_ROLE");
    expect(granted).toHaveLength(1);
    expect(granted[0]).toMatchObject({ sourceId: "sp-client", targetId: "app-role:sp-api:role-read", permissions: ["role-read"] });
  });
});

describe("assignment edges", () => {
  const resource = servicePrincipal({
    id: "sp-api", appId: "api", displayName: "Payroll API",
    appRoles: [
      { id: "role-read", value: "Api.Read", isEnabled: true },
      { id: "role-write", value: "Api.Write", isEnabled: true },
      { id: "role-named", value: null, displayName: "Named only", isEnabled: true },
    ],
  });

  it("merges every role a workload identity holds on one resource into a single CAN_CALL_AS_APP edge", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource), sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "role-read", principalId: "sp-client", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-2", appRoleId: "role-write", principalId: "sp-client", resourceId: "sp-api" })),
      ],
    }));
    const calls = edgesOfType(snapshot, "CAN_CALL_AS_APP");
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      sourceId: "sp-client", targetId: "sp-api", plainLabel: "Can call", permissions: ["Api.Read", "Api.Write"],
    });
    expect(calls[0]!.evidence.sourceRecordIds).toEqual(["a-1", "a-2"]);
    expect(calls[0]!.evidence.completeness).toBe("complete");
  });

  it("classifies a user or group assignment as ASSIGNED_TO rather than a workload call", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource)],
      appRoleAssignments: [
        sourced(assignment({ id: "a-user", appRoleId: "role-read", principalId: "user-1", principalType: "User", resourceId: "sp-api", principalDisplayName: "Avery" })),
        sourced(assignment({ id: "a-group", appRoleId: "role-read", principalId: "group-1", principalType: "Group", resourceId: "sp-api", principalDisplayName: "Finance" })),
      ],
    }));
    const assigned = edgesOfType(snapshot, "ASSIGNED_TO");
    expect(assigned).toHaveLength(2);
    expect(assigned.every((edge) => edge.plainLabel === "Assigned to use")).toBe(true);
    expect(nodeById(snapshot, "user-1")!.kind).toBe("user");
    expect(nodeById(snapshot, "group-1")!.kind).toBe("group");
  });

  it("derives the principal kind from the assignment principal type, defaulting to a person", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource)],
      appRoleAssignments: [
        sourced(assignment({ id: "a-sp", appRoleId: "role-read", principalId: "p-sp", principalType: "serviceprincipal", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-grp", appRoleId: "role-read", principalId: "p-grp", principalType: "GROUP", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-other", appRoleId: "role-read", principalId: "p-other", principalType: "Device", resourceId: "sp-api" })),
      ],
    }));
    expect(nodeById(snapshot, "p-sp")!.kind).toBe("servicePrincipal");
    expect(nodeById(snapshot, "p-grp")!.kind).toBe("group");
    expect(nodeById(snapshot, "p-other")!.kind).toBe("user");
  });

  it("labels a principal discovered only from an assignment as unresolved", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource)],
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "role-read", principalId: "ghost", principalType: "User", resourceId: "sp-api" }))],
    }));
    const ghost = nodeById(snapshot, "ghost")!;
    expect(ghost.label).toBe("Unresolved user");
    expect(ghost.description).toContain("limited information");
    expect(ghost.risk.level).toBe("review");
  });

  it("prefers a supplied principal display name over the unresolved placeholder", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource)],
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "role-read", principalId: "known", principalType: "User", resourceId: "sp-api", principalDisplayName: "  Avery Analyst  " }))],
    }));
    expect(nodeById(snapshot, "known")!.label).toBe("Avery Analyst");
    expect(nodeById(snapshot, "known")!.description).toContain("app-role assignment");
  });

  it("marks the edge unresolved when the resource is outside the collected inventory", () => {
    const snapshot = normalizeTenantScan(rawScan({
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "role-read", principalId: "sp-client", resourceId: "sp-missing", resourceDisplayName: "Absent API" }))],
    }));
    const edge = edgesOfType(snapshot, "CAN_CALL_AS_APP")[0]!;
    expect(edge.evidence.completeness).toBe("unresolved");
    expect(edge.permissions).toEqual(["Unresolved role role-read"]);
    expect(nodeById(snapshot, "sp-missing")!.label).toBe("Absent API");
  });

  it("names an unresolved resource generically when the scan carried no display name", () => {
    const snapshot = normalizeTenantScan(rawScan({
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "role-read", principalId: "sp-client", resourceId: "sp-missing" }))],
    }));
    expect(nodeById(snapshot, "sp-missing")!.label).toBe("Unresolved tenant identity");
  });

  it("falls back to a role display name when the role exposes no value", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(resource)],
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "role-named", principalId: "sp-client", resourceId: "sp-api" }))],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_AS_APP")[0]!.permissions).toEqual(["Named only"]);
  });
});

describe("delegated grant edges", () => {
  it("splits the consent scope string into discrete permissions without duplicates", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" })),
        sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" })),
      ],
      oauth2PermissionGrants: [sourced(grant({ id: "g-1", clientId: "sp-client", resourceId: "sp-api", scope: "  Mail.Read   User.Read Mail.Read " }))],
    }));
    const edge = edgesOfType(snapshot, "CAN_CALL_DELEGATED")[0]!;
    expect(edge.permissions).toEqual(["Mail.Read", "User.Read"]);
    expect(edge.evidence.completeness).toBe("complete");
    expect(edge.plainLabel).toBe("Can call with a signed-in person");
  });

  it("yields no permissions for an empty consent scope", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" })),
        sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" })),
      ],
      oauth2PermissionGrants: [sourced(grant({ id: "g-1", clientId: "sp-client", resourceId: "sp-api", scope: "   " }))],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_DELEGATED")[0]!.permissions).toEqual([]);
  });

  it("marks the grant unresolved when either side is missing from the inventory", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" }))],
      oauth2PermissionGrants: [sourced(grant({ id: "g-1", clientId: "sp-client", resourceId: "sp-absent", scope: "Mail.Read" }))],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_DELEGATED")[0]!.evidence.completeness).toBe("unresolved");
    expect(nodeById(snapshot, "sp-absent")!.label).toBe("Unresolved tenant identity");
  });
});

describe("ownership and membership edges", () => {
  it("drops an ownership record whose target was never collected", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applicationOwners: [{ ...sourced(directoryObject({ id: "owner-1", displayName: "Owner" })), targetId: "app-absent" }],
    }));
    expect(edgesOfType(snapshot, "OWNS")).toHaveLength(0);
  });

  it("marks ownership partial when the owner came back without a display name", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App" }))],
      applicationOwners: [{ ...sourced(directoryObject({ id: "owner-1" })), targetId: "app-1" }],
    }));
    const edge = edgesOfType(snapshot, "OWNS")[0]!;
    expect(edge.evidence.completeness).toBe("partial");
    expect(nodeById(snapshot, "owner-1")!.label).toBe("Unresolved user");
  });

  it("classifies a directory object by its OData type and flags guests as external", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [
        sourced(directoryObject({ id: "user-1", displayName: "Member", userType: "Member", "@odata.type": "#microsoft.graph.user" })),
        sourced(directoryObject({ id: "user-2", displayName: "Partner", userType: "Guest", "@odata.type": "#microsoft.graph.user" })),
      ],
      groups: [sourced(directoryObject({ id: "group-1", displayName: "Team", "@odata.type": "#microsoft.graph.group" }))],
      servicePrincipalOwners: [{ ...sourced(directoryObject({ id: "sp-owner", displayName: "Owning SP", "@odata.type": "#microsoft.graph.servicePrincipal" })), targetId: "absent" }],
    }));
    expect(nodeById(snapshot, "user-1")!.isExternal).toBe(false);
    expect(nodeById(snapshot, "user-2")!.isExternal).toBe(true);
    expect(nodeById(snapshot, "group-1")!.kind).toBe("group");
    expect(nodeById(snapshot, "sp-owner")!.kind).toBe("servicePrincipal");
  });

  it("treats an object with no OData type as a person", () => {
    const snapshot = normalizeTenantScan(rawScan({ users: [sourced(directoryObject({ id: "user-1", displayName: "Nameless type" }))] }));
    expect(nodeById(snapshot, "user-1")!.kind).toBe("user");
  });

  it("links each collected membership to its group and drops memberships of unknown groups", () => {
    const snapshot = normalizeTenantScan(rawScan({
      groups: [sourced(directoryObject({ id: "group-1", displayName: "Finance", "@odata.type": "#microsoft.graph.group" }))],
      groupMemberships: [
        { ...sourced(directoryObject({ id: "user-1", displayName: "Avery" })), groupId: "group-1" },
        { ...sourced(directoryObject({ id: "user-2", displayName: "Blair" })), groupId: "group-absent" },
      ],
    }));
    const memberships = edgesOfType(snapshot, "MEMBER_OF");
    expect(memberships).toHaveLength(1);
    expect(memberships[0]).toMatchObject({ sourceId: "user-1", targetId: "group-1", plainLabel: "Member of" });
    expect(memberships[0]!.evidence.completeness).toBe("complete");
  });

  it("marks a membership partial when the member arrived without a display name", () => {
    const snapshot = normalizeTenantScan(rawScan({
      groups: [sourced(directoryObject({ id: "group-1", displayName: "Finance", "@odata.type": "#microsoft.graph.group" }))],
      groupMemberships: [{ ...sourced(directoryObject({ id: "user-1" })), groupId: "group-1" }],
    }));
    expect(edgesOfType(snapshot, "MEMBER_OF")[0]!.evidence.completeness).toBe("partial");
  });
});

describe("administrative role edges", () => {
  const globalAdmin = roleDefinition({ id: "role-ga", displayName: "Global Administrator", templateId: "template-ga", isBuiltIn: true });

  it("separates an active assignment from a PIM eligibility", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleDefinitions: [sourced(globalAdmin)],
      roleAssignments: [sourced(roleSchedule({ id: "ra-1", principalId: "user-1", roleDefinitionId: "role-ga", directoryScopeId: "/" }))],
      roleEligibilities: [sourced(roleSchedule({ id: "re-1", principalId: "user-2", roleDefinitionId: "role-ga" }))],
    }));
    expect(edgesOfType(snapshot, "ACTIVE_IN_ROLE")[0]).toMatchObject({ sourceId: "user-1", targetId: "role-ga", plainLabel: "Active in role", permissions: ["/"] });
    expect(edgesOfType(snapshot, "ELIGIBLE_FOR_ROLE")[0]).toMatchObject({ sourceId: "user-2", targetId: "role-ga", plainLabel: "Eligible for role", permissions: [] });
  });

  it("records the role definition as a reviewable administrative role node", () => {
    const snapshot = normalizeTenantScan(rawScan({ roleDefinitions: [sourced(globalAdmin)] }));
    expect(nodeById(snapshot, "role-ga")).toMatchObject({
      kind: "directoryRole",
      label: "Global Administrator",
      metadata: { templateId: "template-ga", isBuiltIn: true },
      risk: { level: "review" },
    });
  });

  it("defaults absent role definition metadata rather than emitting undefined", () => {
    const snapshot = normalizeTenantScan(rawScan({ roleDefinitions: [sourced(roleDefinition({ id: "role-x", displayName: "Reports Reader" }))] }));
    expect(nodeById(snapshot, "role-x")!.metadata).toEqual({ templateId: null, isBuiltIn: false });
  });

  it("creates the principal node when a role schedule references an uncollected identity", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleDefinitions: [sourced(globalAdmin)],
      roleAssignments: [sourced(roleSchedule({ id: "ra-1", principalId: "unseen-user", roleDefinitionId: "role-ga" }))],
    }));
    expect(nodeById(snapshot, "unseen-user")).toMatchObject({ kind: "user", label: "Unresolved user" });
    expect(edgesOfType(snapshot, "ACTIVE_IN_ROLE")).toHaveLength(1);
  });

  it("drops a schedule that points at a role definition the scan never collected", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleAssignments: [sourced(roleSchedule({ id: "ra-1", principalId: "user-1", roleDefinitionId: "role-absent" }))],
    }));
    expect(edgesOfType(snapshot, "ACTIVE_IN_ROLE")).toHaveLength(0);
  });
});

describe("Conditional Access policy edges", () => {
  const policy = conditionalAccessPolicy({
    id: "policy-1", displayName: "Require MFA", state: "enabled",
    conditions: { users: { includeUsers: ["user-1", "All"], includeGroups: ["group-1"] }, applications: { includeApplications: ["client-app-id", "Office365"] } },
    grantControls: { builtInControls: ["mfa"], operator: "OR" },
  });

  const scanWithPolicy = () => rawScan({
    servicePrincipals: [sourced(servicePrincipal({ id: "sp-client", appId: "client-app-id", displayName: "Client" }))],
    users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
    groups: [sourced(directoryObject({ id: "group-1", displayName: "Finance", "@odata.type": "#microsoft.graph.group" }))],
    conditionalAccessPolicies: [sourced(policy)],
  });

  it("governs each named user, group, and application while ignoring catch-all tokens", () => {
    const snapshot = normalizeTenantScan(scanWithPolicy());
    const governed = edgesOfType(snapshot, "GOVERNED_BY");
    expect(governed.map((edge) => edge.sourceId).sort()).toEqual(["group-1", "sp-client", "user-1"]);
    expect(governed.every((edge) => edge.targetId === "policy-1")).toBe(true);
    expect(governed[0]!.permissions).toEqual(["mfa"]);
  });

  it("resolves an application by appId onto its tenant service principal", () => {
    const snapshot = normalizeTenantScan(scanWithPolicy());
    expect(edgesOfType(snapshot, "GOVERNED_BY").some((edge) => edge.sourceId === "sp-client")).toBe(true);
  });

  it("rates an enabled policy low and any other state for review", () => {
    const snapshot = normalizeTenantScan(scanWithPolicy());
    expect(nodeById(snapshot, "policy-1")).toMatchObject({
      kind: "policy",
      metadata: { policyType: "conditionalAccess", state: "enabled", controls: "mfa" },
      risk: { level: "low" },
    });
    const reportOnly = normalizeTenantScan(rawScan({
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({ id: "policy-2", displayName: "Pilot", state: "enabledForReportingButNotEnforced" }))],
    }));
    expect(nodeById(reportOnly, "policy-2")!.risk).toEqual({
      level: "review",
      reason: "Policy state is enabledForReportingButNotEnforced.",
    });
    expect(nodeById(reportOnly, "policy-2")!.metadata?.controls).toBe("none");
  });

  it("emits no governance edge for a subject the scan never collected", () => {
    const snapshot = normalizeTenantScan(rawScan({
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({
        id: "policy-3", displayName: "Orphan", state: "enabled",
        conditions: { users: { includeUsers: ["ghost-user"] } },
      }))],
    }));
    expect(edgesOfType(snapshot, "GOVERNED_BY")).toHaveLength(0);
  });

  it("does not repeat a governance edge when a subject is listed twice", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({
        id: "policy-4", displayName: "Dupe", state: "enabled",
        conditions: { users: { includeUsers: ["user-1"], includeGroups: ["user-1"] } },
      }))],
    }));
    expect(edgesOfType(snapshot, "GOVERNED_BY")).toHaveLength(1);
  });
});

describe("observed activity edges", () => {
  it("records an observed call as unconfigured evidence inside a 30-day window", () => {
    const snapshot = normalizeTenantScan(rawScan({
      signIns: [sourced(signIn({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-1", resourceServicePrincipalId: "sp-2", appDisplayName: "Caller", resourceDisplayName: "Resource" }))],
    }));
    const observed = edgesOfType(snapshot, "OBSERVED_CALL")[0]!;
    expect(observed).toMatchObject({ sourceId: "sp-1", targetId: "sp-2", plainLabel: "Called recently", permissions: [] });
    expect(observed.evidence.configured).toBe(false);
    expect(observed.evidence.observed).toEqual({
      lastSeenAt: "2026-08-20T09:00:00Z",
      windowStartsAt: new Date(Date.parse(SCANNED_AT) - 30 * 86_400_000).toISOString(),
    });
  });

  it("names identities discovered only from sign-in activity", () => {
    const snapshot = normalizeTenantScan(rawScan({
      signIns: [sourced(signIn({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-1", resourceServicePrincipalId: "sp-2", appDisplayName: "Caller App", resourceDisplayName: null }))],
    }));
    expect(nodeById(snapshot, "sp-1")!.label).toBe("Caller App");
    expect(nodeById(snapshot, "sp-2")!.label).toBe("Unresolved tenant identity");
  });

  it("ignores a sign-in that cannot name both sides of the call", () => {
    const snapshot = normalizeTenantScan(rawScan({
      signIns: [
        sourced(signIn({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: null, resourceServicePrincipalId: "sp-2" })),
        sourced(signIn({ id: "s-2", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-1", resourceServicePrincipalId: null })),
      ],
    }));
    expect(edgesOfType(snapshot, "OBSERVED_CALL")).toHaveLength(0);
  });

  it("does not overwrite a collected identity with an activity placeholder", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "a", displayName: "Known Caller" }))],
      signIns: [sourced(signIn({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-1", resourceServicePrincipalId: "sp-2", appDisplayName: "Stale Name" }))],
    }));
    expect(nodeById(snapshot, "sp-1")!.label).toBe("Known Caller");
  });
});

describe("cross-tenant trust edges", () => {
  it("creates a partner tenant, its policy node, and the edge naming each accepted claim", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({
        tenantId: "33333333-3333-4333-8333-333333333333",
        inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: true },
        isInMultiTenantOrganization: true,
      }))],
    }));
    const partner = nodeById(snapshot, "external-tenant:33333333-3333-4333-8333-333333333333")!;
    expect(partner).toMatchObject({ kind: "externalTenant", label: "External tenant 33333333", isExternal: true });
    expect(partner.metadata).toMatchObject({ trustsMfa: true, trustsCompliantDevice: false, trustsHybridJoinedDevice: true, multiTenantOrganization: true });
    expect(partner.risk.level).toBe("review");
    expect(nodeById(snapshot, "cross-tenant-policy:33333333-3333-4333-8333-333333333333")).toMatchObject({ kind: "policy", metadata: { policyType: "crossTenantAccess" } });
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual(["MFA", "hybrid joined device"]);
  });

  it("rates a partner trusted only for compliant devices as review, naming that claim alone", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({
        tenantId: "55555555-5555-4555-8555-555555555555",
        inboundTrust: { isMfaAccepted: false, isCompliantDeviceAccepted: true, isHybridAzureADJoinedDeviceAccepted: false },
      }))],
    }));
    const partner = nodeById(snapshot, "external-tenant:55555555-5555-4555-8555-555555555555")!;
    expect(partner.metadata).toMatchObject({ trustsMfa: false, trustsCompliantDevice: true, trustsHybridJoinedDevice: false });
    expect(partner.risk.level).toBe("review");
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual(["compliant device"]);
  });

  it("rates a partner trusted only for hybrid joined devices as review, naming that claim alone", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({
        tenantId: "66666666-6666-4666-8666-666666666666",
        inboundTrust: { isMfaAccepted: false, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: true },
      }))],
    }));
    const partner = nodeById(snapshot, "external-tenant:66666666-6666-4666-8666-666666666666")!;
    expect(partner.metadata).toMatchObject({ trustsMfa: false, trustsCompliantDevice: false, trustsHybridJoinedDevice: true });
    expect(partner.risk.level).toBe("review");
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual(["hybrid joined device"]);
  });

  it("rates a partner that accepts every inbound claim as review, naming all three", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({
        tenantId: "77777777-7777-4777-8777-777777777777",
        inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: true, isHybridAzureADJoinedDeviceAccepted: true },
      }))],
    }));
    expect(nodeById(snapshot, "external-tenant:77777777-7777-4777-8777-777777777777")!.risk.level).toBe("review");
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual(["MFA", "compliant device", "hybrid joined device"]);
  });

  it("rates a partner whose inbound trust accepts nothing as low risk", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({
        tenantId: "88888888-8888-4888-8888-888888888888",
        inboundTrust: { isMfaAccepted: false, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: false },
      }))],
    }));
    expect(nodeById(snapshot, "external-tenant:88888888-8888-4888-8888-888888888888")!.risk.level).toBe("low");
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual([]);
  });

  it("rates a partner that accepts no inbound claim as low risk with no named permissions", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: "44444444-4444-4444-8444-444444444444", inboundTrust: null }))],
    }));
    expect(nodeById(snapshot, "external-tenant:44444444-4444-4444-8444-444444444444")!.risk.level).toBe("low");
    expect(edgesOfType(snapshot, "CROSS_TENANT_ACCESS")[0]!.permissions).toEqual([]);
  });
});

describe("relationship identity", () => {
  it("derives stable edge ids so an unchanged scan normalizes identically", () => {
    const build = () => normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "shared", displayName: "App" }))],
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "shared", displayName: "SP" }))],
    }), { snapshotId: "fixed" });
    expect(build().edges.map((edge) => edge.id)).toEqual(build().edges.map((edge) => edge.id));
    expect(edgesOfType(build(), "INSTANTIATES_AS")[0]).toMatchObject({ sourceId: "app-1", targetId: "sp-1", plainLabel: "Creates a tenant identity" });
  });

  it("gives different relationships different identifiers", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [
        sourced(application({ id: "app-1", appId: "one", displayName: "One" })),
        sourced(application({ id: "app-2", appId: "two", displayName: "Two" })),
      ],
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-1", appId: "one", displayName: "SP One" })),
        sourced(servicePrincipal({ id: "sp-2", appId: "two", displayName: "SP Two" })),
      ],
    }));
    const ids = snapshot.edges.map((edge) => edge.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("records the joining endpoints in the instantiation evidence", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [{ endpoint: "/applications", record: application({ id: "app-1", appId: "shared", displayName: "App" }) }],
      servicePrincipals: [{ endpoint: "/servicePrincipals", record: servicePrincipal({ id: "sp-1", appId: "shared", displayName: "SP" }) }],
    }));
    expect(edgesOfType(snapshot, "INSTANTIATES_AS")[0]!.evidence.sourceEndpoint).toBe("/applications + /servicePrincipals (matching appId)");
  });

  it("emits no instantiation edge when no blueprint matches the identity appId", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "orphan", displayName: "SP" }))],
    }));
    expect(edgesOfType(snapshot, "INSTANTIATES_AS")).toHaveLength(0);
  });
});

describe("node precedence and fallbacks", () => {
  it("keeps the first record that described an object, whichever relationship follows", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App" }))],
      users: [sourced(directoryObject({ id: "user-1", displayName: "Avery Analyst", "@odata.type": "#microsoft.graph.user" }))],
      applicationOwners: [{ ...sourced(directoryObject({ id: "user-1", displayName: "Stale Name" })), targetId: "app-1" }],
    }));
    expect(nodeById(snapshot, "user-1")).toMatchObject({ label: "Avery Analyst", kind: "user" });
  });

  it("describes a group member from the membership record rather than a later assignment", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" }))],
      groups: [sourced({ id: "group-1", displayName: "Finance", securityEnabled: true })],
      groupMemberships: [{ ...sourced(directoryObject({ id: "user-1", displayName: "Avery" })), groupId: "group-1" }],
      appRoleAssignments: [sourced(assignment({ id: "assign-1", appRoleId: "role-1", principalId: "user-1", resourceId: "sp-api", principalType: "User" }))],
    }));
    expect(nodeById(snapshot, "user-1")).toMatchObject({
      label: "Avery",
      description: "Directory object collected from an ownership relationship.",
      risk: { level: "low", reason: "No advisory entity rule applies." },
      ownerIds: [],
    });
  });

  it("falls back to an unresolved label when a directory object carries only blank text", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App" }))],
      applicationOwners: [{ ...sourced(directoryObject({ id: "blank", displayName: "   " })), targetId: "app-1" }],
    }));
    expect(nodeById(snapshot, "blank")?.label).toBe("Unresolved user");
  });

  it("reads the object kind from the Graph type annotation", () => {
    const snapshot = normalizeTenantScan(rawScan({
      groups: [sourced({ id: "group-1", displayName: "Finance", securityEnabled: true })],
      groupMemberships: [
        { ...sourced(directoryObject({ id: "member-group", displayName: "Nested", "@odata.type": "#microsoft.graph.group" })), groupId: "group-1" },
        { ...sourced(directoryObject({ id: "member-sp", displayName: "Workload", "@odata.type": "#microsoft.graph.servicePrincipal" })), groupId: "group-1" },
        { ...sourced(directoryObject({ id: "member-user", displayName: "Person", "@odata.type": "#microsoft.graph.user" })), groupId: "group-1" },
        { ...sourced(directoryObject({ id: "member-plain", displayName: "Unknown kind" })), groupId: "group-1" },
      ],
    }));
    expect(nodeById(snapshot, "member-group")?.kind).toBe("group");
    expect(nodeById(snapshot, "member-sp")?.kind).toBe("servicePrincipal");
    expect(nodeById(snapshot, "member-user")?.kind).toBe("user");
    expect(nodeById(snapshot, "member-plain")?.kind).toBe("user");
  });

  it("invents a reviewable placeholder for an identity a relationship references but the inventory lacks", () => {
    const snapshot = normalizeTenantScan(rawScan({
      oauth2PermissionGrants: [sourced(grant({ id: "g-1", clientId: "sp-absent", resourceId: "sp-missing", scope: "Mail.Read" }))],
    }));
    expect(nodeById(snapshot, "sp-absent")).toMatchObject({
      kind: "servicePrincipal",
      label: "Unresolved tenant identity",
      ownerIds: [],
      risk: { level: "review", reason: "The source object is incomplete; inspect scan errors and skipped endpoints." },
    });
    expect(nodeById(snapshot, "sp-missing")?.kind).toBe("servicePrincipal");
  });

  it("uses the display name a sign-in carried for a workload missing from the inventory, unless it is blank", () => {
    const snapshot = normalizeTenantScan(rawScan({
      signIns: [
        sourced(signIn({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-a", resourceServicePrincipalId: "sp-b", appDisplayName: "Caller App", resourceDisplayName: "   " })),
      ],
    }));
    expect(nodeById(snapshot, "sp-a")?.label).toBe("Caller App");
    expect(nodeById(snapshot, "sp-b")?.label).toBe("Unresolved tenant identity");
  });

  it("names an assignment principal from the assignment when nothing else described it", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "role-1", principalId: "grp-1", resourceId: "sp-api", principalType: "Group", principalDisplayName: "Finance" })),
        sourced(assignment({ id: "a-2", appRoleId: "role-1", principalId: "blank-1", resourceId: "sp-api", principalType: "User", principalDisplayName: "  " })),
      ],
    }));
    expect(nodeById(snapshot, "grp-1")).toMatchObject({
      kind: "group", label: "Finance", description: "Directory principal collected from an app-role assignment.",
      risk: { level: "review" },
    });
    expect(nodeById(snapshot, "blank-1")).toMatchObject({ kind: "user", label: "Unresolved user" });
  });
});

describe("service principal classification", () => {
  const withServicePrincipal = (partial: Parameters<typeof servicePrincipal>[0], applications: ReturnType<typeof application>[] = []) =>
    normalizeTenantScan(rawScan({
      applications: applications.map((record) => sourced(record)),
      servicePrincipals: [sourced(servicePrincipal(partial))],
    }));

  it("records the reported principal type and defaults to Application when Graph omitted it", () => {
    const reported = withServicePrincipal({ id: "sp-1", appId: "a", displayName: "Vendor", servicePrincipalType: "Legacy" });
    expect(nodeById(reported, "sp-1")?.metadata).toMatchObject({ servicePrincipalType: "Legacy" });
    const missing = withServicePrincipal({ id: "sp-2", appId: "b", displayName: "Vendor" });
    expect(nodeById(missing, "sp-2")?.metadata).toMatchObject({ servicePrincipalType: "Application" });
  });

  it("expects an owner only when the tenant also holds the application registration", () => {
    const local = withServicePrincipal({ id: "sp-1", appId: "shared", displayName: "Local" }, [application({ id: "app-1", appId: "shared", displayName: "App" })]);
    expect(nodeById(local, "sp-1")?.metadata).toMatchObject({ ownershipExpected: true });
    expect(nodeById(local, "sp-1")?.risk).toEqual({ level: "review", reason: "No owner was returned in this scan." });
    const foreign = withServicePrincipal({ id: "sp-2", appId: "vendor", displayName: "Vendor" }, [application({ id: "app-1", appId: "shared", displayName: "App" })]);
    expect(nodeById(foreign, "sp-2")?.metadata).toMatchObject({ ownershipExpected: false });
    expect(nodeById(foreign, "sp-2")?.risk).toEqual({
      level: "low",
      reason: "This tenant-local enterprise application is publisher-managed; a local owner is not expected.",
    });
  });

  it("weighs key credentials as well as password credentials", () => {
    const keyOnly = withServicePrincipal({
      id: "sp-1", appId: "shared", displayName: "Local",
      keyCredentials: [{ keyId: "k-1", endDateTime: "2026-09-05T00:00:00.000Z" }],
    }, [application({ id: "app-1", appId: "shared", displayName: "App" })]);
    expect(nodeById(keyOnly, "sp-1")?.credential).toEqual({ status: "expiring", expiresAt: "2026-09-05T00:00:00.000Z" });
    expect(nodeById(keyOnly, "sp-1")?.risk).toEqual({ level: "review", reason: "A credential expires within 90 days (2026-09-05T00:00:00.000Z)." });
    const passwordOnly = withServicePrincipal({
      id: "sp-2", appId: "shared", displayName: "Local",
      passwordCredentials: [{ keyId: "p-1", endDateTime: "2026-09-05T00:00:00.000Z" }],
    }, [application({ id: "app-1", appId: "shared", displayName: "App" })]);
    expect(nodeById(passwordOnly, "sp-2")?.credential).toEqual({ status: "expiring", expiresAt: "2026-09-05T00:00:00.000Z" });
  });
});

describe("relationship resolution", () => {
  it("reads the principal type without regard to case when choosing the relationship", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r-1", principalId: "sp-1", resourceId: "sp-api", principalType: "SERVICEPRINCIPAL" })),
        sourced(assignment({ id: "a-2", appRoleId: "r-1", principalId: "user-1", resourceId: "sp-api", principalType: "user" })),
      ],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_AS_APP").map((edge) => edge.sourceId)).toEqual(["sp-1"]);
    expect(edgesOfType(snapshot, "ASSIGNED_TO").map((edge) => edge.sourceId)).toEqual(["user-1"]);
  });

  it("marks an assignment unresolved when the resource identity is missing entirely", () => {
    const snapshot = normalizeTenantScan(rawScan({
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "r-1", principalId: "sp-1", resourceId: "sp-absent" }))],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_AS_APP")[0]?.evidence.completeness).toBe("unresolved");
  });

  it("marks an assignment unresolved when only some of its roles are published", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({
        id: "sp-api", appId: "api", displayName: "API",
        appRoles: [{ id: "r-known", value: "Api.Read", isEnabled: true }],
      }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r-known", principalId: "sp-1", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-2", appRoleId: "r-unknown", principalId: "sp-1", resourceId: "sp-api" })),
      ],
    }));
    const edge = edgesOfType(snapshot, "CAN_CALL_AS_APP")[0]!;
    expect(edge.evidence.completeness).toBe("unresolved");
    expect(edge.permissions).toEqual(["Api.Read", "Unresolved role r-unknown"]);
    expect(edge.evidence.sourceRecordIds).toEqual(["a-1", "a-2"]);
  });

  it("calls an assignment complete only when the resource published every role it grants", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({
        id: "sp-api", appId: "api", displayName: "API",
        appRoles: [{ id: "r-1", value: "Api.Read", isEnabled: true }, { id: "r-2", value: "Api.Write", isEnabled: true }],
      }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r-1", principalId: "sp-1", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-2", appRoleId: "r-2", principalId: "sp-1", resourceId: "sp-api" })),
      ],
    }));
    expect(edgesOfType(snapshot, "CAN_CALL_AS_APP")[0]?.evidence.completeness).toBe("complete");
  });

  it("grants an app-role edge only when the resource actually publishes that role", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API", appRoles: [{ id: "r-1", value: "Api.Read", isEnabled: true }] })),
        sourced(servicePrincipal({ id: "sp-other", appId: "other", displayName: "Other" })),
      ],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r-1", principalId: "sp-1", resourceId: "sp-api" })),
        // The same role id, but claimed against an identity that publishes nothing.
        sourced(assignment({ id: "a-2", appRoleId: "r-1", principalId: "sp-1", resourceId: "sp-other" })),
      ],
    }));
    expect(edgesOfType(snapshot, "GRANTED_APP_ROLE").map((edge) => edge.targetId)).toEqual(["app-role:sp-api:r-1"]);
  });

  it("marks a delegated grant unresolved when either side is missing from the inventory", () => {
    const known = servicePrincipal({ id: "sp-known", appId: "known", displayName: "Known" });
    const missingClient = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(known)],
      oauth2PermissionGrants: [sourced(grant({ id: "g-1", clientId: "sp-absent", resourceId: "sp-known", scope: "Mail.Read" }))],
    }));
    expect(edgesOfType(missingClient, "CAN_CALL_DELEGATED")[0]?.evidence.completeness).toBe("unresolved");
    const missingResource = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(known)],
      oauth2PermissionGrants: [sourced(grant({ id: "g-2", clientId: "sp-known", resourceId: "sp-absent", scope: "Mail.Read" }))],
    }));
    expect(edgesOfType(missingResource, "CAN_CALL_DELEGATED")[0]?.evidence.completeness).toBe("unresolved");
  });
});

describe("Conditional Access subjects and controls", () => {
  const policyScan = (partial: Parameters<typeof conditionalAccessPolicy>[0]) => normalizeTenantScan(rawScan({
    users: [sourced(directoryObject({ id: "user-1", displayName: "Avery" }))],
    conditionalAccessPolicies: [sourced(conditionalAccessPolicy(partial))],
  }));

  it.each(["All", "None", "GuestsOrExternalUsers", "Office365"])("does not treat the %s keyword as a directory object", (keyword) => {
    const snapshot = policyScan({
      id: "policy-1", displayName: "Require MFA", state: "enabled",
      conditions: { users: { includeUsers: [keyword, "user-1"] } },
    });
    expect(edgesOfType(snapshot, "GOVERNED_BY").map((edge) => edge.sourceId)).toEqual(["user-1"]);
  });

  it("names the grant controls the policy enforces, or none when it enforces nothing", () => {
    const withControls = policyScan({
      id: "policy-1", displayName: "Require MFA", state: "enabled",
      conditions: { users: { includeUsers: ["user-1"] } },
      grantControls: { builtInControls: ["mfa", "compliantDevice"], operator: "AND" },
    });
    expect(nodeById(withControls, "policy-1")?.metadata).toMatchObject({ controls: "mfa, compliantDevice" });
    expect(edgesOfType(withControls, "GOVERNED_BY")[0]?.permissions).toEqual(["mfa", "compliantDevice"]);
    const withoutControls = policyScan({ id: "policy-2", displayName: "Report only", state: "enabledForReportingButNotEnforced", grantControls: null });
    expect(nodeById(withoutControls, "policy-2")?.metadata).toMatchObject({ controls: "none" });
    const emptyControls = policyScan({ id: "policy-3", displayName: "Nothing", state: "disabled", grantControls: { operator: "OR" } });
    expect(nodeById(emptyControls, "policy-3")?.metadata).toMatchObject({ controls: "none" });
  });

  it("records whether the partner belongs to a multi-tenant organization", () => {
    const declared = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: "33333333-3333-4333-8333-333333333333", isInMultiTenantOrganization: true }))],
    }));
    expect(nodeById(declared, "external-tenant:33333333-3333-4333-8333-333333333333")?.metadata).toMatchObject({ multiTenantOrganization: true });
    const absent = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: "44444444-4444-4444-8444-444444444444" }))],
    }));
    expect(nodeById(absent, "external-tenant:44444444-4444-4444-8444-444444444444")?.metadata).toMatchObject({ multiTenantOrganization: false });
  });
});

describe("node shape details", () => {
  it("records an app role's enabled flag, treating anything but true as not enabled", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({
        id: "sp-api", appId: "api", displayName: "API",
        appRoles: [
          { id: "on", value: "Api.On", isEnabled: true },
          { id: "off", value: "Api.Off", isEnabled: false },
          { id: "unknown", value: "Api.Unknown" } as never,
        ],
      }))],
    }));
    expect(nodeById(snapshot, "app-role:sp-api:on")).toMatchObject({ kind: "appRole", ownerIds: [], metadata: { enabled: true } });
    expect(nodeById(snapshot, "app-role:sp-api:off")?.metadata).toMatchObject({ enabled: false });
    expect(nodeById(snapshot, "app-role:sp-api:unknown")?.metadata).toMatchObject({ enabled: false });
    // Only a role Graph explicitly reported as disabled is advisory; an unknown flag is not.
    expect(nodeById(snapshot, "app-role:sp-api:unknown")?.risk.level).toBe("low");
    expect(nodeById(snapshot, "app-role:sp-api:off")?.risk.level).toBe("review");
  });

  it("gives every derived node an empty owner list rather than inventing owners", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API", appRoles: [{ id: "r-1", value: "Api.Read", isEnabled: true }] }))],
      roleDefinitions: [sourced(roleDefinition({ id: "role-1", displayName: "Global Administrator" }))],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({ id: "policy-1", displayName: "Require MFA", state: "enabled" }))],
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: "33333333-3333-4333-8333-333333333333" }))],
    }));
    for (const id of [
      "app-role:sp-api:r-1", "role-1", "policy-1",
      "external-tenant:33333333-3333-4333-8333-333333333333",
      "cross-tenant-policy:33333333-3333-4333-8333-333333333333",
    ]) {
      expect(nodeById(snapshot, id)?.ownerIds, id).toEqual([]);
    }
  });

  it("marks the partner policy node as configured and worth review", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: "33333333-3333-4333-8333-333333333333" }))],
    }));
    expect(nodeById(snapshot, "cross-tenant-policy:33333333-3333-4333-8333-333333333333")).toMatchObject({
      metadata: { policyType: "crossTenantAccess", state: "configured" },
      risk: { level: "review", reason: "Cross-tenant settings require periodic owner review." },
    });
  });
});

describe("identifier derivation", () => {
  it("derives each identifier from its own pair, so two relationships of one kind never collide", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [
        sourced(application({ id: "app-1", appId: "one", displayName: "One" })),
        sourced(application({ id: "app-2", appId: "two", displayName: "Two" })),
      ],
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-1", appId: "one", displayName: "One SP" })),
        sourced(servicePrincipal({ id: "sp-2", appId: "two", displayName: "Two SP" })),
      ],
      applicationOwners: [
        { ...sourced(directoryObject({ id: "user-1", displayName: "Avery" })), targetId: "app-1" },
        { ...sourced(directoryObject({ id: "user-1", displayName: "Avery" })), targetId: "app-2" },
      ],
      groups: [sourced({ id: "group-1", displayName: "Finance", securityEnabled: true })],
      groupMemberships: [
        { ...sourced(directoryObject({ id: "user-1", displayName: "Avery" })), groupId: "group-1" },
        { ...sourced(directoryObject({ id: "user-2", displayName: "Blake" })), groupId: "group-1" },
      ],
    }));
    for (const type of ["OWNS", "MEMBER_OF", "INSTANTIATES_AS"] as const) {
      const ids = edgesOfType(snapshot, type).map((edge) => edge.id);
      expect(ids.length, type).toBe(2);
      expect(new Set(ids).size, type).toBe(2);
    }
  });

  it("keeps an application-only assignment separate from a person's assignment over the same pair", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r-1", principalId: "principal-1", resourceId: "sp-api", principalType: "ServicePrincipal" })),
        sourced(assignment({ id: "a-2", appRoleId: "r-1", principalId: "principal-1", resourceId: "sp-api", principalType: "User" })),
      ],
    }));
    const edges = snapshot.edges.filter((edge) => edge.type === "CAN_CALL_AS_APP" || edge.type === "ASSIGNED_TO");
    expect(edges.map((edge) => edge.type).sort()).toEqual(["ASSIGNED_TO", "CAN_CALL_AS_APP"]);
    expect(new Set(edges.map((edge) => edge.id)).size).toBe(2);
    expect(edges.map((edge) => edge.evidence.sourceRecordIds)).toEqual([["a-1"], ["a-2"]]);
  });

  it("never reads a Conditional Access keyword as a directory object, even one that shares its id", () => {
    const snapshot = normalizeTenantScan(rawScan({
      groups: [
        sourced({ id: "All", displayName: "All", securityEnabled: true }),
        sourced({ id: "None", displayName: "None", securityEnabled: true }),
        sourced({ id: "GuestsOrExternalUsers", displayName: "Guests", securityEnabled: true }),
        sourced({ id: "Office365", displayName: "Office", securityEnabled: true }),
        sourced({ id: "group-real", displayName: "Finance", securityEnabled: true }),
      ],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({
        id: "policy-1", displayName: "Require MFA", state: "enabled",
        conditions: { users: { includeGroups: ["All", "None", "GuestsOrExternalUsers", "Office365", "group-real"] } },
      }))],
    }));
    expect(edgesOfType(snapshot, "GOVERNED_BY").map((edge) => edge.sourceId)).toEqual(["group-real"]);
  });
});
