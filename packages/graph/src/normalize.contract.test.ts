import { describe, expect, it } from "vitest";
import { normalizeTenantScan } from "./normalize";
import {
  TENANT,
  application,
  assignment,
  conditionalAccessPolicy,
  crossTenantPartner,
  directoryObject,
  grant,
  rawScan,
  roleDefinition,
  servicePrincipal,
  sourced,
} from "./test-support";
import type { TenantSnapshot } from "@entra-explorer/domain";

const nodeById = (snapshot: TenantSnapshot, id: string) => snapshot.nodes.find((node) => node.id === id)!;
const PARTNER_TENANT = "33333333-3333-4333-8333-333333333333";

/**
 * The wording below is product surface, not incidental text: DESIGN.md requires plain
 * English first and the Microsoft term second, and nothing may imply that configured
 * access was used. Pinning it keeps a rewording deliberate.
 */
describe("object descriptions", () => {
  it("describes an application blueprint in plain English with the Microsoft term", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "Payroll" }))],
    }));
    expect(nodeById(snapshot, "app-1").description).toBe(
      "Reusable application blueprint (app registration) collected from Microsoft Graph.",
    );
  });

  it("describes a tenant identity and a managed identity differently", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-1", appId: "a", displayName: "Vendor", servicePrincipalType: "Application" })),
        sourced(servicePrincipal({ id: "mi-1", appId: "b", displayName: "Deploy", servicePrincipalType: "ManagedIdentity" })),
      ],
    }));
    expect(nodeById(snapshot, "sp-1").description).toBe(
      "Tenant-local application identity (service principal) collected from Microsoft Graph.",
    );
    expect(nodeById(snapshot, "mi-1").description).toBe("Managed workload identity collected from Microsoft Graph.");
  });

  it("describes an app role by the identity that exposes it", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({
        id: "sp-api", appId: "api", displayName: "Payroll API",
        appRoles: [{ id: "role-1", value: "Api.Read", isEnabled: true }],
      }))],
    }));
    expect(nodeById(snapshot, "app-role:sp-api:role-1").description).toBe("Application role exposed by Payroll API.");
  });

  it("describes an administrative role, a policy, and a partner tenant", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleDefinitions: [sourced(roleDefinition({ id: "role-1", displayName: "Global Administrator" }))],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({ id: "policy-1", displayName: "Require MFA", state: "enabled" }))],
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: PARTNER_TENANT }))],
    }));
    expect(nodeById(snapshot, "role-1").description).toBe("Microsoft Entra administrative role.");
    expect(nodeById(snapshot, "policy-1").description).toBe("Conditional Access policy collected from Microsoft Graph.");
    expect(nodeById(snapshot, `external-tenant:${PARTNER_TENANT}`).description).toBe(
      "Partner organization with explicit cross-tenant access settings.",
    );
    expect(nodeById(snapshot, `cross-tenant-policy:${PARTNER_TENANT}`).description).toBe(
      "Partner-specific Microsoft Entra cross-tenant access policy.",
    );
  });

  it("distinguishes a fully resolved directory object from a partially resolved one", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "a", displayName: "App" }))],
      applicationOwners: [
        { ...sourced(directoryObject({ id: "named", displayName: "Avery" })), targetId: "app-1" },
        { ...sourced(directoryObject({ id: "bare" })), targetId: "app-1" },
      ],
    }));
    expect(nodeById(snapshot, "named").description).toBe("Directory object collected from an ownership relationship.");
    expect(nodeById(snapshot, "bare").description).toBe("Directory object returned with limited information.");
  });

  it("distinguishes a named assignment principal from an unnamed one", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API" }))],
      appRoleAssignments: [
        sourced(assignment({ id: "a-1", appRoleId: "r", principalId: "named", principalType: "User", resourceId: "sp-api", principalDisplayName: "Avery" })),
        sourced(assignment({ id: "a-2", appRoleId: "r", principalId: "bare", principalType: "User", resourceId: "sp-api" })),
      ],
    }));
    expect(nodeById(snapshot, "named").description).toBe("Directory principal collected from an app-role assignment.");
    expect(nodeById(snapshot, "bare").description).toBe("Assignment principal returned with limited information.");
  });

  it("explains an identity referenced by a relationship but missing from the inventory", () => {
    const snapshot = normalizeTenantScan(rawScan({
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "r", principalId: "p", resourceId: "sp-absent" }))],
    }));
    expect(nodeById(snapshot, "sp-absent").description).toBe(
      "Referenced by a configured relationship but missing from the collected service-principal inventory.",
    );
  });
});

describe("advisory reasons", () => {
  it("states why an app role is or is not worth review", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({
        id: "sp-api", appId: "api", displayName: "API",
        appRoles: [{ id: "on", value: "Api.Read", isEnabled: true }, { id: "off", value: "Api.Legacy", isEnabled: false }],
      }))],
    }));
    expect(nodeById(snapshot, "app-role:sp-api:on").risk.reason).toBe("Risk depends on the principals granted this role.");
    expect(nodeById(snapshot, "app-role:sp-api:off").risk.reason).toBe("The role is disabled but may remain referenced by assignments.");
  });

  it("states why an administrative role and a cross-tenant setting need review", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleDefinitions: [sourced(roleDefinition({ id: "role-1", displayName: "Global Administrator" }))],
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: PARTNER_TENANT }))],
    }));
    expect(nodeById(snapshot, "role-1").risk.reason).toBe("Administrative role membership can provide privileged directory access.");
    expect(nodeById(snapshot, `external-tenant:${PARTNER_TENANT}`).risk.reason).toBe("Partner-specific cross-tenant trust must be reviewed in context.");
    expect(nodeById(snapshot, `cross-tenant-policy:${PARTNER_TENANT}`).risk.reason).toBe("Cross-tenant settings require periodic owner review.");
  });

  it("says an enabled policy still depends on its conditions, never that it is effective", () => {
    const snapshot = normalizeTenantScan(rawScan({
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({ id: "policy-1", displayName: "Require MFA", state: "enabled" }))],
    }));
    expect(nodeById(snapshot, "policy-1").risk.reason).toBe("Policy is enabled; applicability still depends on its conditions.");
  });

  it("states why a partially resolved object carries an advisory", () => {
    const snapshot = normalizeTenantScan(rawScan({
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "r", principalId: "p", resourceId: "sp-absent" }))],
    }));
    expect(nodeById(snapshot, "sp-absent").risk.reason).toBe("The source object is incomplete; inspect scan errors and skipped endpoints.");
    expect(nodeById(snapshot, "p").risk.reason).toBe("This object was discovered from an assignment and has limited inventory detail.");
  });

  it("states plainly when no advisory rule applies", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
    }));
    expect(nodeById(snapshot, "user-1").risk.reason).toBe("No advisory entity rule applies.");
  });

  it("states why a bare directory object is advisory", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced(directoryObject({ id: "user-1", "@odata.type": "#microsoft.graph.user" }))],
    }));
    expect(nodeById(snapshot, "user-1").risk.reason).toBe("Limited directory information was returned.");
  });
});

describe("relationship wording", () => {
  it("labels each relationship type in plain English", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced(application({ id: "app-1", appId: "shared", displayName: "App" }))],
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-1", appId: "shared", displayName: "Runtime", appRoles: [{ id: "r", value: "Api.Read", isEnabled: true }] })),
        sourced(servicePrincipal({ id: "sp-2", appId: "client", displayName: "Client" })),
      ],
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "r", principalId: "sp-2", resourceId: "sp-1" }))],
      applicationOwners: [{ ...sourced(directoryObject({ id: "owner-1", displayName: "Avery" })), targetId: "app-1" }],
      groups: [sourced(directoryObject({ id: "group-1", displayName: "Team", "@odata.type": "#microsoft.graph.group" }))],
      groupMemberships: [{ ...sourced(directoryObject({ id: "owner-1", displayName: "Avery" })), groupId: "group-1" }],
    }));
    const labels = new Map(snapshot.edges.map((edge) => [edge.type, edge.plainLabel]));
    expect(labels.get("INSTANTIATES_AS")).toBe("Creates a tenant identity");
    expect(labels.get("CAN_CALL_AS_APP")).toBe("Can call");
    expect(labels.get("EXPOSES_APP_ROLE")).toBe("Exposes app role");
    expect(labels.get("GRANTED_APP_ROLE")).toBe("Granted app role");
    expect(labels.get("OWNS")).toBe("Owns");
    expect(labels.get("MEMBER_OF")).toBe("Member of");
  });

  it("labels an assignment to a person as being assigned to use, not as calling", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API", appRoles: [{ id: "r", value: "Api.Read", isEnabled: true }] }))],
      appRoleAssignments: [sourced(assignment({ id: "a-1", appRoleId: "r", principalId: "user-1", principalType: "User", resourceId: "sp-api" }))],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "ASSIGNED_TO")?.plainLabel).toBe("Assigned to use");
  });

  it("separates a workload call from a person's assignment in the same scan", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [
        sourced(servicePrincipal({ id: "sp-api", appId: "api", displayName: "API", appRoles: [{ id: "r", value: "Api.Read", isEnabled: true }] })),
        sourced(servicePrincipal({ id: "sp-client", appId: "client", displayName: "Client" })),
      ],
      appRoleAssignments: [
        sourced(assignment({ id: "a-app", appRoleId: "r", principalId: "sp-client", principalType: "ServicePrincipal", resourceId: "sp-api" })),
        sourced(assignment({ id: "a-user", appRoleId: "r", principalId: "user-1", principalType: "User", resourceId: "sp-api" })),
      ],
    }));
    expect(snapshot.edges.filter((edge) => edge.type === "CAN_CALL_AS_APP").map((edge) => edge.sourceId)).toEqual(["sp-client"]);
    expect(snapshot.edges.filter((edge) => edge.type === "ASSIGNED_TO").map((edge) => edge.sourceId)).toEqual(["user-1"]);
  });

  it("labels the observed and cross-tenant relationships", () => {
    const snapshot = normalizeTenantScan(rawScan({
      signIns: [sourced({ id: "s-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-1", resourceServicePrincipalId: "sp-2", status: { errorCode: 0 } })],
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: PARTNER_TENANT }))],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "OBSERVED_CALL")?.plainLabel).toBe("Called recently");
    expect(snapshot.edges.find((edge) => edge.type === "CROSS_TENANT_ACCESS")?.plainLabel).toBe("Has partner access settings");
  });
});

describe("Conditional Access subject collection", () => {
  const subjects = (policy: Parameters<typeof conditionalAccessPolicy>[0]) => normalizeTenantScan(rawScan({
    users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
    groups: [sourced(directoryObject({ id: "group-1", displayName: "Team", "@odata.type": "#microsoft.graph.group" }))],
    servicePrincipals: [sourced(servicePrincipal({ id: "sp-1", appId: "client-app-id", displayName: "Client" }))],
    conditionalAccessPolicies: [sourced(conditionalAccessPolicy(policy))],
  })).edges.filter((edge) => edge.type === "GOVERNED_BY").map((edge) => edge.sourceId).sort();

  it("collects users, groups, and applications together", () => {
    expect(subjects({
      id: "p", displayName: "All three", state: "enabled",
      conditions: { users: { includeUsers: ["user-1"], includeGroups: ["group-1"] }, applications: { includeApplications: ["client-app-id"] } },
    })).toEqual(["group-1", "sp-1", "user-1"]);
  });

  it("treats each absent condition block as empty rather than failing", () => {
    expect(subjects({ id: "p", displayName: "None", state: "enabled" })).toEqual([]);
    expect(subjects({ id: "p", displayName: "Users only", state: "enabled", conditions: { users: { includeUsers: ["user-1"] } } })).toEqual(["user-1"]);
    expect(subjects({ id: "p", displayName: "Groups only", state: "enabled", conditions: { users: { includeGroups: ["group-1"] } } })).toEqual(["group-1"]);
    expect(subjects({ id: "p", displayName: "Apps only", state: "enabled", conditions: { applications: { includeApplications: ["client-app-id"] } } })).toEqual(["sp-1"]);
  });

  it.each(["All", "None", "GuestsOrExternalUsers", "Office365"])("ignores the catch-all token %s", (token) => {
    expect(subjects({
      id: "p", displayName: "Catch-all", state: "enabled",
      conditions: { users: { includeUsers: [token, "user-1"] }, applications: { includeApplications: [token] } },
    })).toEqual(["user-1"]);
  });

  it("records the grant controls it enforces on the governance edge", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({
        id: "p", displayName: "MFA", state: "enabled",
        conditions: { users: { includeUsers: ["user-1"] } },
        grantControls: { builtInControls: ["mfa", "compliantDevice"], operator: "AND" },
      }))],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "GOVERNED_BY")?.permissions).toEqual(["mfa", "compliantDevice"]);
    expect(nodeById(snapshot, "p").metadata?.controls).toBe("mfa, compliantDevice");
  });

  it("records no controls when the policy grants none", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced(directoryObject({ id: "user-1", displayName: "Avery", "@odata.type": "#microsoft.graph.user" }))],
      conditionalAccessPolicies: [sourced(conditionalAccessPolicy({
        id: "p", displayName: "Bare", state: "enabled", conditions: { users: { includeUsers: ["user-1"] } },
      }))],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "GOVERNED_BY")?.permissions).toEqual([]);
  });
});

describe("tenant stamping", () => {
  it("stamps the scanning tenant onto a partner tenant node rather than the partner's own id", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: PARTNER_TENANT }))],
    }));
    const partner = nodeById(snapshot, `external-tenant:${PARTNER_TENANT}`);
    expect(partner.tenantId).toBe(TENANT);
    expect(partner.metadata?.externalTenantId).toBe(PARTNER_TENANT);
    expect(partner.isExternal).toBe(true);
  });

  it("truncates a partner tenant id in the label rather than showing it whole", () => {
    const snapshot = normalizeTenantScan(rawScan({
      crossTenantPartners: [sourced(crossTenantPartner({ tenantId: PARTNER_TENANT }))],
    }));
    expect(nodeById(snapshot, `external-tenant:${PARTNER_TENANT}`).label).toBe("External tenant 33333333");
    expect(nodeById(snapshot, `cross-tenant-policy:${PARTNER_TENANT}`).label).toBe("Partner policy 33333333");
  });
});

/**
 * Every edge must carry the provenance a reviewer needs: a deterministic id that names
 * the kind of relationship it came from, the endpoint that produced it, the exact record
 * ids behind it, and an honest completeness verdict. These assertions pin all of it, so a
 * dropped field or a silently reused id cannot pass as a normalized relationship.
 */
describe("edge identity and evidence", () => {
  const SCANNED_AT = "2026-08-26T12:00:00.000Z";
  const ID = /^[0-9a-f]{24}$/;

  function fullScan() {
    return rawScan({
      scannedAt: SCANNED_AT,
      applications: [{ endpoint: "/applications", record: application({ id: "app-1", appId: "shared", displayName: "Payroll" }) }],
      servicePrincipals: [
        {
          endpoint: "/servicePrincipals",
          record: servicePrincipal({
            id: "sp-api", appId: "shared", displayName: "Payroll API",
            appRoles: [{ id: "role-1", value: "Api.Read", displayName: "Read", isEnabled: true, allowedMemberTypes: ["Application"] }],
          }),
        },
        { endpoint: "/servicePrincipals", record: servicePrincipal({ id: "sp-caller", appId: "caller", displayName: "Caller" }) },
      ],
      appRoleAssignments: [
        {
          endpoint: "/servicePrincipals/sp-api/appRoleAssignedTo",
          record: assignment({ id: "assign-1", appRoleId: "role-1", principalId: "sp-caller", resourceId: "sp-api", principalType: "ServicePrincipal" }),
        },
        {
          endpoint: "/servicePrincipals/sp-api/appRoleAssignedTo",
          record: assignment({ id: "assign-2", appRoleId: "role-1", principalId: "user-1", resourceId: "sp-api", principalType: "User", principalDisplayName: "Avery" }),
        },
      ],
      oauth2PermissionGrants: [
        { endpoint: "/oauth2PermissionGrants", record: grant({ id: "grant-1", clientId: "sp-caller", resourceId: "sp-api", scope: "Mail.Read User.Read" }) },
      ],
      applicationOwners: [{ endpoint: "/applications/app-1/owners", record: directoryObject({ id: "user-1", displayName: "Avery" }), targetId: "app-1" }],
      users: [{ endpoint: "/users", record: directoryObject({ id: "user-1", displayName: "Avery" }) }],
      groups: [{ endpoint: "/groups", record: { id: "group-1", displayName: "Finance", securityEnabled: true } }],
      groupMemberships: [{ endpoint: "/groups/group-1/members", groupId: "group-1", record: directoryObject({ id: "user-1", displayName: "Avery" }) }],
      roleDefinitions: [{ endpoint: "/roleManagement/directory/roleDefinitions", record: roleDefinition({ id: "role-def-1", displayName: "Global Administrator" }) }],
      roleAssignments: [{ endpoint: "/roleManagement/directory/roleAssignments", record: { id: "ra-1", principalId: "user-1", roleDefinitionId: "role-def-1", directoryScopeId: "/" } }],
      roleEligibilities: [{ endpoint: "/roleManagement/directory/roleEligibilitySchedules", record: { id: "re-1", principalId: "user-1", roleDefinitionId: "role-def-1", directoryScopeId: null } }],
      conditionalAccessPolicies: [{
        endpoint: "/identity/conditionalAccess/policies",
        record: conditionalAccessPolicy({
          id: "policy-1", displayName: "Require MFA", state: "enabled",
          conditions: { users: { includeUsers: ["user-1"], includeGroups: [] }, applications: { includeApplications: [] } },
          grantControls: { builtInControls: ["mfa"], operator: "OR" },
        }),
      }],
      signIns: [{
        endpoint: "/auditLogs/signIns",
        record: { id: "signin-1", createdDateTime: "2026-08-20T09:00:00Z", servicePrincipalId: "sp-caller", resourceServicePrincipalId: "sp-api", status: { errorCode: 0 } },
      }],
      crossTenantPartners: [{ endpoint: "/policies/crossTenantAccessPolicy/partners", record: crossTenantPartner({ tenantId: PARTNER_TENANT, inboundTrust: { isMfaAccepted: true } }) }],
    });
  }

  const snapshot = normalizeTenantScan(fullScan(), { snapshotId: "snapshot-evidence" });
  const edgeOf = (type: string) => snapshot.edges.find((edge) => edge.type === type)!;

  it.each([
    ["INSTANTIATES_AS", "instantiates", "app-1", "sp-api", "/applications + /servicePrincipals (matching appId)", [], ["app-1", "sp-api"], "complete", "Creates a tenant identity"],
    ["EXPOSES_APP_ROLE", "exposes-role", "sp-api", "app-role:sp-api:role-1", "/servicePrincipals", ["Api.Read"], ["sp-api", "role-1"], "complete", "Exposes app role"],
    ["GRANTED_APP_ROLE", "granted-role", "sp-caller", "app-role:sp-api:role-1", "/servicePrincipals/sp-api/appRoleAssignedTo", ["role-1"], ["assign-1", "role-1"], "complete", "Granted app role"],
    ["CAN_CALL_AS_APP", "assignment", "sp-caller", "sp-api", "/servicePrincipals/sp-api/appRoleAssignedTo", ["Api.Read"], ["assign-1"], "complete", "Can call"],
    ["ASSIGNED_TO", "assignment", "user-1", "sp-api", "/servicePrincipals/sp-api/appRoleAssignedTo", ["Api.Read"], ["assign-2"], "complete", "Assigned to use"],
    ["CAN_CALL_DELEGATED", "delegated", "sp-caller", "sp-api", "/oauth2PermissionGrants", ["Mail.Read", "User.Read"], ["grant-1"], "complete", "Can call with a signed-in person"],
    ["OWNS", "owner", "user-1", "app-1", "/applications/app-1/owners", [], ["user-1"], "complete", "Owns"],
    ["MEMBER_OF", "member", "user-1", "group-1", "/groups/group-1/members", [], ["user-1", "group-1"], "complete", "Member of"],
    ["ACTIVE_IN_ROLE", "role", "user-1", "role-def-1", "/roleManagement/directory/roleAssignments", ["/"], ["ra-1"], "complete", "Active in role"],
    ["ELIGIBLE_FOR_ROLE", "role", "user-1", "role-def-1", "/roleManagement/directory/roleEligibilitySchedules", [], ["re-1"], "complete", "Eligible for role"],
    ["GOVERNED_BY", "policy", "user-1", "policy-1", "/identity/conditionalAccess/policies", ["mfa"], ["policy-1"], "complete", "Governed by"],
    ["OBSERVED_CALL", "activity", "sp-caller", "sp-api", "/auditLogs/signIns", [], ["signin-1"], "complete", "Called recently"],
    ["CROSS_TENANT_ACCESS", "cross-tenant", `external-tenant:${PARTNER_TENANT}`, `cross-tenant-policy:${PARTNER_TENANT}`, "/policies/crossTenantAccessPolicy/partners", ["MFA"], [PARTNER_TENANT], "complete", "Has partner access settings"],
  ])("carries full provenance on a %s edge", (type, prefix, sourceId, targetId, endpoint, permissions, recordIds, completeness, plainLabel) => {
    const edge = edgeOf(type);
    expect(edge, type).toBeDefined();
    const [idPrefix, digest] = edge.id.split(":");
    expect(idPrefix).toBe(prefix);
    expect(digest).toMatch(ID);
    expect(edge.tenantId).toBe(TENANT);
    expect(edge.sourceId).toBe(sourceId);
    expect(edge.targetId).toBe(targetId);
    expect(edge.permissions).toEqual(permissions);
    expect(edge.plainLabel).toBe(plainLabel);
    expect(edge.evidence).toEqual({
      // Observed activity is evidence of use, not of configuration.
      configured: type !== "OBSERVED_CALL",
      observed: type === "OBSERVED_CALL"
        ? { lastSeenAt: "2026-08-20T09:00:00Z", windowStartsAt: "2026-07-27T12:00:00.000Z" }
        : null,
      scannedAt: SCANNED_AT,
      sourceEndpoint: endpoint,
      sourceRecordIds: recordIds,
      sourceObjectId: sourceId,
      targetObjectId: targetId,
      completeness,
    });
  });

  it("gives every edge its own identifier, and repeats it exactly for an unchanged scan", () => {
    const ids = snapshot.edges.map((edge) => edge.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(normalizeTenantScan(fullScan(), { snapshotId: "snapshot-evidence" }).edges.map((edge) => edge.id)).toEqual(ids);
  });

  it("derives the identifier from the relationship, so two kinds between one pair never collide", () => {
    const [callEdge, delegatedEdge] = [edgeOf("CAN_CALL_AS_APP"), edgeOf("CAN_CALL_DELEGATED")];
    expect(callEdge.sourceId).toBe(delegatedEdge.sourceId);
    expect(callEdge.targetId).toBe(delegatedEdge.targetId);
    expect(callEdge.id).not.toBe(delegatedEdge.id);
  });
});

/**
 * Edge identifiers key saved threat reviews and snapshot comparisons, so they are a
 * compatibility surface: the same relationship must hash to the same value across runs
 * and releases. These golden values fail loudly if the inputs to the hash ever change.
 */
describe("stable edge identifiers", () => {
  const snapshot = normalizeTenantScan(rawScan({
    applications: [sourced(application({ id: "app-1", appId: "shared", displayName: "Payroll" }), "/applications")],
    servicePrincipals: [sourced(servicePrincipal({
      id: "sp-1", appId: "shared", displayName: "Payroll SP",
      appRoles: [{ id: "role-1", value: "Api.Read", isEnabled: true }],
    }), "/servicePrincipals")],
    appRoleAssignments: [
      sourced(assignment({ id: "assign-1", appRoleId: "role-1", principalId: "caller-1", resourceId: "sp-1", principalType: "ServicePrincipal" }), "/servicePrincipals/sp-1/appRoleAssignedTo"),
      sourced(assignment({ id: "assign-2", appRoleId: "role-1", principalId: "caller-1", resourceId: "sp-1", principalType: "User" }), "/servicePrincipals/sp-1/appRoleAssignedTo"),
    ],
    oauth2PermissionGrants: [sourced(grant({ id: "grant-1", clientId: "caller-1", resourceId: "sp-1", scope: "Mail.Read" }), "/oauth2PermissionGrants")],
    applicationOwners: [{ ...sourced(directoryObject({ id: "user-1", displayName: "Avery" }), "/applications/app-1/owners"), targetId: "app-1" }],
  }));

  it.each([
    ["INSTANTIATES_AS", "instantiates:3d07ec8386a4831eeeb70ff0"],
    ["CAN_CALL_AS_APP", "assignment:e6d064669f4f5a50b82cf6ff"],
    ["ASSIGNED_TO", "assignment:c747aec9b525c11fadb8e8af"],
    ["EXPOSES_APP_ROLE", "exposes-role:71c6af073aee42f9346e353a"],
    ["CAN_CALL_DELEGATED", "delegated:00d1c1c9f0bcc58c43e6d0b1"],
    ["OWNS", "owner:6393a16fb4797e85aa5b38bd"],
  ])("keeps the identifier of a %s relationship unchanged", (type, id) => {
    expect(snapshot.edges.find((edge) => edge.type === type)?.id).toBe(id);
  });

  it("keeps an application-only call and a person's assignment on separate identifiers", () => {
    const assignments = snapshot.edges.filter((edge) => edge.evidence.sourceEndpoint.includes("appRoleAssignedTo") && edge.type !== "GRANTED_APP_ROLE");
    expect(assignments.map((edge) => [edge.type, edge.evidence.sourceRecordIds])).toEqual([
      ["CAN_CALL_AS_APP", ["assign-1"]],
      ["ASSIGNED_TO", ["assign-2"]],
    ]);
  });

  it("gives a principal discovered from an assignment no owners of its own", () => {
    expect(snapshot.nodes.find((node) => node.id === "caller-1")).toMatchObject({ ownerIds: [] });
  });
});
