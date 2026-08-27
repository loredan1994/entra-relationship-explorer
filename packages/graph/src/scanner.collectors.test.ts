import { describe, expect, it } from "vitest";
import { scanTenant } from "./scanner";
import { TENANT, clientFor, rawScan, routedFetch } from "./test-support";

describe("high-leverage Graph collectors", () => {
  it("collects and sanitizes devices, administrative units, memberships, and workload federation", async () => {
    const recorder = routedFetch({
      "/applications?": [{ id: "app-1", appId: "client", displayName: "Client" }],
      "/servicePrincipals?$select=id,appId": [{ id: "mi-1", appId: "mi", displayName: "Managed", servicePrincipalType: "ManagedIdentity" }],
      "/applications/app-1/federatedIdentityCredentials": [{ id: "fic-app", name: "github", issuer: "https://issuer.example", subject: "repo:example/project", audiences: ["api://AzureADTokenExchange", 7], secret: "discard" }],
      "/servicePrincipals?$select=id,servicePrincipalType": [{ id: "mi-1", servicePrincipalType: "ManagedIdentity", federatedIdentityCredentials: [{ id: "fic-mi", name: "cluster", issuer: "https://cluster.example", subject: "system:serviceaccount:build:agent", audiences: ["api://AzureADTokenExchange"] }] }],
      "/devices?": [{ id: "device-1", deviceId: "device-guid", displayName: "Laptop", accountEnabled: true, isCompliant: false, isManaged: true, approximateLastSignInDateTime: "must-not-survive" }],
      "/directory/administrativeUnits?": [{ id: "au-1", displayName: "Finance", description: "Finance scope", isMemberManagementRestricted: true }],
      "/directory/administrativeUnits/au-1/members": [{ id: "device-1", displayName: "Laptop", "@odata.type": "#microsoft.graph.device" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { concurrency: 1 });
    expect(scan.devices?.[0]?.record).toMatchObject({ id: "device-1", deviceId: "device-guid", isManaged: true, isCompliant: false });
    expect(scan.administrativeUnits?.[0]?.record).toMatchObject({ id: "au-1", isMemberManagementRestricted: true });
    expect(scan.administrativeUnitMemberships?.[0]).toMatchObject({ administrativeUnitId: "au-1", record: { id: "device-1" } });
    expect(scan.federatedIdentityCredentials?.map((item) => [item.parentId, item.parentType, item.record.id])).toEqual([["app-1", "application", "fic-app"], ["mi-1", "managedIdentity", "fic-mi"]]);
    expect(JSON.stringify(scan)).not.toMatch(/secret|approximateLastSignInDateTime|must-not-survive/);
  });

  it("gates authorization and consent evidence independently", async () => {
    const routes = {
      "/policies/authorizationPolicy": { id: "authorizationPolicy", displayName: "Authorization policy", allowInvitesFrom: "adminsAndGuestInviters", defaultUserRolePermissions: { allowedToCreateApps: true, permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.policy-1", 7] } },
      "/policies/permissionGrantPolicies?": [{ id: "policy-1", displayName: "Restricted consent", description: "Low impact" }],
      "/policies/permissionGrantPolicies/policy-1/includes": [{ id: "include-1", permissionClassification: "low", permissionType: "delegated", permissions: ["User.Read", 7], clientApplicationsFromVerifiedPublisherOnly: true }],
      "/policies/permissionGrantPolicies/policy-1/excludes": [{ id: "exclude-1", clientApplicationIds: ["blocked-app"] }],
    };
    const policyOnly = await scanTenant(clientFor(routedFetch(routes)), TENANT, { enabledScopes: ["Policy.Read.All"] });
    expect(policyOnly.authorizationPolicies?.[0]?.record.defaultUserRolePermissions?.permissionGrantPoliciesAssigned).toEqual(["ManagePermissionGrantsForSelf.policy-1"]);
    expect(policyOnly.permissionGrantPolicies).toEqual([]);

    const consentOnly = await scanTenant(clientFor(routedFetch(routes)), TENANT, { enabledScopes: ["Policy.Read.PermissionGrant"] });
    expect(consentOnly.authorizationPolicies).toEqual([]);
    expect(consentOnly.permissionGrantPolicies?.[0]?.record.id).toBe("policy-1");
    expect(consentOnly.permissionGrantPolicyIncludes?.[0]?.record).toMatchObject({ permissions: ["User.Read"], clientApplicationsFromVerifiedPublisherOnly: true });
    expect(consentOnly.permissionGrantPolicyExcludes?.[0]?.record.clientApplicationIds).toEqual(["blocked-app"]);
  });

  it("backfills additive collections when resuming an older checkpoint", async () => {
    const checkpoint = rawScan({ completedStages: ["applications", "servicePrincipals", "usersAndGroups", "groupMemberships", "delegatedPermissionGrants", "appRoleAssignments", "owners", "roles", "conditionalAccess", "crossTenantAccess", "activity"] });
    delete checkpoint.devices;
    delete checkpoint.administrativeUnits;
    delete checkpoint.administrativeUnitMemberships;
    delete checkpoint.federatedIdentityCredentials;
    delete checkpoint.authorizationPolicies;
    delete checkpoint.permissionGrantPolicies;
    delete checkpoint.permissionGrantPolicyIncludes;
    delete checkpoint.permissionGrantPolicyExcludes;
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, { resumeFrom: checkpoint });
    expect(scan).toMatchObject({ devices: [], administrativeUnits: [], administrativeUnitMemberships: [], federatedIdentityCredentials: [], authorizationPolicies: [], permissionGrantPolicies: [], permissionGrantPolicyIncludes: [], permissionGrantPolicyExcludes: [] });
    expect(scan.completedStages).toEqual(expect.arrayContaining(["federatedIdentityCredentials", "devices", "administrativeUnits", "authorizationPolicy", "permissionGrantPolicies"]));
  });
});
