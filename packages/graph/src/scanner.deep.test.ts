import { describe, expect, it, vi } from "vitest";
import { GraphRequestError } from "./client";
import { ScanCancelledError, scanTenant } from "./scanner";
import {
  ALL_OPTIONAL_SCOPES,
  TENANT,
  clientFor,
  jsonResponse,
  rawScan,
  routedFetch,
} from "./test-support";
import type { RawTenantScan, ScanProgressEvent, ScanStage } from "./types";

const SCAN_TIME = new Date("2026-08-26T12:00:00.000Z");
const now = () => SCAN_TIME;

describe("scan input validation", () => {
  it("refuses a tenant identifier that is not a concrete Entra tenant GUID", async () => {
    const client = clientFor(routedFetch());
    await expect(scanTenant(client, "common")).rejects.toThrow(/concrete Microsoft Entra tenant ID/);
    await expect(scanTenant(client, "organizations")).rejects.toThrow(/concrete Microsoft Entra tenant ID/);
    // Nil GUID has version nibble 0, outside the accepted 1-5 range.
    await expect(scanTenant(client, "00000000-0000-0000-0000-000000000000")).rejects.toThrow(/concrete/);
  });

  it("accepts a well-formed tenant GUID regardless of letter case", async () => {
    const recorder = routedFetch();
    await expect(scanTenant(clientFor(recorder), TENANT.toUpperCase(), { now })).resolves.toBeDefined();
  });

  it("refuses to resume a checkpoint captured against a different tenant", async () => {
    const checkpoint = rawScan({ tenantId: "22222222-2222-4222-8222-222222222222" });
    await expect(
      scanTenant(clientFor(routedFetch()), TENANT, { resumeFrom: checkpoint }),
    ).rejects.toThrow(/cannot cross tenant boundaries/);
  });

  it("rejects a concurrency setting outside the supported range", async () => {
    const recorder = routedFetch({ "/groups?": [{ id: "group-1", displayName: "Group", securityEnabled: true }] });
    for (const concurrency of [0, -1, 21, 1.5]) {
      await expect(
        scanTenant(clientFor(recorder), TENANT, { now, concurrency }),
      ).rejects.toThrow("Scanner concurrency must be between 1 and 20.");
    }
  });
});

describe("safe cancellation", () => {
  it("stops with ScanCancelledError as soon as the caller withdraws consent", async () => {
    const recorder = routedFetch();
    await expect(
      scanTenant(clientFor(recorder), TENANT, { now, shouldCancel: async () => true }),
    ).rejects.toBeInstanceOf(ScanCancelledError);
    expect(recorder.requested).toHaveLength(0);
  });

  it("keeps scanning while the caller reports the scan is still wanted", async () => {
    const shouldCancel = vi.fn(async () => false);
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, { now, shouldCancel });
    expect(shouldCancel).toHaveBeenCalled();
    expect(scan.completedStages).toContain("activity");
  });
});

describe("optional-scope stages", () => {
  const optionalRoutes = {
    "/roleManagement/directory/roleDefinitions": [
      { id: "role-def-1", displayName: "Global Administrator", templateId: "template-1", isBuiltIn: true },
    ],
    "/roleManagement/directory/roleAssignments": [
      { id: "assign-1", principalId: "user-1", roleDefinitionId: "role-def-1", directoryScopeId: "/" },
    ],
    "/roleManagement/directory/roleEligibilitySchedules": [
      { id: "elig-1", principalId: "user-2", roleDefinitionId: "role-def-1", directoryScopeId: null },
    ],
    "/identity/conditionalAccess/policies": [
      {
        id: "policy-1",
        displayName: "Require MFA",
        state: "enabled",
        conditions: { users: { includeUsers: ["user-1"], includeGroups: ["group-1"] }, applications: { includeApplications: ["All"] } },
        grantControls: { builtInControls: ["mfa"], operator: "OR" },
      },
    ],
    "/policies/authorizationPolicy": { id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } },
    "/policies/permissionGrantPolicies?": [{ id: "consent-low", displayName: "Low impact consent" }],
    "/policies/permissionGrantPolicies/consent-low/includes": [{ id: "include-1", permissionClassification: "low" }],
    "/policies/permissionGrantPolicies/consent-low/excludes": [],
    "/policies/crossTenantAccessPolicy/partners": [
      { tenantId: "33333333-3333-4333-8333-333333333333", inboundTrust: { isMfaAccepted: true }, isInMultiTenantOrganization: false },
    ],
    "/auditLogs/signIns": [
      {
        id: "signin-1",
        createdDateTime: "2026-08-20T09:00:00Z",
        servicePrincipalId: "sp-1",
        resourceServicePrincipalId: "sp-2",
        appDisplayName: "Caller",
        resourceDisplayName: "Resource",
        status: { errorCode: 0 },
      },
    ],
  };

  it("skips every optional collection when only the core scopes are granted", async () => {
    const recorder = routedFetch(optionalRoutes);
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["https://graph.microsoft.com/Directory.Read.All"],
    });
    expect(recorder.requestedPath("/roleManagement/")).toBe(false);
    expect(recorder.requestedPath("/identity/conditionalAccess/")).toBe(false);
    expect(recorder.requestedPath("/policies/crossTenantAccessPolicy/")).toBe(false);
    expect(recorder.requestedPath("/auditLogs/signIns")).toBe(false);
    expect(scan.roleDefinitions).toEqual([]);
    expect(scan.signIns).toEqual([]);
    // The stages are still marked done so a resume does not retry an ungranted read.
    expect(scan.completedStages).toEqual(
      expect.arrayContaining<ScanStage>(["roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity"]),
    );
  });

  it("collects administrative roles when RoleManagement.Read.Directory is granted", async () => {
    const recorder = routedFetch(optionalRoutes);
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.roleDefinitions).toEqual([
      { endpoint: expect.stringContaining("/roleDefinitions"), record: { id: "role-def-1", displayName: "Global Administrator", templateId: "template-1", isBuiltIn: true } },
    ]);
    expect(scan.roleAssignments?.[0]?.record).toEqual({ id: "assign-1", principalId: "user-1", roleDefinitionId: "role-def-1", directoryScopeId: "/" });
    expect(scan.roleEligibilities?.[0]?.record.directoryScopeId).toBeNull();
  });

  it("accepts a bare scope short name as well as the fully qualified scope URI", async () => {
    const recorder = routedFetch(optionalRoutes);
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["RoleManagement.Read.Directory"],
    });
    expect(scan.roleDefinitions).toHaveLength(1);
    expect(recorder.requestedPath("/identity/conditionalAccess/")).toBe(false);
  });

  it("does not treat a scope that merely ends in similar text as a grant", async () => {
    const recorder = routedFetch(optionalRoutes);
    await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["https://contoso.example/NotRoleManagement.Read.Directory"],
    });
    expect(recorder.requestedPath("/roleManagement/")).toBe(false);
  });

  it("collects Conditional Access and cross-tenant trust under Policy.Read.All", async () => {
    const recorder = routedFetch(optionalRoutes);
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["https://graph.microsoft.com/Policy.Read.All"],
    });
    expect(scan.conditionalAccessPolicies?.[0]?.record).toEqual({
      id: "policy-1",
      displayName: "Require MFA",
      state: "enabled",
      conditions: { users: { includeUsers: ["user-1"], includeGroups: ["group-1"] }, applications: { includeApplications: ["All"] } },
      grantControls: { builtInControls: ["mfa"], operator: "OR" },
    });
    expect(scan.crossTenantPartners?.[0]?.record).toEqual({
      tenantId: "33333333-3333-4333-8333-333333333333",
      inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: false },
      isInMultiTenantOrganization: false,
    });
    expect(recorder.requestedPath("/auditLogs/signIns")).toBe(false);
  });

  it("bounds the sign-in query to the 30 days before the scan timestamp", async () => {
    const recorder = routedFetch(optionalRoutes);
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["https://graph.microsoft.com/AuditLog.Read.All"],
    });
    const signInUrl = recorder.requested.find((url) => url.includes("/auditLogs/signIns"))!;
    const since = new Date(SCAN_TIME.getTime() - 30 * 24 * 60 * 60 * 1_000).toISOString();
    expect(decodeURIComponent(signInUrl)).toContain(`createdDateTime ge ${since}`);
    expect(scan.signIns?.[0]?.record).toEqual({
      id: "signin-1",
      createdDateTime: "2026-08-20T09:00:00Z",
      servicePrincipalId: "sp-1",
      resourceServicePrincipalId: "sp-2",
      appDisplayName: "Caller",
      resourceDisplayName: "Resource",
      status: { errorCode: 0 },
    });
  });

  it("normalizes a sign-in record that omits optional identifiers and status", async () => {
    const recorder = routedFetch({
      "/auditLogs/signIns": [{ id: "signin-2", createdDateTime: "2026-08-21T09:00:00Z", status: "not-an-object" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ["https://graph.microsoft.com/AuditLog.Read.All"],
    });
    expect(scan.signIns?.[0]?.record).toEqual({
      id: "signin-2",
      createdDateTime: "2026-08-21T09:00:00Z",
      servicePrincipalId: null,
      resourceServicePrincipalId: null,
      appDisplayName: null,
      resourceDisplayName: null,
      status: null,
    });
  });

  it("drops a non-numeric sign-in error code rather than passing it through", async () => {
    const recorder = routedFetch({
      "/auditLogs/signIns": [{ id: "signin-3", createdDateTime: "2026-08-21T09:00:00Z", status: { errorCode: "50126" } }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ["AuditLog.Read.All"] });
    expect(scan.signIns?.[0]?.record.status).toEqual({ errorCode: null });
  });
});

describe("Conditional Access sanitization", () => {
  it("replaces malformed condition containers with empty allow-lists", async () => {
    const recorder = routedFetch({
      "/identity/conditionalAccess/policies": [
        { id: "policy-2", displayName: "Broken", state: "disabled", conditions: "nonsense", grantControls: undefined },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ["Policy.Read.All"] });
    expect(scan.conditionalAccessPolicies?.[0]?.record).toEqual({
      id: "policy-2",
      displayName: "Broken",
      state: "disabled",
      conditions: { users: { includeUsers: [], includeGroups: [] }, applications: { includeApplications: [] } },
      grantControls: null,
    });
  });

  it("keeps only string entries inside condition arrays", async () => {
    const recorder = routedFetch({
      "/identity/conditionalAccess/policies": [
        {
          id: "policy-3",
          displayName: "Mixed",
          state: "enabledForReportingButNotEnforced",
          conditions: { users: { includeUsers: ["user-1", 42, null], includeGroups: "not-an-array" }, applications: { includeApplications: ["app-1", {}] } },
          grantControls: { builtInControls: ["mfa", 7], operator: null },
        },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ["Policy.Read.All"] });
    const policy = scan.conditionalAccessPolicies?.[0]?.record;
    expect(policy?.conditions?.users?.includeUsers).toEqual(["user-1"]);
    expect(policy?.conditions?.users?.includeGroups).toEqual([]);
    expect(policy?.conditions?.applications?.includeApplications).toEqual(["app-1"]);
    expect(policy?.grantControls).toEqual({ builtInControls: ["mfa"], operator: null });
  });

  it("defaults absent cross-tenant inbound trust to no accepted claims", async () => {
    const recorder = routedFetch({
      "/policies/crossTenantAccessPolicy/partners": [{ tenantId: "44444444-4444-4444-8444-444444444444" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ["Policy.Read.All"] });
    expect(scan.crossTenantPartners?.[0]?.record).toEqual({
      tenantId: "44444444-4444-4444-8444-444444444444",
      inboundTrust: null,
      isInMultiTenantOrganization: false,
    });
  });
});

describe("credential and app-role sanitization", () => {
  it("keeps credential metadata but discards every secret-bearing field", async () => {
    const recorder = routedFetch({
      "/applications?": [
        {
          id: "app-1",
          appId: "app-guid",
          displayName: "Payroll",
          publisherDomain: "contoso.test",
          appRoles: [],
          passwordCredentials: [
            { keyId: "key-1", displayName: "rotation", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z", type: "Password", usage: "Verify", secretText: "leaked", customKeyIdentifier: "thumbprint" },
          ],
          keyCredentials: [{ keyId: "key-2", key: "base64-private-key" }],
        },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    const record = scan.applications[0]!.record;
    expect(record.passwordCredentials).toEqual([
      { keyId: "key-1", displayName: "rotation", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z", type: "Password", usage: "Verify" },
    ]);
    expect(record.keyCredentials).toEqual([
      { keyId: "key-2", displayName: null, startDateTime: null, endDateTime: null, type: null, usage: null },
    ]);
    expect(JSON.stringify(scan)).not.toContain("leaked");
    expect(JSON.stringify(scan)).not.toContain("base64-private-key");
  });

  it("drops credential entries without a key identifier and non-array credential blocks", async () => {
    const recorder = routedFetch({
      "/applications?": [
        {
          id: "app-2",
          appId: "app-guid-2",
          displayName: "Reports",
          appRoles: [],
          passwordCredentials: [{ displayName: "no key id" }, null, "string", { keyId: "key-ok" }],
          keyCredentials: "not-an-array",
        },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.applications[0]!.record.passwordCredentials.map((item) => item.keyId)).toEqual(["key-ok"]);
    expect(scan.applications[0]!.record.keyCredentials).toEqual([]);
  });

  it("keeps only app roles carrying an identifier and normalizes their flags", async () => {
    const recorder = routedFetch({
      "/servicePrincipals?": [
        {
          id: "sp-1",
          appId: "app-guid",
          displayName: "Resource",
          servicePrincipalType: "Application",
          appRoles: [
            { id: "role-1", value: "Api.Read", displayName: "Read", isEnabled: true, allowedMemberTypes: ["Application", 5] },
            { value: "Api.Orphan" },
            null,
            { id: "role-2", isEnabled: "yes", allowedMemberTypes: "nope" },
          ],
          passwordCredentials: [],
          keyCredentials: [],
        },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.servicePrincipals[0]!.record.appRoles).toEqual([
      { id: "role-1", value: "Api.Read", displayName: "Read", isEnabled: true, allowedMemberTypes: ["Application"] },
      { id: "role-2", value: null, displayName: null, isEnabled: false, allowedMemberTypes: [] },
    ]);
  });

  it("records a skipped endpoint when Graph returns a record without a required identifier", async () => {
    const recorder = routedFetch({ "/applications?": [{ appId: "app-guid", displayName: "No object id" }] });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.applications).toEqual([]);
    expect(scan.skippedEndpoints.some((endpoint) => endpoint.startsWith("/applications"))).toBe(true);
    expect(scan.errors[0]).toMatchObject({ code: "unexpected_error" });
    expect(scan.collectedEndpoints.some((endpoint) => endpoint.startsWith("/applications"))).toBe(false);
  });

  it("treats a blank required identifier the same as a missing one", async () => {
    const recorder = routedFetch({ "/applications?": [{ id: "   ", appId: "app-guid", displayName: "Blank" }] });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.applications).toEqual([]);
    expect(scan.errors[0]?.code).toBe("unexpected_error");
  });
});

describe("partial collection", () => {
  it("records a Graph error code and message without exposing the response body", async () => {
    const recorder = routedFetch({
      "/oauth2PermissionGrants": jsonResponse({ error: { code: "Authorization_RequestDenied", message: "tenant secret detail" } }, 403),
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    const error = scan.errors.find((item) => item.endpoint.startsWith("/oauth2PermissionGrants"));
    expect(error?.code).toBe("Authorization_RequestDenied");
    expect(error?.message).toContain("Microsoft Graph read failed");
    expect(JSON.stringify(scan)).not.toContain("tenant secret detail");
  });

  it("labels a non-Graph failure as an unexpected error with no response detail", async () => {
    const recorder = routedFetch({ "/users?": new Error("socket hang up with internal detail") });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    const error = scan.errors.find((item) => item.endpoint.startsWith("/users"));
    expect(error?.code).toBe("network_error");
    expect(error).toBeDefined();
    expect(JSON.stringify(scan)).not.toContain("socket hang up with internal detail");
  });

  it("keeps scanning later stages after one endpoint is denied", async () => {
    const recorder = routedFetch({ "/applications?": jsonResponse({ error: { code: "Forbidden" } }, 403) });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.applications).toEqual([]);
    expect(scan.completedStages).toContain("activity");
    expect(recorder.requestedPath("/servicePrincipals?")).toBe(true);
  });

  it("surfaces a GraphRequestError instance shape from the collector", () => {
    const error = new GraphRequestError(429, "TooManyRequests", "/v1.0/applications");
    expect(error.name).toBe("GraphRequestError");
    expect(error.status).toBe(429);
    expect(error.message).toContain("/v1.0/applications");
  });
});

describe("progress reporting and checkpoints", () => {
  it("reports one progress event per collection stage with a human-readable detail", async () => {
    const events: ScanProgressEvent[] = [];
    const recorder = routedFetch({
      "/applications?": [{ id: "app-1", appId: "a", displayName: "App", appRoles: [], passwordCredentials: [], keyCredentials: [] }],
      "/servicePrincipals?": [{ id: "sp-1", appId: "a", displayName: "SP", appRoles: [], passwordCredentials: [], keyCredentials: [] }],
      "/users?": [{ id: "user-1", displayName: "Person", userType: "Member" }],
      "/groups?": [{ id: "group-1", displayName: "Group", securityEnabled: true }],
    });
    await scanTenant(clientFor(recorder), TENANT, { now, concurrency: 1, onProgress: (event) => events.push(event) });
    const stages = new Set(events.map((event) => event.stage));
    expect(stages).toEqual(new Set<ScanStage>(["applications", "servicePrincipals", "federatedIdentityCredentials", "usersAndGroups", "groupMemberships", "devices", "administrativeUnits", "delegatedPermissionGrants", "appRoleAssignments", "owners"]));
    expect(events.find((event) => event.stage === "usersAndGroups")?.collected).toBe(2);
    expect(events.every((event) => event.detail.length > 0)).toBe(true);
  });

  it("checkpoints after each stage so a resume can skip completed work", async () => {
    const checkpoints: ScanStage[][] = [];
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, {
      now,
      onCheckpoint: async (partial: RawTenantScan) => { checkpoints.push([...(partial.completedStages ?? [])]); },
    });
    expect(checkpoints.length).toBeGreaterThan(0);
    // Each checkpoint is cumulative and never loses a previously completed stage.
    for (let index = 1; index < checkpoints.length; index += 1) {
      expect(checkpoints[index]!).toEqual(expect.arrayContaining(checkpoints[index - 1]!));
    }
    expect(checkpoints.at(-1)).toEqual(scan.completedStages);
  });

  it("does not re-read a stage that the checkpoint already marked complete", async () => {
    const recorder = routedFetch();
    const checkpoint = rawScan({
      completedStages: ["applications", "servicePrincipals", "usersAndGroups", "groupMemberships", "delegatedPermissionGrants", "appRoleAssignments", "owners"],
      collectedEndpoints: ["/applications"],
    });
    await scanTenant(clientFor(recorder), TENANT, { now, resumeFrom: checkpoint });
    expect(recorder.requestedPath("/applications?")).toBe(false);
    expect(recorder.requestedPath("/servicePrincipals?$select=id,appId")).toBe(false);
    expect(recorder.requestedPath("/users?")).toBe(false);
  });

  it("resumes from a deep copy so the caller's checkpoint is never mutated", async () => {
    const checkpoint = rawScan({ completedStages: ["applications"], collectedEndpoints: ["/applications"] });
    const before = structuredClone(checkpoint);
    await scanTenant(clientFor(routedFetch()), TENANT, { now, resumeFrom: checkpoint });
    expect(checkpoint).toEqual(before);
  });

  it("stamps the scan timestamp from the injected clock", async () => {
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, { now });
    expect(scan.scannedAt).toBe(SCAN_TIME.toISOString());
    expect(scan.tenantId).toBe(TENANT);
  });
});

describe("per-object fan-out", () => {
  it("requests owners and memberships for each collected object with an encoded identifier", async () => {
    const awkwardId = "sp/with space";
    const recorder = routedFetch({
      "/applications?": [{ id: "app-1", appId: "a", displayName: "App", appRoles: [], passwordCredentials: [], keyCredentials: [] }],
      "/servicePrincipals?": [{ id: awkwardId, appId: "a", displayName: "SP", appRoles: [], passwordCredentials: [], keyCredentials: [] }],
      "/groups?": [{ id: "group-1", displayName: "Group", securityEnabled: true }],
      "/members?": [{ id: "user-1", displayName: "Member", userType: "Member" }],
      "/owners?": [{ id: "owner-1", displayName: "Owner" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, concurrency: 2 });
    expect(recorder.requestedPath(`/servicePrincipals/${encodeURIComponent(awkwardId)}/owners`)).toBe(true);
    expect(recorder.requestedPath("/groups/group-1/members")).toBe(true);
    expect(scan.applicationOwners[0]).toMatchObject({ targetId: "app-1", record: { id: "owner-1" } });
    expect(scan.servicePrincipalOwners[0]).toMatchObject({ targetId: awkwardId });
    expect(scan.groupMemberships?.[0]).toMatchObject({ groupId: "group-1", record: { id: "user-1" } });
  });

  it("collects every object when the work list is longer than the concurrency limit", async () => {
    const groups = Array.from({ length: 7 }, (_, index) => ({ id: `group-${index}`, displayName: `Group ${index}`, securityEnabled: true }));
    const recorder = routedFetch({ "/groups?": groups, "/members?": [{ id: "member-1", displayName: "Member" }] });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, concurrency: 3 });
    expect(scan.groupMemberships).toHaveLength(groups.length);
    for (const group of groups) expect(recorder.requestedPath(`/groups/${group.id}/members`)).toBe(true);
  });

  it("tags users and groups with their directory object type", async () => {
    const recorder = routedFetch({
      "/users?": [{ id: "user-1", displayName: "Guest Person", userType: "Guest", externalUserState: "Accepted" }],
      "/groups?": [{ id: "group-1", displayName: "Team", securityEnabled: false }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.users?.[0]?.record).toEqual({ id: "user-1", displayName: "Guest Person", userType: "Guest", externalUserState: "Accepted", "@odata.type": "#microsoft.graph.user" });
    expect(scan.groups?.[0]?.record).toEqual({ id: "group-1", displayName: "Team", userType: null, securityEnabled: false, "@odata.type": "#microsoft.graph.group" });
  });

  it("stores a non-boolean securityEnabled flag as unknown rather than coercing it", async () => {
    const recorder = routedFetch({ "/groups?": [{ id: "group-1", displayName: "Team", securityEnabled: "true" }] });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.groups?.[0]?.record.securityEnabled).toBeNull();
  });
});

describe("optional-stage progress reporting", () => {
  const optionalRoutes = {
    "/roleManagement/directory/roleDefinitions": [{ id: "rd-1", displayName: "Global Administrator" }],
    "/roleManagement/directory/roleAssignments": [{ id: "ra-1", principalId: "user-1", roleDefinitionId: "rd-1" }],
    "/roleManagement/directory/roleEligibilitySchedules": [
      { id: "re-1", principalId: "user-2", roleDefinitionId: "rd-1" },
      { id: "re-2", principalId: "user-3", roleDefinitionId: "rd-1" },
    ],
    "/identity/conditionalAccess/policies": [
      { id: "p-1", displayName: "Require MFA", state: "enabled" },
      { id: "p-2", displayName: "Block legacy", state: "disabled" },
    ],
    "/policies/authorizationPolicy": { id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } },
    "/policies/permissionGrantPolicies?": [],
    "/policies/crossTenantAccessPolicy/partners": [{ tenantId: "33333333-3333-4333-8333-333333333333" }],
    "/auditLogs/signIns": [
      { id: "s-1", createdDateTime: "2026-08-20T09:00:00Z" },
      { id: "s-2", createdDateTime: "2026-08-21T09:00:00Z" },
      { id: "s-3", createdDateTime: "2026-08-22T09:00:00Z" },
    ],
  };

  async function progressFor(scopes: readonly string[]): Promise<ScanProgressEvent[]> {
    const events: ScanProgressEvent[] = [];
    await scanTenant(clientFor(routedFetch(optionalRoutes)), TENANT, {
      now,
      enabledScopes: scopes,
      onProgress: (event) => events.push(event),
    });
    return events;
  }

  it("counts active and eligible role assignments together in the roles stage", async () => {
    const roles = (await progressFor(["RoleManagement.Read.Directory"])).find((event) => event.stage === "roles");
    expect(roles).toEqual({ stage: "roles", collected: 3, detail: "Active and eligible administrative roles collected" });
  });

  it("reports the Conditional Access and cross-tenant stages under Policy.Read.All", async () => {
    const events = await progressFor(["Policy.Read.All"]);
    expect(events.find((event) => event.stage === "conditionalAccess")).toEqual({
      stage: "conditionalAccess", collected: 2, detail: "Conditional Access policies collected",
    });
    expect(events.find((event) => event.stage === "crossTenantAccess")).toEqual({
      stage: "crossTenantAccess", collected: 1, detail: "Partner-specific cross-tenant trust collected",
    });
  });

  it("reports the sign-in activity stage under AuditLog.Read.All", async () => {
    const activity = (await progressFor(["AuditLog.Read.All"])).find((event) => event.stage === "activity");
    expect(activity).toEqual({ stage: "activity", collected: 3, detail: "Time-bounded sign-in activity collected" });
  });

  it("emits no optional-stage progress when the scope is not granted", async () => {
    const events = await progressFor([]);
    for (const stage of ["roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity"] as const) {
      expect(events.some((event) => event.stage === stage), stage).toBe(false);
    }
  });

  it("reports every optional stage when every optional scope is granted", async () => {
    const events = await progressFor(ALL_OPTIONAL_SCOPES);
    for (const stage of ["roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity"] as const) {
      expect(events.some((event) => event.stage === stage), stage).toBe(true);
    }
  });

  it("starts a resumed scan with the stage list the checkpoint recorded", async () => {
    const recorder = routedFetch(optionalRoutes);
    const checkpoint = rawScan({ completedStages: undefined });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, resumeFrom: checkpoint });
    expect(scan.completedStages).toBeDefined();
    expect(scan.completedStages).toContain("applications");
  });
});

describe("application permission sanitization", () => {
  const caller = { id: "sp-1", appId: "app-1", displayName: "Caller" };

  it("keeps only the documented fields of an app role assignment", async () => {
    const recorder = routedFetch({
      "/appRoleAssignedTo": [{
        id: "assign-1", appRoleId: "role-1", principalId: "sp-1", principalType: "ServicePrincipal", resourceId: "sp-2",
        principalDisplayName: 42, resourceDisplayName: "Microsoft Graph", createdDateTime: "2026-08-01T00:00:00Z",
      }],
      "/servicePrincipals?": [caller],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.appRoleAssignments[0]?.record).toEqual({
      id: "assign-1", appRoleId: "role-1", principalId: "sp-1", principalType: "ServicePrincipal", resourceId: "sp-2",
      principalDisplayName: null, resourceDisplayName: "Microsoft Graph",
    });
  });

  it("keeps only the documented fields of a delegated permission grant", async () => {
    const recorder = routedFetch({
      "/oauth2PermissionGrants": [{
        id: "grant-1", clientId: "sp-1", consentType: "Principal", principalId: 7, resourceId: "sp-2",
        scope: "Mail.Read User.Read", expiryTime: "2027-01-01T00:00:00Z",
      }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.oauth2PermissionGrants[0]?.record).toEqual({
      id: "grant-1", clientId: "sp-1", consentType: "Principal", principalId: null, resourceId: "sp-2", scope: "Mail.Read User.Read",
    });
  });

  it("skips the grant endpoint when a record omits a required identifier", async () => {
    const recorder = routedFetch({
      "/oauth2PermissionGrants": [{ id: "grant-2", clientId: "sp-1", consentType: "AllPrincipals", resourceId: "sp-2" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.oauth2PermissionGrants).toEqual([]);
    expect(scan.collectedEndpoints.some((endpoint) => endpoint.startsWith("/oauth2PermissionGrants"))).toBe(false);
    expect(scan.skippedEndpoints.some((endpoint) => endpoint.startsWith("/oauth2PermissionGrants"))).toBe(true);
    expect(scan.errors.find((error) => error.endpoint.startsWith("/oauth2PermissionGrants"))?.code).toBe("unexpected_error");
  });

  it("reports a sanitization failure without leaking the record that caused it", async () => {
    const recorder = routedFetch({
      "/oauth2PermissionGrants": [{ id: "grant-3", clientId: "sp-1", consentType: "AllPrincipals", resourceId: "sp-2", scope: 42, secret: "tenant-detail" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    const error = scan.errors.find((item) => item.endpoint.startsWith("/oauth2PermissionGrants"))!;
    expect(error.message).toBe("The read failed without exposing response data.");
    expect(JSON.stringify(scan.errors)).not.toContain("tenant-detail");
  });

  it("skips the assignment endpoint when a record omits a required identifier", async () => {
    const recorder = routedFetch({
      "/appRoleAssignedTo": [{ id: "assign-2", appRoleId: "role-1", principalId: "sp-1", resourceId: "sp-2" }],
      "/servicePrincipals?": [caller],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.appRoleAssignments).toEqual([]);
    expect(scan.skippedEndpoints.some((endpoint) => endpoint.includes("/appRoleAssignedTo"))).toBe(true);
  });

  it("treats a non-array appRoles payload as no published roles", async () => {
    const recorder = routedFetch({
      "/servicePrincipals?": [{ ...caller, appRoles: "Mail.Read" }],
      "/applications": [{ id: "app-object-1", appId: "app-1", displayName: "App", appRoles: { id: "role-1" } }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.servicePrincipals[0]?.record.appRoles).toEqual([]);
    expect(scan.applications[0]?.record.appRoles).toEqual([]);
  });
});

describe("stage bookkeeping", () => {
  /** Every endpoint fragment a stage reads, keyed by the stage that owns it. */
  const STAGE_ENDPOINTS: Array<[ScanStage, string[]]> = [
    ["applications", ["/applications?$select=id,appId"]],
    ["servicePrincipals", ["/servicePrincipals?$select=id,appId"]],
    ["federatedIdentityCredentials", ["/applications/app-1/federatedIdentityCredentials", "/servicePrincipals?$select=id,servicePrincipalType"]],
    ["usersAndGroups", ["/users?", "/groups?"]],
    ["groupMemberships", ["/groups/group-1/members"]],
    ["devices", ["/devices?"]],
    ["administrativeUnits", ["/directory/administrativeUnits?$select", "/directory/administrativeUnits/au-1/members"]],
    ["delegatedPermissionGrants", ["/oauth2PermissionGrants?"]],
    ["appRoleAssignments", ["/appRoleAssignedTo?"]],
    ["owners", ["/owners?"]],
    ["roles", ["/roleManagement/directory/roleDefinitions"]],
    ["conditionalAccess", ["/identity/conditionalAccess/policies"]],
    ["authorizationPolicy", ["/policies/authorizationPolicy"]],
    ["permissionGrantPolicies", ["/policies/permissionGrantPolicies?", "/policies/permissionGrantPolicies/consent-1/includes", "/policies/permissionGrantPolicies/consent-1/excludes"]],
    ["crossTenantAccess", ["/policies/crossTenantAccessPolicy/partners"]],
    ["activity", ["/auditLogs/signIns"]],
  ];

  const inventory = {
    "/applications?": [{ id: "app-1", appId: "shared", displayName: "App" }],
    "/servicePrincipals?": [{ id: "sp-1", appId: "shared", displayName: "SP" }],
    "/groups?": [{ id: "group-1", displayName: "Finance", securityEnabled: true }],
    "/users?": [{ id: "user-1", displayName: "Avery" }],
    "/devices?": [{ id: "device-1", deviceId: "device-guid-1", displayName: "Laptop" }],
    "/directory/administrativeUnits?": [{ id: "au-1", displayName: "Finance" }],
    "/directory/administrativeUnits/au-1/members": [{ id: "device-1", displayName: "Laptop", "@odata.type": "#microsoft.graph.device" }],
    "/policies/authorizationPolicy": { id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } },
    "/policies/permissionGrantPolicies?": [{ id: "consent-1", displayName: "Consent policy" }],
    "/policies/permissionGrantPolicies/consent-1/includes": [{ id: "include-1" }],
    "/policies/permissionGrantPolicies/consent-1/excludes": [],
  };

  it("records every stage it completed, in the order the scan runs them", async () => {
    const scan = await scanTenant(clientFor(routedFetch(inventory)), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.completedStages).toEqual(STAGE_ENDPOINTS.map(([stage]) => stage));
  });

  it.each(STAGE_ENDPOINTS)("skips the %s reads when the checkpoint already completed that stage", async (stage, endpoints) => {
    const recorder = routedFetch(inventory);
    await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ALL_OPTIONAL_SCOPES,
      resumeFrom: rawScan({ completedStages: [stage] }),
    });
    for (const endpoint of endpoints) expect(recorder.requestedPath(endpoint), `${stage} → ${endpoint}`).toBe(false);
  });

  it.each(STAGE_ENDPOINTS)("still reads the %s endpoints when another stage was the one completed", async (stage, endpoints) => {
    const other: ScanStage = stage === "applications" ? "activity" : "applications";
    const recorder = routedFetch(inventory);
    await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ALL_OPTIONAL_SCOPES,
      resumeFrom: rawScan({ completedStages: [other], applications: stage === "applications" ? [] : [{ endpoint: "/applications", record: { id: "app-1", appId: "shared", displayName: "App", appRoles: [], passwordCredentials: [], keyCredentials: [] } }] }),
    });
    for (const endpoint of endpoints) expect(recorder.requestedPath(endpoint), `${stage} → ${endpoint}`).toBe(true);
  });

  it("records every endpoint it collected, so absence is never mistaken for coverage", async () => {
    const recorder = routedFetch(inventory);
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    for (const [, endpoints] of STAGE_ENDPOINTS) {
      for (const endpoint of endpoints) {
        expect(scan.collectedEndpoints.some((collected) => collected.includes(endpoint)), endpoint).toBe(true);
      }
    }
    expect(scan.skippedEndpoints).toEqual([]);
    expect(scan.errors).toEqual([]);
  });

  it("starts an empty scan with empty collections rather than seeded ones", async () => {
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, { now });
    expect(scan).toMatchObject({
      tenantId: TENANT, applications: [], servicePrincipals: [], appRoleAssignments: [], oauth2PermissionGrants: [],
      applicationOwners: [], servicePrincipalOwners: [], users: [], groups: [], groupMemberships: [],
      devices: [], administrativeUnits: [], administrativeUnitMemberships: [], federatedIdentityCredentials: [],
      roleDefinitions: [], roleAssignments: [], roleEligibilities: [], conditionalAccessPolicies: [],
      signIns: [], crossTenantPartners: [], authorizationPolicies: [], permissionGrantPolicies: [], permissionGrantPolicyIncludes: [], permissionGrantPolicyExcludes: [], skippedEndpoints: [], errors: [],
    });
  });

  it("counts application and service principal owners together", async () => {
    const events: ScanProgressEvent[] = [];
    const recorder = routedFetch({
      ...inventory,
      "/applications/app-1/owners": [{ id: "user-1", displayName: "Avery" }],
      "/servicePrincipals/sp-1/owners": [{ id: "user-2", displayName: "Blake" }, { id: "user-3", displayName: "Casey" }],
    });
    await scanTenant(clientFor(recorder), TENANT, { now, onProgress: (event) => events.push(event) });
    expect(events.find((event) => event.stage === "owners")?.collected).toBe(3);
  });

  it("accepts the highest supported concurrency", async () => {
    const recorder = routedFetch(inventory);
    await expect(scanTenant(clientFor(recorder), TENANT, { now, concurrency: 20 })).resolves.toBeDefined();
    await expect(scanTenant(clientFor(recorder), TENANT, { now, concurrency: 1 })).resolves.toBeDefined();
  });

  it("names its cancellation error so a caller can tell it from a failure", async () => {
    await expect(scanTenant(clientFor(routedFetch()), TENANT, { now, shouldCancel: async () => true }))
      .rejects.toMatchObject({ name: "ScanCancelledError", message: "The scan was cancelled safely." });
  });
});

describe("record sanitization at the edges", () => {
  it("keeps the Graph type annotation of a group member so its kind survives", async () => {
    const recorder = routedFetch({
      "/groups?": [{ id: "group-1", displayName: "Finance", securityEnabled: true }],
      "/members?": [{ id: "member-1", displayName: "Nested", userType: "Member", "@odata.type": "#microsoft.graph.group" }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.groupMemberships?.[0]?.record).toEqual({
      id: "member-1", displayName: "Nested", userType: "Member", "@odata.type": "#microsoft.graph.group",
    });
  });

  it("drops a type annotation that is not a string rather than passing it through", async () => {
    const recorder = routedFetch({
      "/groups?": [{ id: "group-1", displayName: "Finance", securityEnabled: true }],
      "/members?": [{ id: "member-2", displayName: "Odd", "@odata.type": 7 }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now });
    expect(scan.groupMemberships?.[0]?.record["@odata.type"]).toBeUndefined();
  });

  it("records an unknown built-in flag as unknown rather than as false", async () => {
    const recorder = routedFetch({
      "/roleManagement/directory/roleDefinitions": [
        { id: "role-1", displayName: "Custom role", templateId: null },
        { id: "role-2", displayName: "Built in", isBuiltIn: true },
        { id: "role-3", displayName: "Odd", isBuiltIn: "yes" },
      ],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.roleDefinitions?.map((item) => item.record.isBuiltIn)).toEqual([null, true, null]);
  });

  it("accepts only real booleans as partner trust claims", async () => {
    const recorder = routedFetch({
      "/policies/crossTenantAccessPolicy/partners": [{
        tenantId: "33333333-3333-4333-8333-333333333333",
        inboundTrust: { isMfaAccepted: "yes", isCompliantDeviceAccepted: 1, isHybridAzureADJoinedDeviceAccepted: true },
        isInMultiTenantOrganization: "true",
      }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.crossTenantPartners?.[0]?.record).toEqual({
      tenantId: "33333333-3333-4333-8333-333333333333",
      inboundTrust: { isMfaAccepted: false, isCompliantDeviceAccepted: false, isHybridAzureADJoinedDeviceAccepted: true },
      isInMultiTenantOrganization: false,
    });
  });
});

describe("resuming a finished scan", () => {
  const ALL_STAGES: ScanStage[] = [
    "applications", "servicePrincipals", "federatedIdentityCredentials", "usersAndGroups", "groupMemberships", "devices", "administrativeUnits", "delegatedPermissionGrants",
    "appRoleAssignments", "owners", "roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity",
  ];

  it("reads nothing and checkpoints nothing when every stage is already complete", async () => {
    const recorder = routedFetch();
    const checkpoints: RawTenantScan[] = [];
    const scan = await scanTenant(clientFor(recorder), TENANT, {
      now,
      enabledScopes: ALL_OPTIONAL_SCOPES,
      resumeFrom: rawScan({ completedStages: [...ALL_STAGES] }),
      onCheckpoint: async (partial) => { checkpoints.push(partial); },
    });
    expect(recorder.requested).toEqual([]);
    expect(checkpoints).toEqual([]);
    expect(scan.completedStages).toEqual(ALL_STAGES);
  });

  it("adopts an empty stage list when the checkpoint recorded none, then fills it in", async () => {
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, {
      now,
      enabledScopes: ALL_OPTIONAL_SCOPES,
      resumeFrom: rawScan({ completedStages: undefined }),
    });
    expect(scan.completedStages).toEqual(ALL_STAGES);
  });

  it("records only endpoint paths among the endpoints it collected", async () => {
    const scan = await scanTenant(clientFor(routedFetch()), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.collectedEndpoints.length).toBeGreaterThan(0);
    for (const endpoint of scan.collectedEndpoints) expect(endpoint.startsWith("/"), endpoint).toBe(true);
  });

  it("refuses a tenant identifier that only contains a well-formed GUID", async () => {
    const client = clientFor(routedFetch());
    for (const tenantId of [`${TENANT}-extra`, `urn:${TENANT}`]) {
      await expect(scanTenant(client, tenantId), tenantId).rejects.toThrow(/concrete Microsoft Entra tenant ID/);
    }
  });

  it("keeps every partner trust claim Graph reported as a real boolean", async () => {
    const recorder = routedFetch({
      "/policies/crossTenantAccessPolicy/partners": [{
        tenantId: "33333333-3333-4333-8333-333333333333",
        inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: true, isHybridAzureADJoinedDeviceAccepted: true },
        isInMultiTenantOrganization: true,
      }],
    });
    const scan = await scanTenant(clientFor(recorder), TENANT, { now, enabledScopes: ALL_OPTIONAL_SCOPES });
    expect(scan.crossTenantPartners?.[0]?.record).toEqual({
      tenantId: "33333333-3333-4333-8333-333333333333",
      inboundTrust: { isMfaAccepted: true, isCompliantDeviceAccepted: true, isHybridAzureADJoinedDeviceAccepted: true },
      isInMultiTenantOrganization: true,
    });
  });
});
