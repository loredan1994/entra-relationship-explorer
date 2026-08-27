import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, compareSnapshots } from "@entra-explorer/domain";
import { normalizeTenantScan } from "./normalize";
import { rawScan, SCANNED_AT, sourced, TENANT } from "./test-support";

describe("new collector normalization", () => {
  it("resolves device membership and administrative-unit role scope without using the display name as identity", () => {
    const scan = rawScan({
      devices: [sourced({ id: "device-1", deviceId: "device-guid", displayName: "Finance laptop", accountEnabled: true })],
      administrativeUnits: [sourced({ id: "au-1", displayName: "Finance", description: "Scoped administration" })],
      administrativeUnitMemberships: [{ ...sourced({ id: "device-1", displayName: "Finance laptop", "@odata.type": "#microsoft.graph.device" }), administrativeUnitId: "au-1" }],
      roleDefinitions: [sourced({ id: "role-1", displayName: "User Administrator" })],
      roleAssignments: [sourced({ id: "assignment-1", principalId: "user-1", roleDefinitionId: "role-1", directoryScopeId: "/administrativeUnits/au-1" })],
    });
    const snapshot = normalizeTenantScan(scan, { snapshotId: "snapshot-1" });
    expect(snapshot.nodes.find((node) => node.id === "device-1")).toMatchObject({ kind: "device", metadata: { deviceId: "device-guid" } });
    expect(snapshot.nodes.find((node) => node.id === "au-1")).toMatchObject({ kind: "administrativeUnit", label: "Finance" });
    expect(snapshot.edges.find((edge) => edge.type === "IN_ADMINISTRATIVE_UNIT")).toMatchObject({ sourceId: "device-1", targetId: "au-1" });
    expect(snapshot.edges.find((edge) => edge.type === "ACTIVE_IN_ROLE")).toMatchObject({ scope: { directoryScopeId: "/administrativeUnits/au-1", objectId: "au-1" }, evidence: { completeness: "complete" } });

    const renamed = normalizeTenantScan({ ...scan, administrativeUnits: [sourced({ id: "au-1", displayName: "Finance EU" })] }, { snapshotId: "snapshot-2" });
    const diff = compareSnapshots(snapshot, renamed);
    expect(diff.changes.filter((change) => change.subject === "relationship")).toEqual([]);
    expect(diff.changes).toContainEqual(expect.objectContaining({ id: "au-1", subject: "object", kind: "changed" }));
  });

  it("preserves an unknown directory scope as unresolved evidence", () => {
    const snapshot = normalizeTenantScan(rawScan({
      roleDefinitions: [sourced({ id: "role-1", displayName: "User Administrator" })],
      roleAssignments: [sourced({ id: "assignment-1", principalId: "user-1", roleDefinitionId: "role-1", directoryScopeId: "/administrativeUnits/missing" })],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "ACTIVE_IN_ROLE")).toMatchObject({ scope: { directoryScopeId: "/administrativeUnits/missing", objectId: null }, evidence: { completeness: "unresolved" } });
  });

  it("builds an inferred privileged path from an application federated credential", () => {
    const snapshot = normalizeTenantScan(rawScan({
      applications: [sourced({ id: "app-1", appId: "client-app", displayName: "Deployment app", appRoles: [], passwordCredentials: [], keyCredentials: [] })],
      servicePrincipals: [
        sourced({ id: "sp-1", appId: "client-app", displayName: "Deployment identity", appRoles: [], passwordCredentials: [], keyCredentials: [] }),
        sourced({ id: "graph", appId: "graph-app", displayName: "Microsoft Graph", appRoles: [{ id: "role-1", value: "Directory.ReadWrite.All", isEnabled: true }], passwordCredentials: [], keyCredentials: [] }),
      ],
      federatedIdentityCredentials: [{ ...sourced({ id: "fic-1", name: "github-main", issuer: "https://token.actions.githubusercontent.com", subject: "repo:example/project:ref:refs/heads/main", audiences: ["api://AzureADTokenExchange"], description: null }, "/applications/app-1/federatedIdentityCredentials"), parentId: "app-1", parentType: "application" }],
      appRoleAssignments: [sourced({ id: "grant-1", appRoleId: "role-1", principalId: "sp-1", principalType: "ServicePrincipal", resourceId: "graph" })],
    }));
    const federation = snapshot.edges.find((edge) => edge.type === "FEDERATES_AS");
    expect(federation).toMatchObject({ sourceId: "federated-credential:app-1:fic-1", targetId: "app-1", evidence: { sourceRecordIds: ["app-1", "fic-1"] } });
    const finding = analyzeTenantIntelligence(snapshot).findings.find((item) => item.category === "federated-identity");
    expect(finding).toMatchObject({ severity: "critical", evidenceClass: "inferred" });
    expect(finding?.uncertainty.join(" ")).toMatch(/does not prove.*token/i);
  });

  it("connects managed-identity federation directly to its parent identity", () => {
    const snapshot = normalizeTenantScan(rawScan({
      servicePrincipals: [sourced({ id: "mi-1", appId: "mi-app", displayName: "Build identity", servicePrincipalType: "ManagedIdentity", appRoles: [], passwordCredentials: [], keyCredentials: [] })],
      federatedIdentityCredentials: [{ ...sourced({ id: "fic-1", name: "cluster", issuer: "https://issuer.example", subject: "system:serviceaccount:build:agent", audiences: ["api://AzureADTokenExchange"] }), parentId: "mi-1", parentType: "managedIdentity" }],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "FEDERATES_AS")).toMatchObject({ targetId: "mi-1" });
  });

  it("reports the legacy broad-consent assignment but not disabled user consent", () => {
    const legacy = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy";
    const snapshot = normalizeTenantScan(rawScan({
      authorizationPolicies: [sourced({ id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [legacy] } }, "/policies/authorizationPolicy")],
      permissionGrantPolicies: [sourced({ id: "microsoft-user-default-legacy", displayName: "Legacy user consent" })],
      permissionGrantPolicyIncludes: [{ ...sourced({ id: "include-1", permissionType: "delegated", permissions: ["all"] }), policyId: "microsoft-user-default-legacy" }],
    }));
    expect(snapshot.edges.find((edge) => edge.type === "ASSIGNS_CONSENT_POLICY")).toMatchObject({ evidence: { completeness: "complete" } });
    expect(analyzeTenantIntelligence(snapshot).findings).toContainEqual(expect.objectContaining({ category: "consent-policy", severity: "high", evidenceClass: "configured" }));

    const disabled = normalizeTenantScan(rawScan({ authorizationPolicies: [sourced({ id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } })] }));
    expect(disabled.nodes.find((node) => node.id === "authorizationPolicy")?.metadata?.userConsentState).toBe("disabled");
    expect(analyzeTenantIntelligence(disabled).findings.some((item) => item.category === "consent-policy")).toBe(false);
  });

  it("keeps an assigned policy visible when consent-policy detail was not collected", () => {
    const snapshot = normalizeTenantScan(rawScan({ authorizationPolicies: [sourced({ id: "authorizationPolicy", displayName: "Authorization policy", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.custom-policy"] } })] }));
    expect(snapshot.nodes.find((node) => node.id === "custom-policy")).toEqual({ id: "custom-policy", tenantId: TENANT, kind: "policy", label: "custom-policy", description: "Assigned permission grant policy whose detail was not collected.", ownerIds: [], metadata: { policyType: "permissionGrant", coverage: "unresolved" }, risk: { level: "review", reason: "The policy assignment is known, but its include and exclude conditions are unavailable." } });
    expect(snapshot.edges.find((edge) => edge.type === "ASSIGNS_CONSENT_POLICY")).toMatchObject({ evidence: { completeness: "unresolved" } });
  });

  it("normalizes sparse and fully populated collector records without inventing evidence", () => {
    const snapshot = normalizeTenantScan(rawScan({
      users: [sourced({ id: "user-1", displayName: "Person", userType: "Member" })],
      groups: [sourced({ id: "group-1", displayName: "Group" })],
      devices: [
        sourced({ id: "device-1", deviceId: "abcdefgh-1234", displayName: " ", accountEnabled: false, isCompliant: true, isManaged: false, isManagementRestricted: true, operatingSystem: "Linux", operatingSystemVersion: "1", profileType: "RegisteredDevice", registrationDateTime: "2026-01-01T00:00:00Z", trustType: "Workplace" }),
        sourced({ id: "device-unknown", deviceId: "unknown-state" }),
      ],
      administrativeUnits: [sourced({ id: "au-empty", displayName: " ", description: " ", isMemberManagementRestricted: false, membershipType: "Dynamic", membershipRuleProcessingState: "On", visibility: "HiddenMembership" })],
      groupMemberships: [
        { ...sourced({ id: "nested-au", displayName: "Nested scope", "@odata.type": "#microsoft.graph.administrativeUnit" }), groupId: "group-1" },
        { ...sourced({ id: "directory-device", deviceId: "directory-device", "@odata.type": "#microsoft.graph.device" }), groupId: "group-1" },
      ],
      administrativeUnitMemberships: [
        { ...sourced({ id: "directory-device", deviceId: "directory-device", "@odata.type": "#microsoft.graph.device" }), administrativeUnitId: "au-empty" },
        { ...sourced({ id: "user-1", displayName: "Person", "@odata.type": "#microsoft.graph.user" }), administrativeUnitId: "missing" },
        { ...sourced({ id: "user-1", displayName: "Person", "@odata.type": "#microsoft.graph.user" }), administrativeUnitId: "device-1" },
      ],
      authorizationPolicies: [
        sourced({ id: "auth-empty", displayName: "Default authorization" }),
        sourced({ id: "auth-custom", displayName: "Custom authorization", allowInvitesFrom: "adminsAndGuestInviters", allowEmailVerifiedUsersToJoinOrganization: true, blockMsolPowerShell: false, defaultUserRolePermissions: { allowedToCreateApps: true, allowedToCreateSecurityGroups: false, allowedToCreateTenants: true, allowedToReadBitlockerKeysForOwnedDevice: false, allowedToReadOtherUsers: true, permissionGrantPoliciesAssigned: ["custom-policy"] } }),
      ],
      permissionGrantPolicies: [sourced({ id: "custom-policy", displayName: "Custom consent", description: "Restricted policy" })],
      permissionGrantPolicyIncludes: [
        { ...sourced({ id: "include-1", permissionClassification: "low", permissionType: "delegated", clientApplicationsFromVerifiedPublisherOnly: true }), policyId: "custom-policy" },
        { ...sourced({ id: "include-2", permissionClassification: null, permissionType: null, clientApplicationsFromVerifiedPublisherOnly: true }), policyId: "custom-policy" },
      ],
      permissionGrantPolicyExcludes: [{ ...sourced({ id: "exclude-1" }), policyId: "custom-policy" }],
      federatedIdentityCredentials: [{ ...sourced({ id: "orphan", name: "orphan", issuer: "https://issuer", subject: "subject", audiences: [] }), parentId: "missing-parent", parentType: "application" }],
    }));
    expect(snapshot.nodes.find((node) => node.id === "device-1")).toEqual({
      id: "device-1", tenantId: TENANT, kind: "device", label: "Device abcdefgh", description: "Directory device collected from Microsoft Graph.", ownerIds: [],
      metadata: { deviceId: "abcdefgh-1234", accountEnabled: false, compliant: true, managed: false, managementRestricted: true, operatingSystem: "Linux", operatingSystemVersion: "1", profileType: "RegisteredDevice", registrationDateTime: "2026-01-01T00:00:00Z", trustType: "Workplace" },
      risk: { level: "low", reason: "The directory device is disabled." },
    });
    expect(snapshot.nodes.find((node) => node.id === "device-unknown")).toMatchObject({ metadata: { accountEnabled: null }, risk: { level: "review", reason: "Device posture is inventory evidence and must be interpreted with management and compliance context." } });
    expect(snapshot.nodes.find((node) => node.id === "au-empty")).toEqual({
      id: "au-empty", tenantId: TENANT, kind: "administrativeUnit", label: "Administrative unit au-empty", description: "Administrative unit (directory scope) collected from Microsoft Graph.", ownerIds: [],
      metadata: { memberManagementRestricted: false, membershipType: "Dynamic", membershipRuleProcessingState: "On", visibility: "HiddenMembership" },
      risk: { level: "low", reason: "Administrative units scope directory membership and role assignments; presence alone is not a risk finding." },
    });
    expect(snapshot.nodes.find((node) => node.id === "nested-au")?.kind).toBe("administrativeUnit");
    expect(snapshot.nodes.find((node) => node.id === "directory-device")?.kind).toBe("device");
    expect(snapshot.nodes.find((node) => node.id === "auth-empty")?.metadata?.userConsentState).toBe("disabled");
    expect(snapshot.nodes.find((node) => node.id === "auth-custom")).toEqual({
      id: "auth-custom", tenantId: TENANT, kind: "policy", label: "Custom authorization", description: "Tenant authorization policy collected from Microsoft Graph.", ownerIds: [],
      metadata: { policyType: "authorization", allowInvitesFrom: "adminsAndGuestInviters", emailVerifiedUsersCanJoin: true, blockMsolPowerShell: false, allowedToCreateApps: true, allowedToCreateSecurityGroups: false, allowedToCreateTenants: true, allowedToReadBitlockerKeysForOwnedDevice: false, allowedToReadOtherUsers: true, permissionGrantPoliciesAssigned: "custom-policy", userConsentState: "configured" },
      risk: { level: "low", reason: "User consent policy assignments require review in context." },
    });
    expect(snapshot.nodes.find((node) => node.id === "custom-policy")).toEqual({
      id: "custom-policy", tenantId: TENANT, kind: "policy", label: "Custom consent", description: "Restricted policy", ownerIds: [],
      metadata: { policyType: "permissionGrant", includeCount: 2, excludeCount: 1, permissionClassifications: "low", permissionTypes: "delegated", verifiedPublishersOnly: true, coverage: "complete" },
      risk: { level: "low", reason: "Consent policy conditions require contextual review." },
    });
    expect(snapshot.nodes.find((node) => node.id === "federated-credential:missing-parent:orphan")).toEqual({
      id: "federated-credential:missing-parent:orphan", tenantId: TENANT, kind: "federatedCredential", label: "orphan", description: "Federated identity credential (workload trust) collected from Microsoft Graph.", ownerIds: [],
      metadata: { credentialId: "orphan", parentId: "missing-parent", parentType: "application", issuer: "https://issuer", subject: "subject", audiences: "", description: null },
      risk: { level: "review", reason: "A matching external token can authenticate as the configured workload identity; configured trust does not prove token issuance or use." },
    });
    expect(snapshot.edges.find((edge) => edge.type === "IN_ADMINISTRATIVE_UNIT")).toMatchObject({ sourceId: "directory-device", evidence: { completeness: "partial" } });
    expect(snapshot.edges.some((edge) => edge.type === "FEDERATES_AS" && edge.sourceId.includes("orphan"))).toBe(false);
    expect(snapshot.edges.find((edge) => edge.type === "ASSIGNS_CONSENT_POLICY")).toMatchObject({ targetId: "custom-policy", evidence: { completeness: "complete" } });
    expect(snapshot.edges.find((edge) => edge.type === "IN_ADMINISTRATIVE_UNIT")?.evidence).toEqual({ configured: true, observed: null, scannedAt: SCANNED_AT, sourceEndpoint: "/test-endpoint", sourceRecordIds: ["directory-device", "au-empty"], sourceObjectId: "directory-device", targetObjectId: "au-empty", completeness: "partial" });

    const sparsePolicyScan = rawScan({ permissionGrantPolicies: [sourced({ id: "sparse-policy", displayName: "Sparse consent" })] });
    delete sparsePolicyScan.permissionGrantPolicyIncludes;
    delete sparsePolicyScan.permissionGrantPolicyExcludes;
    expect(normalizeTenantScan(sparsePolicyScan).nodes.find((node) => node.id === "sparse-policy")).toMatchObject({
      metadata: { includeCount: 0, excludeCount: 0, permissionClassifications: "none", permissionTypes: "none", verifiedPublishersOnly: false },
    });
  });
});
