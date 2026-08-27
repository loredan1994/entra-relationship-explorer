import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, compareSnapshots } from "@entra-explorer/domain";
import { normalizeTenantScan } from "./normalize";
import { rawScan, sourced } from "./test-support";

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
    expect(snapshot.nodes.find((node) => node.id === "custom-policy")).toMatchObject({ kind: "policy", metadata: { coverage: "unresolved" } });
    expect(snapshot.edges.find((edge) => edge.type === "ASSIGNS_CONSENT_POLICY")).toMatchObject({ evidence: { completeness: "unresolved" } });
  });
});
