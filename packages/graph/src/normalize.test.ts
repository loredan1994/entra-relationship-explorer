import { describe, expect, it } from "vitest";
import { assertTenantBoundary } from "@entra-explorer/domain";
import { normalizeTenantScan } from "./normalize";
import { assertReadOnlyScopes, CORE_GRAPH_SCOPES, IDENTITY_SCOPES } from "./permissions";
import type { RawTenantScan } from "./types";

const tenantId = "11111111-1111-4111-8111-111111111111";
const scannedAt = "2026-08-26T12:00:00.000Z";

function rawScan(): RawTenantScan {
  return {
    tenantId,
    scannedAt,
    applications: [{ endpoint: "/applications", record: {
      id: "app-object", appId: "shared-app-id", displayName: "Resource blueprint", publisherDomain: "example.test",
      appRoles: [], passwordCredentials: [], keyCredentials: [],
    } }],
    servicePrincipals: [
      { endpoint: "/servicePrincipals", record: {
        id: "resource-sp", appId: "shared-app-id", displayName: "Resource identity", appRoles: [
          { id: "role-read", value: "Api.Read", isEnabled: true },
          { id: "role-write", value: "Api.Write", isEnabled: true },
        ], passwordCredentials: [], keyCredentials: [],
      } },
      { endpoint: "/servicePrincipals", record: {
        id: "client-sp", appId: "client-app-id", displayName: "Client identity", appRoles: [],
        passwordCredentials: [], keyCredentials: [],
      } },
    ],
    appRoleAssignments: [
      { endpoint: "/servicePrincipals/resource-sp/appRoleAssignedTo", record: {
        id: "assignment-read", appRoleId: "role-read", principalId: "client-sp", principalType: "ServicePrincipal", resourceId: "resource-sp",
      } },
      { endpoint: "/servicePrincipals/resource-sp/appRoleAssignedTo", record: {
        id: "assignment-write", appRoleId: "role-write", principalId: "client-sp", principalType: "ServicePrincipal", resourceId: "resource-sp",
      } },
    ],
    oauth2PermissionGrants: [],
    applicationOwners: [{ endpoint: "/applications/app-object/owners", targetId: "app-object", record: {
      id: "owner-user", displayName: "Synthetic owner", "@odata.type": "#microsoft.graph.user",
    } }],
    servicePrincipalOwners: [],
    collectedEndpoints: ["/applications", "/servicePrincipals", "/servicePrincipals/resource-sp/appRoleAssignedTo"],
    skippedEndpoints: [],
    errors: [],
  };
}

describe("normalizeTenantScan", () => {
  it("joins blueprints and tenant identities and aggregates application roles", () => {
    const snapshot = normalizeTenantScan(rawScan(), { tenantLabel: "Example tenant", snapshotId: "snapshot-one" });
    expect(() => assertTenantBoundary(snapshot)).not.toThrow();
    expect(snapshot.mode).toBe("tenant");
    expect(snapshot.edges.find((edge) => edge.type === "INSTANTIATES_AS")).toMatchObject({
      sourceId: "app-object", targetId: "resource-sp",
    });
    expect(snapshot.edges.find((edge) => edge.type === "CAN_CALL_AS_APP")).toMatchObject({
      sourceId: "client-sp",
      targetId: "resource-sp",
      permissions: ["Api.Read", "Api.Write"],
      evidence: { configured: true, observed: null, completeness: "complete" },
    });
  });

  it("marks an incomplete referenced object as unresolved", () => {
    const raw = rawScan();
    raw.appRoleAssignments[0]!.record.resourceId = "missing-resource";
    raw.appRoleAssignments = [raw.appRoleAssignments[0]!];
    const snapshot = normalizeTenantScan(raw);
    const edge = snapshot.edges.find((candidate) => candidate.type === "CAN_CALL_AS_APP");
    expect(edge?.evidence.completeness).toBe("unresolved");
    expect(snapshot.nodes.find((node) => node.id === "missing-resource")?.label).toBe("Unresolved tenant identity");
  });

  it("preserves partial scan errors without raw response bodies", () => {
    const raw = rawScan();
    raw.errors.push({ endpoint: "/oauth2PermissionGrants", code: "Authorization_RequestDenied", message: "safe" });
    raw.skippedEndpoints.push("/oauth2PermissionGrants");
    const snapshot = normalizeTenantScan(raw);
    expect(snapshot.completion.status).toBe("partial");
    expect(snapshot.completion.errors).toEqual(["/oauth2PermissionGrants: Authorization_RequestDenied"]);
  });
});

describe("permission boundary", () => {
  it("accepts only the documented Phase 1 read scopes", () => {
    expect(() => assertReadOnlyScopes([...IDENTITY_SCOPES, ...CORE_GRAPH_SCOPES])).not.toThrow();
  });

  it("rejects any write-capable or unknown scope", () => {
    expect(() => assertReadOnlyScopes(["https://graph.microsoft.com/Application.ReadWrite.All"])).toThrow(/outside|write/i);
    expect(() => assertReadOnlyScopes(["https://graph.microsoft.com/AuditLog.Read.All"])).toThrow(/outside/i);
  });
});
