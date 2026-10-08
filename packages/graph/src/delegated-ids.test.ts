import { expect, it } from "vitest";
import { normalizeTenantScan } from "./normalize";
import { rawScan, servicePrincipal, sourced } from "./test-support";

function grant(scopes: Array<{ id: string; value?: string | null }> | undefined, value = "Read Write") {
  return normalizeTenantScan(rawScan({
    servicePrincipals: [
      sourced(servicePrincipal({ id: "client", appId: "client-app", displayName: "Client", oauth2PermissionScopes: [{ id: "wrong-resource-id", value: "Read" }] })),
      sourced(servicePrincipal({ id: "resource", appId: "api", displayName: "Resource", oauth2PermissionScopes: scopes })),
    ],
    oauth2PermissionGrants: [sourced({ id: "consent", clientId: "client", resourceId: "resource", consentType: "AllPrincipals", scope: value }, "/oauth2PermissionGrants")],
  })).edges.find(e => e.type === "CAN_CALL_DELEGATED")!;
}

it("joins every consent value to the exact resource catalog and preserves consent provenance", () => {
  const result = grant([{ id: "read-id", value: "Read" }, { id: "write-id", value: "Write" }, { id: "unused", value: "Other" }], "\tWrite  Read\nRead");
  expect(result.permissions).toEqual(["Write", "Read"]);
  expect(result.permissionIds).toEqual(["write-id", "read-id"]);
  expect(result.evidence.sourceEndpoint).toBe("/oauth2PermissionGrants");
  expect(result.evidence.sourceRecordIds).toEqual(["consent"]);
});

it.each([
  undefined, [], [{ id: "read-id", value: "Read" }],
  [{ id: "read-id", value: "read" }, { id: "write-id", value: "Write" }],
  [{ id: "read-id", value: "Read" }, { id: "other-id", value: "Read" }, { id: "write-id", value: "Write" }],
  [{ id: "", value: "Read" }, { id: "write-id", value: "Write" }],
])("keeps permission IDs unknown when the complete exact mapping is unavailable (%j)", scopes => {
  const result = grant(scopes);
  expect(result.permissionIds).toBeUndefined();
  expect(result.permissions).toEqual(["Read", "Write"]);
});

it("deduplicates repeated source definitions and treats empty consent as no granted scope", () => {
  expect(grant([{ id: "r", value: "Read" }, { id: "r", value: "Read" }], "Read").permissionIds).toEqual(["r"]);
  expect(grant(undefined, " \t\n").permissionIds).toEqual([]);
});
