import { expect, it } from "vitest";
import { scanTenant } from "./scanner";
import { clientFor, jsonResponse, routedFetch, SCANNED_AT, TENANT } from "./test-support";
import type { ScanProgressEvent } from "./types";
it("keeps failed singleton policy reads out of inventory and reports the failed endpoint", async () => {
  const recorder = routedFetch({ "/policies/authorizationPolicy": jsonResponse({ error: { code: "Authorization_RequestDenied", message: "Forbidden" } }, 403) });
  const progress: ScanProgressEvent[] = [];
  const scan = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT), enabledScopes: ["Policy.Read.All"], onProgress: p => progress.push(p) });
  expect(scan.authorizationPolicies).toEqual([]);
  expect(scan.skippedEndpoints.some(e => e.startsWith("/policies/authorizationPolicy"))).toBe(true);
  expect(scan.errors).toContainEqual(expect.objectContaining({ code: "Authorization_RequestDenied" }));
  expect(progress).toContainEqual({ stage: "authorizationPolicy", collected: 0, detail: "Authorization policy collected" });
});
it("reports child collection counts and retains explicit directory object types", async () => {
  const recorder = routedFetch({
    "/directory/administrativeUnits/unit/members": [{ id: "person" }],
    "/directory/administrativeUnits?": [{ id: "unit" }],
    "/devices?": [{ id: "device", deviceId: "device-id" }],
    "/policies/permissionGrantPolicies/policy/includes": [{ id: "include" }],
    "/policies/permissionGrantPolicies/policy/excludes": [{ id: "exclude" }, { id: "exclude2" }],
    "/policies/permissionGrantPolicies?": [{ id: "policy", displayName: "Policy" }],
  });
  const progress: ScanProgressEvent[] = [];
  const scan = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT), enabledScopes: ["Policy.Read.PermissionGrant"], onProgress: p => progress.push(p) });
  expect(progress).toContainEqual({ stage: "administrativeUnits", collected: 1, detail: "Administrative unit membership collected" });
  expect(progress).toContainEqual({ stage: "permissionGrantPolicies", collected: 3, detail: "Consent policy conditions collected" });
  expect(progress).toContainEqual({ stage: "permissionGrantPolicies", collected: 1, detail: "Consent policies collected" });
  expect(scan.devices![0]!.record["@odata.type"]).toBe("#microsoft.graph.device");
  expect(scan.administrativeUnits![0]!.record["@odata.type"]).toBe("#microsoft.graph.administrativeUnit");
});
it("allowlists manifest permissions and ignores non-managed federation expansion records", async () => {
  const recorder = routedFetch({
    "$expand=federatedIdentityCredentials": [
      { id: "not-managed", servicePrincipalType: "Application", federatedIdentityCredentials: [{ id: "ignored", name: "Ignored", issuer: "https://issuer.test", subject: "subject" }] },
      { id: "managed", servicePrincipalType: "ManagedIdentity" },
    ],
    "/applications?": [{ id: "app", appId: "client", displayName: "Client", requiredResourceAccess: [{ resourceAppId: "api", resourceAccess: [{ id: "role", type: "Role", extra: "SECRET" }, { id: "scope", type: "Scope" }, { id: "unknown", type: "Other" }] }, { resourceAppId: "empty" }] }],
    "/servicePrincipals?": [{ id: "sp", appId: "client", displayName: "Client", verifiedPublisher: null }],
  });
  const scan = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT) });
  expect(scan.applications[0]!.record.requiredResourceAccess).toEqual([{ resourceAppId: "api", resourceAccess: [{ id: "role", type: "Role" }, { id: "scope", type: "Scope" }] }, { resourceAppId: "empty", resourceAccess: [] }]);
  expect(scan.servicePrincipals[0]!.record.verifiedPublisher).toBeNull();
  expect(scan.federatedIdentityCredentials).toEqual([]);
});
it("bounds audit dates and activity text, preserving sparse actor and target information without private fields", async () => {
  const recorder = routedFetch({ "/auditLogs/directoryAudits": [
    { id: "application", activityDateTime: SCANNED_AT, activityDisplayName: "x".repeat(301), result: "failure", initiatedBy: { app: { servicePrincipalId: "actor", secret: "SECRET" } }, targetResources: [{ id: "app" }, { id: 9 }, {}, null, 1, "invalid"] },
    { id: "unknown", activityDateTime: SCANNED_AT, activityDisplayName: "Change" },
    { id: "empty-user", activityDateTime: SCANNED_AT, activityDisplayName: "Change", initiatedBy: { user: {} }, targetResources: "invalid" },
    { id: "empty-actor", activityDateTime: SCANNED_AT, activityDisplayName: "Change", initiatedBy: {} },
  ] });
  const progress: ScanProgressEvent[] = [];
  const scan = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT), collectDirectoryAudits: true, onProgress: p => progress.push(p) });
  const endpoint = scan.auditEvents![0]!.sourceEndpoint;
  expect(decodeURIComponent(endpoint)).toContain("activityDateTime ge 2026-07-27T12:00:00.000Z and activityDateTime le 2026-08-26T12:00:00.000Z");
  expect(scan.auditEvents).toEqual([
    { id: "application", tenantId: TENANT, occurredAt: SCANNED_AT, activity: "x".repeat(300), result: "failure", actor: { id: "actor", kind: "application" }, targetIds: ["app"], sourceEndpoint: endpoint },
    { id: "unknown", tenantId: TENANT, occurredAt: SCANNED_AT, activity: "Change", result: "unknown", actor: { id: null, kind: "unknown" }, targetIds: [], sourceEndpoint: endpoint },
    { id: "empty-user", tenantId: TENANT, occurredAt: SCANNED_AT, activity: "Change", result: "unknown", actor: { id: null, kind: "user" }, targetIds: [], sourceEndpoint: endpoint },
    { id: "empty-actor", tenantId: TENANT, occurredAt: SCANNED_AT, activity: "Change", result: "unknown", actor: { id: null, kind: "unknown" }, targetIds: [], sourceEndpoint: endpoint },
  ]);
  expect(progress).toContainEqual({ stage: "directoryAudits", collected: 4, detail: "Time-bounded directory change evidence collected" });
});

it("preserves sparse authorization fields and ignores scalar publisher values", async () => {
  const recorder = routedFetch({ "/policies/authorizationPolicy": { id: "auth", displayName: "Authorization" }, "/servicePrincipals?": [{ id: "sp", appId: "client", displayName: "Client", verifiedPublisher: "invalid" }] });
  const scan = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT), enabledScopes: ["Policy.Read.All"] });
  expect(scan.authorizationPolicies![0]!.record.defaultUserRolePermissions).toEqual({ allowedToCreateApps: null, allowedToCreateSecurityGroups: null, allowedToCreateTenants: null, allowedToReadBitlockerKeysForOwnedDevice: null, allowedToReadOtherUsers: null, permissionGrantPoliciesAssigned: undefined });
  expect(scan.servicePrincipals[0]!.record.verifiedPublisher).toBeNull();
});

it("never invents federation audiences when Graph omits the field", async () => {
  const recorder = routedFetch({ "/applications?": [{ id: "app", appId: "client", displayName: "App" }], "/applications/app/federatedIdentityCredentials": [{ id: "fic", name: "Trust", issuer: "https://issuer.example", subject: "subject" }] });
  const scan = await scanTenant(clientFor(recorder), TENANT);
  expect(scan.federatedIdentityCredentials![0]!.record.audiences).toEqual([]);
});
