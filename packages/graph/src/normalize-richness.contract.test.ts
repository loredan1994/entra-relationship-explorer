import { expect, it } from "vitest";
import { normalizeTenantScan } from "./normalize";
import { application, servicePrincipal, rawScan, sourced, SCANNED_AT, TENANT } from "./test-support";
import type { CollectorCoverage } from "@entra-explorer/domain";
it.each(["partial", "denied", "unavailable", "complete", "not-enabled", "unknown"] as CollectorCoverage["state"][])("derives completion from %s coverage independently of errors", state => {
  const entry: CollectorCoverage = { id: "devices", state, reason: "Synthetic", scope: "Directory.Read.All", endpoints: [], failedEndpoints: [], itemCount: 0, collectedAt: SCANNED_AT };
  const s = normalizeTenantScan(rawScan({ coverage: [{ ...entry, id: "applications", state: "complete" }, entry] }));
  expect(s.completion.status).toBe(["partial", "denied", "unavailable"].includes(state) ? "partial" : "complete");
  expect(s.completion.collectors).toEqual([{ ...entry, id: "applications", state: "complete" }, entry]);
});
it("normalizes requested role and scope IDs, credential metadata, and permission definition fallbacks", () => {
  const s = normalizeTenantScan(rawScan({
    applications: [sourced(application({ id: "app", appId: "app-id", displayName: "App", verifiedPublisher: { verifiedPublisherId: "publisher", displayName: "Publisher" }, requiredResourceAccess: [{ resourceAppId: "resource", resourceAccess: [{ id: "role", type: "Role" }, { id: "scope", type: "Scope" }] }], passwordCredentials: [{ keyId: "password", displayName: "Deployment", startDateTime: "2026-01-01", endDateTime: "2027-01-01" }], keyCredentials: [{ keyId: "certificate" }] }), "/applications")],
    servicePrincipals: [sourced(servicePrincipal({ id: "sp", appId: "resource", displayName: "API", appRoles: [{ id: "value", value: "Data.Read", displayName: "Label" }, { id: "label", value: "", displayName: "Fallback" }, { id: "id" }], oauth2PermissionScopes: [{ id: "scope", value: "Scope.Read" }, { id: "scope-id" }] }))],
  }));
  expect(s.nodes.find(n => n.id === "app")).toMatchObject({ applicationProfile: { verifiedPublisherId: "publisher", verifiedPublisherName: "Publisher" }, requestedPermissions: [{ resourceAppId: "resource", permissionId: "role", kind: "application" }, { resourceAppId: "resource", permissionId: "scope", kind: "delegated" }], credentials: [
    { id: "password", kind: "password", label: "Deployment", startsAt: "2026-01-01", expiresAt: "2027-01-01", sourceEndpoint: "/applications" },
    { id: "certificate", kind: "certificate", label: null, startsAt: null, expiresAt: null, sourceEndpoint: "/applications" },
  ] });
  expect(s.nodes.find(n => n.id === "sp")!.permissionDefinitions).toEqual([{ id: "value", value: "Data.Read", kind: "application" }, { id: "label", value: "Fallback", kind: "application" }, { id: "id", value: "id", kind: "application" }, { id: "scope", value: "Scope.Read", kind: "delegated" }, { id: "scope-id", value: "scope-id", kind: "delegated" }]);
});
it("summarizes the next usable expiry instead of an old or exactly expired rotated key", () => {
  const s = normalizeTenantScan(rawScan({ applications: [sourced(application({ id: "app", appId: "app-id", displayName: "App", passwordCredentials: [{ keyId: "old", endDateTime: "2026-01-01" }, { keyId: "boundary", endDateTime: SCANNED_AT }, { keyId: "next", endDateTime: "2027-01-01" }] }))] }));
  expect(s.nodes[0]!.credential).toEqual({ status: "healthy", expiresAt: "2027-01-01T00:00:00.000Z" });
});
it.each(["api-app", "api"])("resolves v1.0 user sign-in app IDs and resource %s without requiring beta identity fields", resourceId => {
  const s = normalizeTenantScan(rawScan({ servicePrincipals: [sourced(servicePrincipal({ id: "wrong", appId: "wrong-app", displayName: "Unrelated" })), sourced(servicePrincipal({ id: "client", appId: "client-app", displayName: "Client" })), sourced(servicePrincipal({ id: "api", appId: "api-app", displayName: "API" }))], signIns: [sourced({ id: "event", createdDateTime: SCANNED_AT, appId: "client-app", resourceId, status: { errorCode: 0 } }, "/auditLogs/signIns")] }));
  expect(s.edges.filter(e => e.type === "OBSERVED_CALL")).toMatchObject([{ sourceId: "client", targetId: "api", evidence: { configured: false, observed: { lastSeenAt: SCANNED_AT } } }]);
});
it.each([["AllPrincipals", "all-users"], ["Principal", "single-user"], ["other", "unknown"]] as const)("preserves %s consent audience and principal ID", (consentType, audience) => {
  const s = normalizeTenantScan(rawScan({ oauth2PermissionGrants: [sourced({ id: "grant", clientId: "client", resourceId: "api", consentType, scope: "Data.Read", principalId: "person" })] }));
  expect(s.edges.find(e => e.type === "CAN_CALL_DELEGATED")!.consent).toEqual({ audience, principalId: "person" });
});
it("does not infer permission definitions from non-default role IDs when the role catalog is empty", () => {
  const s = normalizeTenantScan(rawScan({ servicePrincipals: [sourced(servicePrincipal({ id: "api", appId: "api-app", displayName: "API", appRolesCollected: true }))], appRoleAssignments: [sourced({ id: "grant", principalId: "client", resourceId: "api", appRoleId: "unknown", principalType: "ServicePrincipal" })] }));
  expect(s.edges.find(e => e.type === "CAN_CALL_AS_APP")!.evidence.completeness).toBe("unresolved");
});
it("retains sparse directory metadata and true posture flags", () => {
  const s = normalizeTenantScan(rawScan({ devices: [sourced({ id: "device", deviceId: "device-id", isManaged: true })], administrativeUnits: [sourced({ id: "long-unit-identifier", isMemberManagementRestricted: true })], authorizationPolicies: [sourced({ id: "auth", displayName: "Auth", blockMsolPowerShell: true, defaultUserRolePermissions: { allowedToCreateSecurityGroups: true, allowedToReadBitlockerKeysForOwnedDevice: true } })] }));
  expect(s.nodes.find(n => n.id === "device")!.metadata!.managed).toBe(true);
  expect(s.nodes.find(n => n.id === "long-unit-identifier")).toMatchObject({ label: "Administrative unit long-uni", metadata: { memberManagementRestricted: true } });
  expect(s.nodes.find(n => n.id === "auth")).toMatchObject({ metadata: { blockMsolPowerShell: true, allowedToCreateSecurityGroups: true, allowedToReadBitlockerKeysForOwnedDevice: true, permissionGrantPoliciesAssigned: "", userConsentState: "unknown" }, risk: { level: "review", reason: "User consent policy assignments were not collected." } });
  expect(s.nodes.map(n => n.id)).toEqual(["device", "long-unit-identifier", "auth"]);
});
it("keeps administrative scopes exact and ensures membership-only objects exist with explainable edges", () => {
  const s = normalizeTenantScan(rawScan({ administrativeUnits: [sourced({ id: "unit", displayName: "Unit" })], administrativeUnitMemberships: [{ ...sourced({ id: "person", displayName: "Person", "@odata.type": "#microsoft.graph.user" }, "/directory/administrativeUnits/unit/members"), administrativeUnitId: "unit" }], roleDefinitions: [sourced({ id: "role", displayName: "Role" })], roleAssignments: ["/administrativeUnits/unit", "/prefix/administrativeUnits/unit", "/administrativeUnits/unit/child"].map((directoryScopeId, i) => sourced({ id: `assignment-${i}`, principalId: "person", roleDefinitionId: "role", directoryScopeId })) }));
  expect(s.nodes.find(n => n.id === "person")!.kind).toBe("user");
  expect(s.edges.filter(e => e.type === "ACTIVE_IN_ROLE").map(e => e.scope!.objectId)).toEqual(["unit", null, null]);
  const membership = s.edges.find(e => e.type === "IN_ADMINISTRATIVE_UNIT")!;
  expect(membership).toEqual({ id: expect.stringMatching(/^administrative-unit-member:[a-f0-9]{24}$/), tenantId: TENANT, type: "IN_ADMINISTRATIVE_UNIT", sourceId: "person", targetId: "unit", plainLabel: "In administrative unit", permissions: [], evidence: { configured: true, observed: null, scannedAt: SCANNED_AT, sourceEndpoint: "/directory/administrativeUnits/unit/members", sourceRecordIds: ["person", "unit"], sourceObjectId: "person", targetObjectId: "unit", completeness: "complete" } });
});
it("preserves all configured federation evidence and distinguishes two credentials on a parent", () => {
  const s = normalizeTenantScan(rawScan({ applications: [sourced(application({ id: "app", appId: "client", displayName: "App" }))], federatedIdentityCredentials: ["one", "two"].map(id => ({ ...sourced({ id, name: id, issuer: "https://issuer.test", subject: "subject", audiences: ["one", "two"] }, "/applications/app/federatedIdentityCredentials"), parentId: "app", parentType: "application" as const })) }));
  const links = s.edges.filter(e => e.type === "FEDERATES_AS");
  expect(new Set(links.map(e => e.id)).size).toBe(2);
  for (const [i, id] of ["one", "two"].entries()) {
    expect(s.nodes.find(n => n.id === `federated-credential:app:${id}`)!.metadata!.audiences).toBe("one, two");
    expect(links[i]).toEqual({ id: expect.stringMatching(/^federates:[a-f0-9]{24}$/), tenantId: TENANT, type: "FEDERATES_AS", sourceId: `federated-credential:app:${id}`, targetId: "app", plainLabel: "Can federate as", permissions: [], evidence: { configured: true, observed: null, scannedAt: SCANNED_AT, sourceEndpoint: "/applications/app/federatedIdentityCredentials", sourceRecordIds: ["app", id], sourceObjectId: `federated-credential:app:${id}`, targetObjectId: "app", completeness: "complete" } });
  }
});

it("keeps consent conditions isolated by policy and certifies only successful include and exclude reads", () => {
  const raw = rawScan({
    authorizationPolicies: [sourced({ id: "auth", displayName: "Authorization", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy", "ManagePermissionGrantsForSelf.custom"] } }, "/policies/authorizationPolicy")],
    permissionGrantPolicies: [sourced({ id: "microsoft-user-default-legacy", displayName: "Legacy" }), sourced({ id: "custom", displayName: "Custom", description: " Trimmed description " })],
    permissionGrantPolicyIncludes: [
      { ...sourced({ id: "one", permissionClassification: "low", permissionType: "delegated", clientApplicationsFromVerifiedPublisherOnly: true }), policyId: "custom" },
      { ...sourced({ id: "two", permissionClassification: "medium", permissionType: "application", clientApplicationsFromVerifiedPublisherOnly: false }), policyId: "custom" },
      { ...sourced({ id: "other" }), policyId: "unrelated" },
    ],
    permissionGrantPolicyExcludes: [{ ...sourced({ id: "other" }), policyId: "unrelated" }],
    collectedEndpoints: ["/policies/permissionGrantPolicies/custom/includes?$select=id", "/policies/permissionGrantPolicies/custom/excludes", "/policies/permissionGrantPolicies/microsoft-user-default-legacy/includes", "/policies/permissionGrantPolicies/microsoft-user-default-legacy/excludes"],
    skippedEndpoints: ["/policies/permissionGrantPolicies/other/excludes"],
  });
  const s = normalizeTenantScan(raw);
  expect(s.nodes.find(n => n.id === "auth")).toMatchObject({ metadata: { permissionGrantPoliciesAssigned: "ManagePermissionGrantsForSelf.microsoft-user-default-legacy, ManagePermissionGrantsForSelf.custom" }, risk: { level: "high" } });
  expect(s.nodes.find(n => n.id === "microsoft-user-default-legacy")).toMatchObject({ description: "Permission grant policy (consent policy) collected from Microsoft Graph.", metadata: { includeCount: 0, excludeCount: 0, permissionTypes: "none", permissionClassifications: "none", verifiedPublishersOnly: false, coverage: "complete" }, risk: { level: "high", reason: "This built-in policy permits broad user consent when assigned." } });
  expect(s.nodes.find(n => n.id === "custom")).toMatchObject({ description: "Trimmed description", metadata: { includeCount: 2, excludeCount: 0, permissionTypes: "delegated, application", permissionClassifications: "low, medium", verifiedPublishersOnly: false, coverage: "complete" } });
  const links = s.edges.filter(e => e.type === "ASSIGNS_CONSENT_POLICY");
  expect(new Set(links.map(e => e.id)).size).toBe(2);
  expect(links.find(e => e.targetId === "custom")).toEqual({ id: expect.stringMatching(/^consent-policy:[a-f0-9]{24}$/), tenantId: TENANT, type: "ASSIGNS_CONSENT_POLICY", sourceId: "auth", targetId: "custom", plainLabel: "Assigns consent policy", permissions: [], evidence: { configured: true, observed: null, scannedAt: SCANNED_AT, sourceEndpoint: "/policies/authorizationPolicy", sourceRecordIds: ["auth", "custom"], sourceObjectId: "auth", targetObjectId: "custom", completeness: "complete" } });
  for (const part of ["includes", "excludes"]) {
    const failed = structuredClone(raw); failed.skippedEndpoints.push(`/policies/permissionGrantPolicies/custom/${part}?page=2`);
    expect(normalizeTenantScan(failed).nodes.find(n => n.id === "custom")).toMatchObject({ metadata: { coverage: "partial" }, risk: { level: "review", reason: "Consent conditions are unavailable or incomplete; zero collected conditions is not assurance." } });
  }
});

it("prioritizes inventory membership details over sparse references and rejects a non-unit target", () => {
  const raw = rawScan({ applications: [sourced(application({ id: "app", appId: "app-id", displayName: "App" }))], applicationOwners: [{ ...sourced({ id: "person" }), targetId: "app" }], administrativeUnitMemberships: [{ ...sourced({ id: "person", displayName: "Member inventory", "@odata.type": "#microsoft.graph.user" }), administrativeUnitId: "app" }] });
  const s = normalizeTenantScan(raw);
  expect(s.nodes.find(n => n.id === "person")!.label).toBe("Member inventory");
  expect(s.edges.filter(e => e.type === "IN_ADMINISTRATIVE_UNIT")).toEqual([]);
});
it("distinguishes membership IDs and empty delegated definition inventory", () => {
  const raw = rawScan({ administrativeUnits: [sourced({ id: "unit" })], administrativeUnitMemberships: ["one", "two"].map(id => ({ ...sourced({ id }), administrativeUnitId: "unit" })), servicePrincipals: [sourced(servicePrincipal({ id: "sp", appId: "client", displayName: "Client" }))] });
  const s = normalizeTenantScan(raw);
  expect(s.edges.filter(e => e.type === "IN_ADMINISTRATIVE_UNIT")).toHaveLength(2);
  expect(s.nodes.find(n => n.id === "sp")!.permissionDefinitions).toEqual([]);
});
it("leaves policy detail unconfirmed when another object occupies the referenced ID", () => {
  const s = normalizeTenantScan(rawScan({ users: [sourced({ id: "custom", "@odata.type": "#microsoft.graph.user" })], authorizationPolicies: [sourced({ id: "auth", displayName: "Auth", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["custom"] } })] }));
  expect(s.edges.find(e => e.type === "ASSIGNS_CONSENT_POLICY")!.evidence.completeness).toBe("unresolved");
});
it("does not accept unrelated successful endpoints as proof of consent-policy coverage", () => {
  const raw = rawScan({ permissionGrantPolicies: [sourced({ id: "custom", displayName: "Custom" })], collectedEndpoints: ["/unrelated"] });
  expect(normalizeTenantScan(raw).nodes[0]!.metadata!.coverage).toBe("partial");
});

it("calls user consent disabled only for an explicitly empty policy assignment inventory", () => {
  const s = normalizeTenantScan(rawScan({ authorizationPolicies: [sourced({ id: "auth-empty", displayName: "Auth", defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] } })] }));
  expect(s.nodes.find(n => n.id === "auth-empty")).toMatchObject({ metadata: { userConsentState: "disabled" }, risk: { level: "low", reason: "User consent is disabled by the default authorization policy." } });
});
