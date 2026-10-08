import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligence, permissionLedger } from "@entra-explorer/domain";
import { scanTenant } from "./scanner";
import { normalizeTenantScan } from "./normalize";
import { clientFor, jsonResponse, rawScan, routedFetch, sourced, TENANT, SCANNED_AT } from "./test-support";

describe("new collection contracts", () => {
  it("collects declarations, definitions and consent audience while dropping secret and certificate material", async () => {
    const recorder = routedFetch({
      "/applications?": [{ id: "app", appId: "client-app", displayName: "Client", requiredResourceAccess: [{ resourceAppId: "api-app", resourceAccess: [{ id: "scope", type: "Scope" }] }], passwordCredentials: [{ keyId: "key", displayName: "deploy", startDateTime: "2025-01-01", endDateTime: "2027-01-01", secretText: "SENTINEL_SECRET" }], keyCredentials: [{ keyId: "cert", key: "SENTINEL_CERTIFICATE", startDateTime: "2025-01-01", endDateTime: "2027-01-01" }] }],
      "/servicePrincipals?": [{ id: "client", appId: "client-app", displayName: "Client" }, { id: "api", appId: "api-app", displayName: "API", oauth2PermissionScopes: [{ id: "scope", value: "Data.Read" }] }],
      "/oauth2PermissionGrants?": [{ id: "grant", clientId: "client", resourceId: "api", consentType: "Principal", principalId: "person", scope: "Data.Read" }],
    });
    const raw = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT) });
    const snapshot = normalizeTenantScan(raw);
    expect(JSON.stringify(raw)).not.toContain("SENTINEL");
    expect(snapshot.nodes.find(n => n.id === "app")!.credentials).toHaveLength(2);
    expect(permissionLedger(snapshot).find(r => r.permission === "Data.Read")).toMatchObject({ status: "requested-and-granted", audience: "One user", principalId: "person" });
    expect(recorder.requested.some(url => url.includes("requiredResourceAccess"))).toBe(true);
    expect(recorder.requested.some(url => url.includes("oauth2PermissionScopes"))).toBe(true);
  });
  it("requires explicit directory-audit opt-in and retains only allowlisted context", async () => {
    const recorder = routedFetch({ "/auditLogs/directoryAudits": [{ id: "audit", activityDateTime: SCANNED_AT, activityDisplayName: "Update application", result: "success", initiatedBy: { user: { id: "actor", userPrincipalName: "SENTINEL_UPN", ipAddress: "SENTINEL_IP" } }, targetResources: [{ id: "app", modifiedProperties: [{ newValue: "SENTINEL_KEY" }] }], additionalDetails: "SENTINEL_DETAIL" }] });
    const client = clientFor(recorder);
    const disabled = await scanTenant(client, TENANT, { now: () => new Date(SCANNED_AT) });
    expect(recorder.requestedPath("directoryAudits")).toBe(false);
    expect(disabled.coverage!.find(c => c.id === "directoryAudits")!.state).toBe("not-enabled");
    const enabled = await scanTenant(client, TENANT, { now: () => new Date(SCANNED_AT), collectDirectoryAudits: true });
    expect(enabled.auditEvents).toEqual([expect.objectContaining({ id: "audit", actor: { id: "actor", kind: "user" }, targetIds: ["app"] })]);
    expect(JSON.stringify(enabled)).not.toContain("SENTINEL");
    const url = recorder.requested.find(url => url.includes("directoryAudits"))!;
    expect(decodeURIComponent(url)).toContain(`activityDateTime le ${SCANNED_AT}`);
    expect(url).toContain("/v1.0/");
  });
  it("marks denied parent inventories and v1.0 membership/activity limitations as incomplete", async () => {
    const recorder = routedFetch({ "/applications?": jsonResponse({ error: { code: "Authorization_RequestDenied", message: "Forbidden" } }, 403), "/groups?": [{ id: "group", displayName: "Group" }] });
    const raw = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT), enabledScopes: ["AuditLog.Read.All"] });
    expect(raw.coverage!.find(c => c.id === "applications")!.state).toBe("denied");
    expect(raw.coverage!.find(c => c.id === "owners")!.state).toBe("partial");
    expect(raw.coverage!.find(c => c.id === "groupMemberships")!.state).toBe("partial");
    expect(raw.coverage!.find(c => c.id === "activity")!.window!.eventClasses).toEqual(["interactiveUser"]);
    expect(raw.coverage!.find(c => c.id === "activity")!.limits).toEqual({ maxPagesPerEndpoint: 10000, maxItemsPerEndpoint: 1000000 });
    const snapshot = normalizeTenantScan(raw);
    expect(snapshot.completion.status).toBe("partial");
    expect(analyzeTenantIntelligence(snapshot).findings.some(f => f.category === "dormant-access")).toBe(false);
  });
  it("cannot certify a consent policy whose exclusion read failed", () => {
    const s = normalizeTenantScan(rawScan({ permissionGrantPolicies: [sourced({ id: "policy", displayName: "Custom" })], collectedEndpoints: ["/policies/permissionGrantPolicies/policy/includes"], skippedEndpoints: ["/policies/permissionGrantPolicies/policy/excludes"] }));
    expect(s.nodes.find(n => n.id === "policy")).toMatchObject({ metadata: { coverage: "partial" }, risk: { level: "review" } });
  });
});
