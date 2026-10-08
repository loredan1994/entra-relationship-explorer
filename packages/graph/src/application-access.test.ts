import { describe, expect, it, vi } from "vitest";
import { applicationAccessReviews } from "@entra-explorer/domain";
import { scanTenant } from "./scanner";
import { normalizeTenantScan } from "./normalize";
import { clientFor, routedFetch, SCANNED_AT, TENANT, rawScan, servicePrincipal, sourced, assignment } from "./test-support";

describe("application access collection contract", () => {
  it("collects sign-in controls and publisher context with existing GET reads while stripping unrelated data", async () => {
    const publisher = { verifiedPublisherId: "publisher-id", displayName: "Publisher", privateDetails: "SENTINEL" };
    const recorder = routedFetch({
      "/applications?": [{ id: "app", appId: "api-app", displayName: "Registration", signInAudience: "AzureADMultipleOrgs", verifiedPublisher: publisher, notes: "SENTINEL" }],
      "/servicePrincipals?": [{ id: "api", appId: "api-app", displayName: "API", signInAudience: "AzureADMultipleOrgs", accountEnabled: false, appRoleAssignmentRequired: true, appOwnerOrganizationId: "publisher-tenant", preferredSingleSignOnMode: "saml", verifiedPublisher: publisher, notificationEmailAddresses: ["SENTINEL"], appRoles: [{ id: "reader", value: "Read" }] }],
      "/servicePrincipals/api/appRoleAssignedTo": [{ id: "assignment", appRoleId: "reader", principalId: "group", principalType: "Group", resourceId: "api", principalDisplayName: "Operators" }],
    });
    const raw = await scanTenant(clientFor(recorder), TENANT, { now: () => new Date(SCANNED_AT) });
    const s = normalizeTenantScan(raw);
    expect(JSON.stringify(raw)).not.toContain("SENTINEL");
    expect(s.nodes.find(n => n.id === "api")?.applicationProfile).toEqual({ signInAudience: "AzureADMultipleOrgs", accountEnabled: false, assignmentRequired: true, homeTenantId: "publisher-tenant", verifiedPublisherId: "publisher-id", verifiedPublisherName: "Publisher", preferredSsoMode: "saml" });
    expect(s.nodes.find(n => n.id === "app")?.applicationProfile?.signInAudience).toBe("AzureADMultipleOrgs");
    const review = applicationAccessReviews(s).find(r => r.identity.id === "api")!;
    expect(review.registration?.id).toBe("app");
    expect(review.incoming).toHaveLength(1);
    expect(review.incoming[0]).toMatchObject({ type: "ASSIGNED_TO", permissions: ["Read"], evidence: { sourceRecordIds: ["assignment"], completeness: "complete" } });
    expect(review.assignmentsCollected).toBe(true);
    const select = new URL(recorder.requested.find(u => u.includes("/servicePrincipals?"))!).searchParams.get("$select")!;
    for (const field of ["accountEnabled", "appRoleAssignmentRequired", "signInAudience", "verifiedPublisher", "appOwnerOrganizationId", "preferredSingleSignOnMode"]) expect(select.split(",")).toContain(field);
    for (const [, init] of vi.mocked(recorder.fetchImpl).mock.calls) expect(init?.method).toBe("GET");
    expect(recorder.requested.some(url => url.includes("/auditLogs/"))).toBe(false);
  });
  it("does not turn omitted or malformed controls into disabled, unassigned or verified state", async () => {
    const recorder = routedFetch({ "/servicePrincipals?": [
      { id: "missing", appId: "one", displayName: "Missing" },
      { id: "invalid", appId: "two", displayName: "Invalid", accountEnabled: "false", appRoleAssignmentRequired: 0, signInAudience: 42, verifiedPublisher: "SENTINEL" },
      { id: "enabled", appId: "three", displayName: "Enabled", accountEnabled: true, appRoleAssignmentRequired: false },
    ] });
    const s = normalizeTenantScan(await scanTenant(clientFor(recorder), TENANT));
    for (const id of ["missing", "invalid"]) expect(s.nodes.find(n => n.id === id)?.applicationProfile).toMatchObject({ accountEnabled: null, assignmentRequired: null, signInAudience: null, verifiedPublisherId: null });
    expect(s.nodes.find(n => n.id === "enabled")?.applicationProfile).toMatchObject({ accountEnabled: true, assignmentRequired: false });
  });
});


it.each(["User", "Group", "ServicePrincipal"])("recognizes default access for a %s without inventing a named permission", (principalType) => {
  const zero = "00000000-0000-0000-0000-000000000000";
  const raw = rawScan({ servicePrincipals: [sourced(servicePrincipal({ id: "api", appId: "api-app", displayName: "API", appRolesCollected: true }))], appRoleAssignments: [sourced(assignment({ id: "assignment", appRoleId: zero, principalId: "caller", principalType, resourceId: "api" }))] });
  const view = applicationAccessReviews(normalizeTenantScan(raw)).find(r => r.identity.id === "api")!;
  expect(view.incoming[0]).toMatchObject({ permissions: ["Default access (no specific app role)"], permissionIds: [zero], evidence: { completeness: "complete", sourceRecordIds: ["assignment"] } });
  raw.servicePrincipals[0]!.record.appRoles = [{ id: "named-role", value: "Read" }];
  expect(applicationAccessReviews(normalizeTenantScan(raw)).find(r => r.identity.id === "api")!.incoming[0]!.evidence.completeness).toBe("unresolved");
  raw.servicePrincipals = [];
  expect(applicationAccessReviews(normalizeTenantScan(raw)).find(r => r.identity.id === "api")!.incoming[0]!.evidence.completeness).toBe("unresolved");
});


it("keeps default assignments unresolved when the requested role inventory was omitted", async () => {
  const run = async (roles: unknown) => {
    const recorder = routedFetch({
      "/servicePrincipals?": [{ id: "api", appId: "api-app", displayName: "API", ...(roles === undefined ? {} : { appRoles: roles }) }],
      "/servicePrincipals/api/appRoleAssignedTo": [{ id: "default", appRoleId: "00000000-0000-0000-0000-000000000000", principalId: "person", principalType: "User", resourceId: "api" }],
    });
    return applicationAccessReviews(normalizeTenantScan(await scanTenant(clientFor(recorder), TENANT)))[0]!.incoming[0]!;
  };
  expect((await run([])).evidence.completeness).toBe("complete");
  expect((await run(undefined)).evidence.completeness).toBe("unresolved");
  expect((await run(null)).evidence.completeness).toBe("unresolved");
});
