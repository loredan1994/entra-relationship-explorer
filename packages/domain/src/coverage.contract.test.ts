import { expect, it } from "vitest";
import { coverageMatrix, endpointWasCollected } from "./coverage";
import { snapshot } from "./test-support";
it("provides an explicit unknown record for each historical collector, retaining known records unchanged", () => {
  const s = snapshot([], []);
  const historical = coverageMatrix(s);
  expect(historical.map(c => c.id)).toEqual(["applications", "servicePrincipals", "federatedIdentityCredentials", "usersAndGroups", "groupMemberships", "devices", "administrativeUnits", "delegatedPermissionGrants", "appRoleAssignments", "owners", "roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity", "directoryAudits"]);
  for (const row of historical) expect(row).toMatchObject({ state: "unknown", reason: "This snapshot predates detailed collector coverage. Run another read-only scan to establish it.", collectedAt: null, endpoints: [], failedEndpoints: [], itemCount: 0 });
  expect(historical.find(c => c.id === "applications")).toMatchObject({ label: "Application blueprints", role: "Directory reader access", scope: "Application.Read.All" });
  const recorded = { id: "activity", state: "partial" as const, reason: "Bounded", collectedAt: s.scannedAt, endpoints: ["/auditLogs/signIns"], failedEndpoints: ["/auditLogs/signIns?next=x"], itemCount: 7, scope: "AuditLog.Read.All", window: { startsAt: "2026-07-27T10:00:00Z", endsAt: s.scannedAt, eventClasses: ["interactiveUser"] }, limits: { maxPagesPerEndpoint: 2, maxItemsPerEndpoint: 40 } };
  s.completion.collectors = [{ ...recorded, id: "unknown-collector", itemCount: 999 }, recorded];
  expect(coverageMatrix(s).find(c => c.id === "activity")).toEqual({ ...recorded, label: "User sign-ins", role: "Supported role, such as Reports Reader; available retention varies" });
  expect(coverageMatrix(s)).toHaveLength(17);
});
it.each([
  ["/applications", ["/applications?$select=id"], [], true],
  ["/applications", ["/applications/a"], [], false],
  ["/applications", [], [], false],
  ["/applications?x=y", ["/applications?$select=id"], ["/applications?next=x"], false],
  ["/applications", ["/applications"], ["/servicePrincipals"], true],
  ["/servicePrincipals?$expand=owners", ["/servicePrincipals"], [], false],
  ["/servicePrincipals?$expand=owners", ["/servicePrincipals?$expand=roles"], [], false],
  ["/servicePrincipals?$expand=owners", ["/servicePrincipals?$select=id&$expand=owners"], [], true],
  ["/servicePrincipals?$expand=owners", ["/servicePrincipals?$expand=owners"], ["/servicePrincipals?$expand=roles"], true],
  ["/servicePrincipals?$expand=owners", ["/servicePrincipals?$expand=owners"], ["/servicePrincipals?$select=id&$expand=owners"], false],
] as const)("matches exact endpoint paths and required expansions (%#)", (endpoint, collected, skipped, expected) => {
  const s = snapshot([], []); s.completion.collectedEndpoints = [...collected]; s.completion.skippedEndpoints = [...skipped];
  expect(endpointWasCollected(s, endpoint)).toBe(expected);
});
