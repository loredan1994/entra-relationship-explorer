import { describe, expect, it } from "vitest";
import { assertTenantBoundary } from "@entra-explorer/domain";
import { ReadOnlyGraphClient } from "./client";
import { normalizeTenantScan } from "./normalize";
import { scanTenant } from "./scanner";

const accessToken = process.env.LIVE_GRAPH_TOKEN;
const tenantId = process.env.LIVE_TENANT_ID;

describe.skipIf(!accessToken || !tenantId)("live read-only tenant acceptance", () => {
  it("collects and normalizes the approved inventory without mutation", async () => {
    const raw = await scanTenant(new ReadOnlyGraphClient(accessToken!, { maxRetries: 8 }), tenantId!, { concurrency: 4 });
    expect(raw.applications.length).toBeGreaterThan(0);
    expect(raw.servicePrincipals.length).toBeGreaterThan(0);
    expect(raw.errors).toEqual([]);
    expect(raw.skippedEndpoints).toEqual([]);

    // A successful v1.0 read still cannot establish complete workload membership.
    // Assert every collector explicitly so unrelated partial/denied reads cannot pass.
    const hasGroups = (raw.groups?.length ?? 0) > 0;
    const expectedCoverage = {
      applications: "complete",
      servicePrincipals: "complete",
      federatedIdentityCredentials: "complete",
      usersAndGroups: "complete",
      groupMemberships: hasGroups ? "partial" : "complete",
      devices: "complete",
      administrativeUnits: "complete",
      delegatedPermissionGrants: "complete",
      appRoleAssignments: "complete",
      owners: "complete",
      roles: "not-enabled",
      conditionalAccess: "not-enabled",
      authorizationPolicy: "not-enabled",
      permissionGrantPolicies: "not-enabled",
      crossTenantAccess: "not-enabled",
      activity: "not-enabled",
      directoryAudits: "not-enabled",
    };
    expect(Object.fromEntries((raw.coverage ?? []).map(c => [c.id, c.state]))).toEqual(expectedCoverage);
    if (hasGroups) {
      expect(raw.coverage?.find(c => c.id === "groupMemberships")?.reason).toContain("Graph v1.0 group members can omit service principals");
    }
    const snapshot = normalizeTenantScan(raw, { tenantLabel: "Live acceptance tenant" });
    expect(() => assertTenantBoundary(snapshot)).not.toThrow();
    expect(snapshot.completion.status).toBe(hasGroups ? "partial" : "complete");
    expect(snapshot.edges.every((edge) => edge.evidence.observed === null)).toBe(true);
    expect(snapshot.edges.every((edge) => edge.evidence.sourceEndpoint && edge.evidence.sourceObjectId && edge.evidence.targetObjectId)).toBe(true);
  }, 180_000);
});
