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
    const snapshot = normalizeTenantScan(raw, { tenantLabel: "Live acceptance tenant" });
    expect(() => assertTenantBoundary(snapshot)).not.toThrow();
    expect(snapshot.completion.status).toBe("complete");
    expect(snapshot.edges.every((edge) => edge.evidence.observed === null)).toBe(true);
  }, 180_000);
});
