import { describe, expect, it } from "vitest";
import { analyzeFindingLifecycle } from "./finding-lifecycle";
import { edge, node, snapshot, TENANT } from "./test-support";
import type { TenantSnapshot } from "./types";

const orphan = (ownerIds: string[] = []) => node({ id: "app-orphan", kind: "application", label: "Orphan App", ownerIds });
const complete = (id: string, scannedAt: string, ownerIds: string[] = [], endpoints = ["/applications", "/applications/00000000-0000-4000-8000-000000000001/owners"]): TenantSnapshot =>
  snapshot([orphan(ownerIds)], [], { id, scannedAt, completion: { status: "complete", collectedEndpoints: endpoints, skippedEndpoints: [], errors: [] } });

describe("finding lifecycle", () => {
  it("classifies first-seen, consecutive, returned, and no-longer-detected findings", () => {
    const first = complete("snap-1", "2026-08-24T00:00:00.000Z");
    expect(analyzeFindingLifecycle([first]).counts.new).toBe(1);

    const second = complete("snap-2", "2026-08-25T00:00:00.000Z");
    expect(analyzeFindingLifecycle([second, first]).records[0]?.status).toBe("ongoing");

    const absent = complete("snap-3", "2026-08-26T00:00:00.000Z", ["owner"]);
    expect(analyzeFindingLifecycle([absent, second]).records[0]?.status).toBe("no-longer-detected");

    const returned = complete("snap-4", "2026-08-27T00:00:00.000Z");
    expect(analyzeFindingLifecycle([returned, absent, second]).records[0]?.status).toBe("returned");
  });

  it("treats an absence as unconfirmed when the current scan is partial", () => {
    const before = complete("snap-before", "2026-08-26T00:00:00.000Z");
    const current = { ...complete("snap-current", "2026-08-27T00:00:00.000Z", ["owner"]), completion: { status: "partial" as const, collectedEndpoints: ["/applications"], skippedEndpoints: ["/applications/{id}/owners"], errors: ["denied"] } };
    expect(analyzeFindingLifecycle([current, before]).records.find(({ finding }) => finding.category === "ownership")?.status).toBe("unconfirmed");
  });

  it("treats an absence as unconfirmed when required endpoint coverage regressed", () => {
    const before = complete("snap-before", "2026-08-26T00:00:00.000Z");
    const current = complete("snap-current", "2026-08-27T00:00:00.000Z", ["owner"], ["/applications"]);
    expect(analyzeFindingLifecycle([current, before]).records.find(({ finding }) => finding.category === "ownership")?.status).toBe("unconfirmed");
  });

  it("treats moving activity-window queries as the same collected endpoint family", () => {
    const caller = node({ id: "caller", kind: "servicePrincipal", label: "Caller", ownerIds: ["owner"] });
    const resource = node({ id: "resource", kind: "servicePrincipal", label: "Resource", ownerIds: ["owner"] });
    const configured = edge("CAN_CALL_AS_APP", caller, resource, { id: "grant", permissions: ["Api.Read"], evidence: { sourceEndpoint: "/servicePrincipals/caller/appRoleAssignedTo" } });
    const before = snapshot([caller, resource], [configured], { id: "before", scannedAt: "2026-08-26T00:00:00.000Z", completion: { status: "complete", collectedEndpoints: ["/servicePrincipals/caller/appRoleAssignedTo", "/auditLogs/signIns?$filter=createdDateTime ge 2026-07-27"], skippedEndpoints: [], errors: [] } });
    const observed = edge("OBSERVED_CALL", caller, resource, { id: "observed", evidence: { sourceEndpoint: "/auditLogs/signIns?$filter=createdDateTime ge 2026-07-28" } });
    const current = snapshot([caller, resource], [configured, observed], { id: "current", scannedAt: "2026-08-27T00:00:00.000Z", completion: { status: "complete", collectedEndpoints: ["/servicePrincipals/caller/appRoleAssignedTo", "/auditLogs/signIns?$filter=createdDateTime ge 2026-07-28"], skippedEndpoints: [], errors: [] } });
    const dormant = analyzeFindingLifecycle([current, before]).records.find(({ finding }) => finding.category === "dormant-access");
    expect(dormant?.status).toBe("no-longer-detected");
  });

  it("orders lifecycle output deterministically", () => {
    const a = node({ id: "app-a", kind: "application", label: "Zed", ownerIds: [] });
    const b = node({ id: "app-b", kind: "application", label: "Abe", ownerIds: [] });
    const current = snapshot([a, b], [], { id: "current", scannedAt: "2026-08-27T00:00:00.000Z" });
    const titles = analyzeFindingLifecycle([current]).records.map(({ finding }) => finding.title);
    expect(titles).toEqual([...titles].sort());
  });

  it("uses the stable finding id when severity, lifecycle, and title all tie", () => {
    const zed = node({ id: "app-z", kind: "application", label: "Duplicate", ownerIds: [] });
    const abe = node({ id: "app-a", kind: "application", label: "Duplicate", ownerIds: [] });
    const current = snapshot([zed, abe], [], { id: "current", scannedAt: "2026-08-27T00:00:00.000Z" });
    const records = analyzeFindingLifecycle([current]).records.filter(({ finding }) => finding.category === "ownership");
    const ids = records.map(({ finding }) => finding.id);
    expect(ids).toEqual([...ids].sort());
  });

  it("rejects empty, cross-tenant, and incorrectly ordered history", () => {
    expect(() => analyzeFindingLifecycle([])).toThrow(/at least one/i);
    const newest = complete("new", "2026-08-27T00:00:00.000Z");
    const older = complete("old", "2026-08-26T00:00:00.000Z");
    expect(() => analyzeFindingLifecycle([older, newest])).toThrow(/newest to oldest/i);
    const other = { ...older, tenant: { tenantId: "d0000000-0000-4000-8000-000000000000", tenantLabel: "Other" }, nodes: older.nodes.map((item) => ({ ...item, tenantId: "d0000000-0000-4000-8000-000000000000" })) };
    expect(() => analyzeFindingLifecycle([newest, other])).toThrow(/same tenant/i);
    expect(newest.tenant.tenantId).toBe(TENANT);
  });
});
