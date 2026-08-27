import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";

const getEntraConfig = vi.fn();
const getServerSession = vi.fn();
const recentSnapshots = vi.fn();
const recordAccess = vi.fn();

vi.mock("./config", () => ({ getEntraConfig: () => getEntraConfig() }));
vi.mock("./backend", () => ({ getBackend: async () => ({ recentSnapshots, recordAccess }) }));
vi.mock("./auth/session-store", () => ({
  SESSION_COOKIE: "entra_explorer_session",
  getServerSession: (...args: unknown[]) => getServerSession(...args),
}));

const { loadExportSnapshot } = await import("./export-snapshot");

const liveConfig = { enabled: true, tenantId: TENANT };

/** `null` stands for a request with no session cookie at all; the default is a present one. */
function request(cookieValue: string | null = "session-cookie"): NextRequest {
  return { cookies: { get: () => (cookieValue === null ? undefined : { value: cookieValue }) } } as unknown as NextRequest;
}

function tenantSnapshot(id = "snap-1"): TenantSnapshot {
  return { ...cleanProjectFixture, id, tenant: { tenantId: TENANT, tenantLabel: "Contoso" }, mode: "tenant" };
}

beforeEach(() => {
  vi.clearAllMocks();
  getEntraConfig.mockReturnValue(liveConfig);
  getServerSession.mockResolvedValue({ id: "session-1", tenantId: TENANT });
  recentSnapshots.mockResolvedValue([tenantSnapshot()]);
});

describe("demo exports", () => {
  it("exports the sample snapshot without a session when live access is off", async () => {
    getEntraConfig.mockReturnValue({ enabled: false, reason: "off" });
    expect(await loadExportSnapshot(request(), "graph_csv")).toBe(cleanProjectFixture);
    expect(getServerSession).not.toHaveBeenCalled();
    expect(recordAccess).not.toHaveBeenCalled();
  });
});

describe("authentication", () => {
  it("answers 401 when there is no session", async () => {
    getServerSession.mockResolvedValue(null);
    const result = await loadExportSnapshot(request(null), "graph_csv");
    // A request with no cookie must look up nothing rather than fail on a missing value.
    expect(getServerSession).toHaveBeenCalledWith(undefined, liveConfig);
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(401);
    expect(await (result as Response).text()).toBe("Authentication required.");
  });

  it("answers 401 rather than exporting across a tenant boundary", async () => {
    getServerSession.mockResolvedValue({ id: "session-1", tenantId: OTHER_TENANT });
    const result = await loadExportSnapshot(request(), "graph_csv");
    expect((result as Response).status).toBe(401);
    expect(recentSnapshots).not.toHaveBeenCalled();
    expect(recordAccess).not.toHaveBeenCalled();
  });

  it("reads the session from the request cookie", async () => {
    await loadExportSnapshot(request("cookie-value"), "graph_csv");
    expect(getServerSession).toHaveBeenCalledWith("cookie-value", liveConfig);
  });
});

describe("snapshot availability", () => {
  it("answers 404 when the tenant has no completed scan", async () => {
    recentSnapshots.mockResolvedValue([]);
    const result = await loadExportSnapshot(request(), "graph_csv");
    expect((result as Response).status).toBe(404);
    expect(await (result as Response).text()).toBe("No tenant snapshot is available.");
    expect(recordAccess).not.toHaveBeenCalled();
  });

  it("exports only the newest snapshot for the session's tenant", async () => {
    const snapshot = tenantSnapshot("snap-newest");
    recentSnapshots.mockResolvedValue([snapshot]);
    expect(await loadExportSnapshot(request(), "graph_csv")).toBe(snapshot);
    expect(recentSnapshots).toHaveBeenCalledWith(TENANT, 1);
  });
});

describe("audit trail", () => {
  it("records the export against the tenant, session, and snapshot before returning data", async () => {
    const snapshot = tenantSnapshot("snap-audited");
    recentSnapshots.mockResolvedValue([snapshot]);
    await loadExportSnapshot(request(), "attack_flow_json");
    expect(recordAccess).toHaveBeenCalledWith(TENANT, "session-1", "export", "attack_flow_json", "snap-audited");
  });

  it("names the resource type the caller supplied, so each export is distinguishable", async () => {
    for (const resourceType of ["graph_csv", "findings_csv", "attack_flow_json"]) {
      await loadExportSnapshot(request(), resourceType);
      expect(recordAccess).toHaveBeenCalledWith(TENANT, "session-1", "export", resourceType, "snap-1");
    }
    expect(recordAccess).toHaveBeenCalledTimes(3);
  });

  it("propagates a failure to record the export rather than exporting unaudited", async () => {
    recordAccess.mockRejectedValue(new Error("audit write failed"));
    await expect(loadExportSnapshot(request(), "graph_csv")).rejects.toThrow("audit write failed");
  });
});
