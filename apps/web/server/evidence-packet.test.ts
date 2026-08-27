import { analyzeTenantIntelligenceHistory, cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

const loadExportSnapshotHistory = vi.fn();
const getEntraConfig = vi.fn();
const getServerSession = vi.fn();
const getThreatReview = vi.fn();

vi.mock("./export-snapshot", () => ({ loadExportSnapshotHistory: (...args: unknown[]) => loadExportSnapshotHistory(...args) }));
vi.mock("./config", () => ({ getEntraConfig: () => getEntraConfig() }));
vi.mock("./auth/session-store", () => ({ SESSION_COOKIE: "entra_explorer_session", getServerSession: (...args: unknown[]) => getServerSession(...args) }));
vi.mock("./backend", () => ({ getBackend: async () => ({ getThreatReview }) }));

const { loadEvidencePacket } = await import("./evidence-packet");

function snapshot(): TenantSnapshot { return structuredClone(cleanProjectFixture); }
function request(query: string, cookie = "session-cookie"): NextRequest {
  return { nextUrl: new URL(`http://127.0.0.1/api/export/evidence${query}`), cookies: { get: () => ({ value: cookie }) } } as unknown as NextRequest;
}

beforeEach(() => {
  vi.clearAllMocks();
  getEntraConfig.mockReturnValue({ enabled: false });
  loadExportSnapshotHistory.mockResolvedValue([snapshot()]);
  getServerSession.mockResolvedValue({ id: "session", tenantId: cleanProjectFixture.tenant.tenantId });
  getThreatReview.mockResolvedValue(null);
});

describe("evidence packet request boundary", () => {
  it("requires one explicitly typed subject before loading tenant data", async () => {
    for (const query of ["", "?kind=tenant&id=x", "?kind=finding", "?kind=path&id=%20"]) {
      const result = await loadEvidencePacket(request(query), "evidence_packet_json");
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(400);
    }
    expect(loadExportSnapshotHistory).not.toHaveBeenCalled();
  });

  it("propagates authentication and snapshot responses from the shared export boundary", async () => {
    const denied = new Response("Authentication required.", { status: 401 });
    loadExportSnapshotHistory.mockResolvedValue(denied);
    expect(await loadEvidencePacket(request("?kind=finding&id=x"), "evidence_packet_json")).toBe(denied);
  });

  it("builds finding and path packets from retained history", async () => {
    const current = snapshot();
    loadExportSnapshotHistory.mockResolvedValue([current]);
    const intelligence = analyzeTenantIntelligenceHistory([current]);
    const finding = intelligence.findings[0]!;
    const path = intelligence.paths[0]!;
    const findingPacket = await loadEvidencePacket(request(`?kind=finding&id=${finding.id}`), "evidence_packet_json");
    const pathPacket = await loadEvidencePacket(request(`?kind=path&id=${path.id}`), "evidence_packet_markdown");

    expect(findingPacket).toMatchObject({ packetType: "finding", finding: { id: finding.id } });
    expect(pathPacket).toMatchObject({ packetType: "attack-path", attackPath: { id: path.id } });
    expect(loadExportSnapshotHistory).toHaveBeenCalledWith(expect.anything(), "evidence_packet_markdown");
  });

  it("includes the current encrypted review in live mode", async () => {
    const current = snapshot();
    const finding = analyzeTenantIntelligenceHistory([current]).findings.find((item) => item.attackPathId)!;
    getEntraConfig.mockReturnValue({ enabled: true, tenantId: current.tenant.tenantId });
    getThreatReview.mockResolvedValue({ findingId: finding.id, snapshotId: current.id, tenantId: current.tenant.tenantId, disposition: "mitigating", owner: "IAM", expiresAt: null, assumption: "Change scheduled", updatedAt: current.scannedAt });
    const packet = await loadEvidencePacket(request(`?kind=path&id=${finding.attackPathId}`), "evidence_packet_json");

    expect(getServerSession).toHaveBeenCalledWith("session-cookie", expect.objectContaining({ enabled: true }));
    expect(getThreatReview).toHaveBeenCalledWith(current.tenant.tenantId, current.id, finding.id);
    expect(packet).toMatchObject({ review: { disposition: "mitigating", sourceSnapshotId: current.id } });
  });

  it("omits review context when the second tenant guard cannot confirm the session", async () => {
    const current = snapshot();
    const finding = analyzeTenantIntelligenceHistory([current]).findings[0]!;
    getEntraConfig.mockReturnValue({ enabled: true, tenantId: current.tenant.tenantId });
    getServerSession.mockResolvedValue({ id: "session", tenantId: "other-tenant" });
    const packet = await loadEvidencePacket(request(`?kind=finding&id=${finding.id}`), "evidence_packet_json");
    expect(packet).toMatchObject({ review: null });
    expect(getThreatReview).not.toHaveBeenCalled();
  });

  it("keeps a live packet review-free when no current decision exists", async () => {
    const current = snapshot();
    const finding = analyzeTenantIntelligenceHistory([current]).findings[0]!;
    getEntraConfig.mockReturnValue({ enabled: true, tenantId: current.tenant.tenantId });
    getThreatReview.mockResolvedValue(null);
    const packet = await loadEvidencePacket(request(`?kind=finding&id=${finding.id}`), "evidence_packet_json");
    expect(packet).toMatchObject({ review: null });
    expect(getThreatReview).toHaveBeenCalled();
  });

  it("returns subject-specific 404 responses", async () => {
    const finding = await loadEvidencePacket(request("?kind=finding&id=missing"), "evidence_packet_json");
    const path = await loadEvidencePacket(request("?kind=path&id=missing"), "evidence_packet_json");
    expect(await (finding as Response).text()).toBe("Finding not found.");
    expect((finding as Response).status).toBe(404);
    expect(await (path as Response).text()).toBe("Attack path not found.");
  });

  it("does not disguise tenant-history integrity failures as missing subjects", async () => {
    const current = snapshot();
    const other = snapshot();
    other.tenant.tenantId = "other";
    loadExportSnapshotHistory.mockResolvedValue([current, other]);
    await expect(loadEvidencePacket(request("?kind=finding&id=x"), "evidence_packet_json")).rejects.toThrow("same tenant");
  });
});
