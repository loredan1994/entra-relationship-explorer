import { analyzeTenantIntelligenceHistory, buildFindingEvidencePacket, cleanProjectFixture } from "@entra-explorer/domain";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

const loadEvidencePacket = vi.fn();
vi.mock("@/server/evidence-packet", () => ({ loadEvidencePacket: (...args: unknown[]) => loadEvidencePacket(...args) }));

const { GET: getJson } = await import("../app/api/export/evidence-packet.json/route");
const { GET: getMarkdown } = await import("../app/api/export/evidence-packet.md/route");

const request = {} as NextRequest;
const finding = analyzeTenantIntelligenceHistory([cleanProjectFixture]).findings[0]!;
const packet = buildFindingEvidencePacket([cleanProjectFixture], finding.id);

beforeEach(() => { vi.clearAllMocks(); loadEvidencePacket.mockResolvedValue(packet); });

describe("evidence packet export routes", () => {
  it("returns versioned pretty JSON with safe download headers", async () => {
    const response = await getJson(request);
    expect(loadEvidencePacket).toHaveBeenCalledWith(request, "evidence_packet_json");
    expect(response.headers.get("content-type")).toContain("application/vnd.entra-explorer.evidence+json");
    expect(response.headers.get("content-disposition")).toContain("finding-evidence");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await response.json()).toMatchObject({ schemaVersion: "ere-evidence-packet/1.0", finding: { id: finding.id } });
  });

  it("returns sanitized Markdown with safe download headers", async () => {
    const response = await getMarkdown(request);
    expect(loadEvidencePacket).toHaveBeenCalledWith(request, "evidence_packet_markdown");
    expect(response.headers.get("content-type")).toContain("text/markdown");
    expect(response.headers.get("content-disposition")).toContain("finding-evidence");
    expect(await response.text()).toContain("## Interpretation boundary");
  });

  it("passes shared-boundary errors through unchanged", async () => {
    const denied = new Response("Authentication required.", { status: 401 });
    loadEvidencePacket.mockResolvedValue(denied);
    expect(await getJson(request)).toBe(denied);
    expect(await getMarkdown(request)).toBe(denied);
  });
});
