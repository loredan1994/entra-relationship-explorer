import { NextRequest } from "next/server";
import { cleanProjectFixture, relationships } from "@entra-explorer/domain";
import { beforeEach, expect, it, vi } from "vitest";
import { GET } from "../app/api/export/relationships.csv/route";
import { loadExportSnapshot } from "./export-snapshot";

vi.mock("./export-snapshot", () => ({ loadExportSnapshot: vi.fn() }));
beforeEach(() => vi.clearAllMocks());

it("downloads the same synthetic relationship inventory as the demo UI", async () => {
  vi.mocked(loadExportSnapshot).mockResolvedValue(cleanProjectFixture);
  const request = new NextRequest("http://localhost/api/export/relationships.csv");
  const response = await GET(request);
  expect(loadExportSnapshot).toHaveBeenCalledWith(request, "snapshot");
  expect(response.status).toBe(200);
  expect(response.headers.get("content-disposition")).toMatch(/^attachment; filename="entra-relationships-.*\.csv"$/);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const csv = await response.text();
  expect(csv.split("\r\n")).toHaveLength(relationships(cleanProjectFixture).length + 1);
  for (const { source, target, edge } of relationships(cleanProjectFixture)) {
    expect(csv).toContain(source.id);
    expect(csv).toContain(target.id);
    expect(csv).toContain(edge.type);
  }
});

it.each([401, 404])("preserves the authenticated loader's %s response instead of substituting sample data", async status => {
  const denied = new Response("Not available.", { status });
  vi.mocked(loadExportSnapshot).mockResolvedValue(denied);
  expect(await GET(new NextRequest("http://localhost/api/export/relationships.csv"))).toBe(denied);
});
