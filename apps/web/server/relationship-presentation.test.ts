import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { layoutGraph } from "../components/graph-layout";
import { RelationshipExplorer } from "../components/relationship-explorer";

vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock("../components/graph-layout", async importOriginal => {
  const original = await importOriginal<typeof import("../components/graph-layout")>();
  return { ...original, layoutGraph: vi.fn((...args: Parameters<typeof original.layoutGraph>) => {
    if (args[0].length > 15) throw new Error("Unbounded table layout was attempted.");
    return original.layoutGraph(...args);
  }) };
});
beforeEach(() => { vi.mocked(layoutGraph).mockClear(); });

function render(snapshot: TenantSnapshot) {
  return renderToStaticMarkup(createElement(RelationshipExplorer, { snapshot }));
}

it("does not spend graph-layout work on the tenant table, including large cyclic inventories", () => {
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.mode = "tenant";
  snapshot.nodes = Array.from({ length: 3_000 }, (_, i) => ({ ...snapshot.nodes[0]!, id: `node-${i}`, label: `Identity ${i}` }));
  snapshot.edges = snapshot.nodes.map((node, i) => ({ ...snapshot.edges[0]!, id: `edge-${i}`, sourceId: node.id, targetId: snapshot.nodes[(i + 1) % snapshot.nodes.length]!.id }));
  const html = render(snapshot);
  expect(html).toContain("relationship-table");
  expect(html).toContain("Showing 1–50 of 3000 recorded relationships");
  expect(html).not.toContain("<strong>Identity 2999</strong>");
  expect(html.match(/<tr[ >]/g)).toHaveLength(51);
  expect(layoutGraph).not.toHaveBeenCalled();
});

it("keeps the small sample map while starting large samples in the bounded table workflow", () => {
  expect(render(cleanProjectFixture)).toContain("relationship-canvas");
  expect(layoutGraph).toHaveBeenCalledOnce();
  vi.mocked(layoutGraph).mockClear();
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.nodes.push(...Array.from({ length: 20 }, (_, i) => ({ ...snapshot.nodes[0]!, id: `extra-${i}` })));
  expect(render(snapshot)).toContain("relationship-table");
  expect(layoutGraph).not.toHaveBeenCalled();
});

it("labels observed and incomplete relationships accurately in both presentations", () => {
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.edges = [
    { ...snapshot.edges[0]!, type: "OBSERVED_CALL", plainLabel: "Successful sign-in to resource", permissions: [], evidence: { ...snapshot.edges[0]!.evidence, configured: false, observed: { lastSeenAt: "2026-10-08T10:00:00Z", windowStartsAt: "2026-09-08T10:00:00Z" } } },
    { ...snapshot.edges[1]!, evidence: { ...snapshot.edges[1]!.evidence, configured: false } },
  ];
  const map = render(snapshot);
  expect(map).toContain("0 configured connections, 1 observed sign-in connections, 1 connections with incomplete evidence");
  expect(map).toContain("Observed sign-in relationship.");
  expect(map).toContain("Evidence incomplete relationship.");
  expect(map).toContain("Observed sign-ins are separate evidence");
  expect(map).not.toContain("Activity is not collected");
  snapshot.mode = "tenant";
  const table = render(snapshot);
  expect(table).toContain("<small>Observed sign-in</small>");
  expect(table).toContain("<small>Evidence incomplete</small>");
  expect(table).not.toContain("<small>Configured</small>");
});

it("retains both evidence labels when a relationship carries configuration and observation", () => {
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.mode = "tenant";
  snapshot.edges[0]!.evidence.observed = { lastSeenAt: "2026-10-08T10:00:00Z", windowStartsAt: "2026-09-08T10:00:00Z" };
  expect(render(snapshot)).toContain("<small>Configured and observed</small>");
});
