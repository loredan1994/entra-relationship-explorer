import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { RelationshipExplorer } from "../components/relationship-explorer";

vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));

it("starts dense parallel relationships in the complete table even when they connect only two objects", () => {
  const edge = cleanProjectFixture.edges[0]!;
  const snapshot = {
    ...cleanProjectFixture,
    nodes: cleanProjectFixture.nodes.filter(node => node.id === edge.sourceId || node.id === edge.targetId),
    edges: Array.from({ length: 250 }, (_, index) => ({ ...edge, id: `synthetic-parallel-${index}` })),
  };
  const html = renderToStaticMarkup(createElement(RelationshipExplorer, { snapshot }));
  expect(html).toContain("Showing 1–50 of 250 recorded relationships");
  expect(html).not.toContain("relationship-canvas");
});
