import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { cleanProjectFixture, relationships } from "@entra-explorer/domain";
import { EvidenceInspector } from "../components/relationship-explorer";

it("renders observed sign-in evidence without claiming configured access or hiding its timestamp", () => {
  const snapshot = structuredClone(cleanProjectFixture);
  const view = relationships(snapshot)[0]!;
  view.edge = { ...view.edge, type: "OBSERVED_CALL", plainLabel: "Successful sign-in to resource", evidence: { ...view.edge.evidence, configured: false, observed: { lastSeenAt: "2026-10-08T10:00:00Z", windowStartsAt: "2026-09-08T10:00:00Z" } } };
  const html = renderToStaticMarkup(createElement(EvidenceInspector, { view, snapshot }));
  expect(html).toContain("Observed sign-in");
  expect(html).toMatch(/<time datetime="2026-10-08T10:00:00Z"/i);
  expect(html).toContain("2026-09-08T10:00:00Z");
  expect(html).toContain("does not prove a configured permission was exercised");
  expect(html).not.toContain("Configured relationship");
  expect(html).not.toContain("No activity attached");
});

it("does not fabricate observations for a configured grant or an incomplete relationship", () => {
  const snapshot = structuredClone(cleanProjectFixture);
  const view = relationships(snapshot)[0]!;
  const html = renderToStaticMarkup(createElement(EvidenceInspector, { view, snapshot }));
  expect(html).toContain("Configured relationship");
  expect(html).toContain("No activity attached to this relationship");
  expect(html).not.toContain("Observed sign-in");
  view.edge.evidence.configured = false;
  const incomplete = renderToStaticMarkup(createElement(EvidenceInspector, { view, snapshot }));
  expect(incomplete).toContain("Evidence incomplete");
  expect(incomplete).not.toContain("Configured relationship");
});
