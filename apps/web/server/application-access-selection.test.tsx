import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { applicationAccessReviews, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, it } from "vitest";
import { ApplicationAccess } from "../components/application-access";

const identities = applicationAccessReviews(cleanProjectFixture);
const selected = identities.find(review => review.identity.label === "Clean Project API")!;

it("does not present another application's details for a requested identity absent from this snapshot", () => {
  const html = renderToStaticMarkup(createElement(ApplicationAccess, { snapshot: cleanProjectFixture, query: "", selectedId: "an-identity-no-longer-collected" }));
  expect(html).toContain("The requested application identity is not in this snapshot.");
  expect(html).not.toContain('aria-label="Selected application access"');
  expect(html).toContain("Application access review");
  expect(html).toContain("Clean Project API");
});

it("explains when a valid bookmarked identity is hidden by the filter and preserves it in the clear-filter link", () => {
  const html = renderToStaticMarkup(createElement(ApplicationAccess, { snapshot: cleanProjectFixture, query: "Expense Reporter", selectedId: selected.identity.id }));
  expect(html).toContain("The requested application identity is hidden by the current filter.");
  expect(html).not.toContain('aria-label="Selected application access"');
  expect(html).toContain(`/investigations?view=applications&amp;identity=${selected.identity.id}#application-access-detail`);
});

it("continues to show the requested identity, or the first identity when no selection is requested", () => {
  const requested = renderToStaticMarkup(createElement(ApplicationAccess, { snapshot: cleanProjectFixture, query: "", selectedId: selected.identity.id }));
  expect(requested).toContain(`<h2>${selected.identity.label}</h2>`);
  expect(requested).toContain('aria-label="Selected application access"');
  const initial = renderToStaticMarkup(createElement(ApplicationAccess, { snapshot: cleanProjectFixture, query: "" }));
  expect(initial).toContain(`<h2>${identities[0]!.identity.label}</h2>`);
});
