import { expect, test, type Page } from "@playwright/test";

async function openFilters(page: Page) {
  if ((page.viewportSize()?.width ?? 1280) <= 700) {
    const toggle = page.locator(".mobile-filter-toggle");
    await expect(toggle).toBeVisible();
    if (await toggle.getAttribute("aria-expanded") === "false") await toggle.click();
  }
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toBeVisible();
}

test("Inspect reveals the selected evidence and returns keyboard focus to its row", async ({ page }) => {
  await page.goto("/map");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  const row = page.getByRole("row").filter({ hasText: "Can federate as" });
  const inspect = row.getByRole("button", { name: "Inspect", exact: true });
  const inspector = page.getByRole("complementary", { name: "Selected relationship evidence" });

  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspector).toBeFocused();
  await expect(inspector.getByRole("heading", { name: "Can federate as", exact: true })).toBeInViewport();
  await expect(inspector).toContainText("https://token.actions.githubusercontent.com");
  await expect(inspect).toHaveAttribute("aria-pressed", "true");
  await inspector.getByRole("button", { name: "Back to selected relationship" }).click();
  await expect(inspect).toBeFocused();
  await expect(inspect).toBeInViewport();

  // The already-selected button must still bring the panel back into view.
  await inspector.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await inspect.click();
  await expect(inspector).toBeFocused();
  await expect.poll(() => inspector.evaluate(element => element.scrollTop)).toBe(0);
  await expect(inspector.getByRole("heading", { name: "Can federate as", exact: true })).toBeInViewport();
});

test("Fit and Home restore the complete graph after pointer or keyboard panning", async ({ page }) => {
  await page.goto("/map");
  await openFilters(page);
  await page.getByPlaceholder("Name or permission", { exact: true }).fill("no-such-relationship");
  await expect(page.getByRole("heading", { name: "No relationships match" })).toBeVisible();
  await page.locator(".map-empty").getByRole("button", { name: "Clear filters", exact: true }).click();
  const canvas = page.getByRole("group", { name: /13 objects and 11 configured connections/ });
  const scaler = page.locator(".canvas-scaler");
  await page.getByRole("button", { name: "Fit", exact: true }).click();
  const fittedTransform = await scaler.evaluate(element => (element as HTMLElement).style.transform);
  await canvas.dispatchEvent("wheel", { deltaX: 100, deltaY: 150 });
  await expect.poll(() => scaler.evaluate(element => (element as HTMLElement).style.transform)).not.toBe(fittedTransform);
  await page.getByRole("button", { name: "Fit", exact: true }).click();
  await expect.poll(() => scaler.evaluate(element => (element as HTMLElement).style.transform)).toBe(fittedTransform);
  await canvas.focus();
  await page.keyboard.press("ArrowRight");
  await expect.poll(() => scaler.evaluate(element => (element as HTMLElement).style.transform)).not.toBe(fittedTransform);
  await page.keyboard.press("Home");
  await expect.poll(() => scaler.evaluate(element => (element as HTMLElement).style.transform)).toBe(fittedTransform);
});

test("Back follows the current relationship after selecting a different graph object", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/map");
  const appGrant = page.getByRole("button", { name: /^Clean Project Orchestrator Can call Clean Project API:/ });
  const inspector = page.getByRole("complementary", { name: "Selected relationship evidence" });
  await appGrant.click();
  await inspector.getByRole("button", { name: "Back to selected relationship" }).click();
  await expect(appGrant).toBeFocused();

  const apiIdentity = page.getByRole("button", { name: /Clean Project API, Tenant identity/ });
  await apiIdentity.click();
  await expect(inspector.getByRole("heading", { name: "Creates a tenant identity", exact: true })).toBeVisible();
  await inspector.getByRole("button", { name: "Back to selected relationship" }).click();
  await expect(apiIdentity).toBeFocused();
  await expect(appGrant).not.toBeFocused();

  // Switching presentation removes the graph trigger; return to the current row.
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await inspector.getByRole("button", { name: "Back to selected relationship" }).click();
  await expect(page.locator('.relationship-table button[aria-pressed="true"]')).toBeFocused();
});

test("the table leaves the bounded map focus and restores all filtered relationships", async ({ page }) => {
  await page.goto("/map");
  await page.getByRole("button", { name: /Clean Project API, Blueprint/ }).click();
  await expect(page.getByText("One-hop view.")).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.getByRole("row")).toHaveCount(12);
  await expect(page.getByText("One-hop view.")).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "recorded relationships" })).toHaveText("Showing 1–11 of 11 recorded relationships.");
});

test("same-route navigation resets query filters to the destination URL", async ({ page }) => {
  await page.goto("/map?q=Api.Write&kind=application");
  await openFilters(page);
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("Api.Write");
  await expect(page.getByRole("checkbox", { name: /Blueprint App registration/ })).toBeChecked();
  await page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Relationship map", exact: true }).click();
  await expect(page).toHaveURL(/\/map$/);
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("");
  await openFilters(page);
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("");
  await expect(page.getByRole("checkbox", { name: /Blueprint App registration/ })).not.toBeChecked();
  await expect(page.getByRole("group", { name: /13 objects and 11 configured connections/ })).toBeVisible();
  await page.goBack();
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("Api.Write");
  await openFilters(page);
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("Api.Write");
  await expect(page.getByRole("checkbox", { name: /Blueprint App registration/ })).toBeChecked();
});

test("saved-filter storage failure is explained without claiming the filter was saved", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.addInitScript(() => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (this === window.localStorage) throw new DOMException("Storage is blocked", "SecurityError");
      return original.call(this, key, value);
    };
  });
  await page.goto("/map");
  await openFilters(page);
  await page.getByPlaceholder("Name or permission", { exact: true }).fill("Api.Write");
  await page.getByRole("button", { name: "Save current", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Could not save this change" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Search: Api.Write", exact: true })).toHaveCount(0);
  await expect(page.getByText("No saved filters yet.")).toBeVisible();
  expect(errors).toEqual([]);
});

test("global search has an explicit submit action that opens matching evidence", async ({ page }) => {
  await page.goto("/overview");
  const search = page.getByRole("search");
  await search.getByRole("textbox", { name: "Search relationships" }).fill("Api.Write");
  await search.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page).toHaveURL(/\/map\?q=Api.Write$/);
  await openFilters(page);
  await expect(page.getByPlaceholder("Name or permission", { exact: true })).toHaveValue("Api.Write");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.getByRole("row")).toHaveCount(2);
  await expect(page.getByRole("cell", { name: /Api.Read.*Api.Write/ })).toBeVisible();
});

test("the evidence panel stays reachable at the tablet layout breakpoint", async ({ page }) => {
  await page.setViewportSize({ width: 980, height: 900 });
  await page.goto("/map");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByRole("row").filter({ hasText: "Can federate as" }).getByRole("button", { name: "Inspect", exact: true }).click();
  const inspector = page.getByRole("complementary", { name: "Selected relationship evidence" });
  await expect(inspector).toBeFocused();
  const bounds = await inspector.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(981);
  await expect(inspector.getByRole("heading", { name: "Can federate as", exact: true })).toBeInViewport();
});

test("inspecting a lower table row reveals the evidence heading on a short desktop viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/map");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  const table = page.locator(".relationship-table-wrap");
  await table.evaluate(element => { element.scrollTop = element.scrollHeight; });
  const lastRow = page.getByRole("row").last();
  const relationship = await lastRow.getByRole("cell").nth(1).evaluate(element => element.childNodes[0]?.textContent ?? "");
  await lastRow.getByRole("button", { name: "Inspect", exact: true }).click();
  const inspector = page.getByRole("complementary", { name: "Selected relationship evidence" });
  await expect(inspector).toBeFocused();
  await expect(inspector.getByRole("heading", { name: relationship, exact: true })).toBeInViewport();
  const bounds = await inspector.boundingBox();
  expect(bounds!.height).toBeLessThanOrEqual(720);
});

test("overview review actions open the actual finding and ownership queue", async ({ page }) => {
  await page.goto("/overview");
  const review = page.getByRole("link", { name: /^Review finding / }).first();
  const title = await review.locator("xpath=..").locator("strong").textContent();
  await review.click();
  await expect(page).toHaveURL(/\/security\?finding=/);
  await expect(page.getByRole("button", { name: new RegExp(title!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }).first()).toHaveAttribute("aria-pressed", "true");
  await page.goto("/overview");
  await page.getByRole("link", { name: /No owner recorded/ }).click();
  await expect(page).toHaveURL(/\/security\?category=ownership$/);
  const findings = page.locator(".finding-button");
  expect(await findings.count()).toBeGreaterThan(0);
  for (const finding of await findings.all()) await expect(finding).toContainText("ownership");
});
