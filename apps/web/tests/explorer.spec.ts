import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("map, table, search, filters, and evidence stay consistent", async ({ page }) => {
  await page.goto("/map");

  await expect(page.getByRole("group", { name: /7 objects and 7 configured connections/ })).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText(
    "This does not prove recent use",
  );

  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.getByRole("row")).toHaveCount(8);

  await page.getByPlaceholder("Name or permission", { exact: true }).fill("Api.Write");
  await expect(page.getByRole("row")).toHaveCount(2);
  await expect(page.getByRole("cell", { name: /Api.Read.*Api.Write/ })).toBeVisible();

  await page.getByPlaceholder("Name or permission", { exact: true }).fill("");
  await page.getByRole("checkbox", { name: /Group Group/ }).check();
  await expect(page.getByRole("row")).toHaveCount(2);
  await expect(page.getByRole("cell", { name: /Project Operators/ })).toBeVisible();
});

test("the relationship map is keyboard reachable", async ({ page }) => {
  await page.goto("/map");
  const tableButton = page.getByRole("button", { name: "Table", exact: true });
  await tableButton.focus();
  await page.keyboard.press("Enter");
  await expect(tableButton).toHaveAttribute("aria-pressed", "true");
});

test("filters can be saved locally and objects expand to a bounded one-hop view", async ({ page }) => {
  await page.goto("/map");
  const search = page.getByPlaceholder("Name or permission", { exact: true });
  await search.fill("Api.Write");
  await page.getByRole("button", { name: "Save current" }).click();
  await expect(page.getByRole("button", { name: "Search: Api.Write", exact: true })).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Search: Api.Write", exact: true }).click();
  await expect(search).toHaveValue("Api.Write");
  await search.fill("");
  await page.getByRole("button", { name: /Clean Project API, Blueprint/ }).click();
  await expect(page.getByText("One-hop view.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Clear one-hop focus" })).toBeVisible();
});

test("core routes have no detectable WCAG A or AA violations", async ({ page }, testInfo) => {
  for (const route of ["/overview", "/map", "/permissions", "/changes", "/security", "/settings"]) {
    await page.goto(route);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(results.violations, `${route} accessibility violations on ${testInfo.project.name}`).toEqual([]);
  }
});

test("mobile layout does not overflow the page", async ({ page }, testInfo) => {
  test.skip(!testInfo.project.name.startsWith("mobile"), "Mobile-only assertion");
  await page.goto("/map");
  const metrics = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: window.innerWidth }));
  expect(metrics.body).toBeLessThanOrEqual(metrics.viewport + 1);
});

test("the security page reports tenant exposure from configured access only", async ({ page }) => {
  await page.goto("/security");
  await expect(page.getByRole("heading", { name: "Where this tenant is exposed.", level: 1 })).toBeVisible();

  // The fixture grants Api.Read plus Api.Write as an application permission.
  const powerful = page.getByRole("article").filter({ hasText: "Clean Project Orchestrator" }).first();
  await expect(powerful).toContainText("Application permission");
  await expect(powerful).toContainText("Api.Write");

  // Configured access must never be presented as observed use.
  await expect(page.getByText("Configured, not observed.")).toBeVisible();
  await expect(page.getByRole("main")).not.toContainText("last used");

  // Unowned identities are named, and link to their evidence.
  await expect(page.getByRole("table").filter({ hasText: "Expense Reporter" })).toBeVisible();
});

test("live access is disabled by default and responses are hardened", async ({ request }) => {
  const session = await request.get("/api/v1/session");
  expect(session.ok()).toBeTruthy();
  await expect(session.json()).resolves.toEqual({ enabled: false, connected: false });
  expect(session.headers()["cache-control"]).toContain("no-store");
  expect(session.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");

  const scan = await request.post("/api/v1/scans");
  expect(scan.status()).toBe(404);
  await expect(scan.json()).resolves.toEqual({ error: "Live Entra access is disabled." });
});
