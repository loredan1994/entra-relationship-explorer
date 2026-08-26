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

test("the threat workspace explains transitive paths and keeps evidence classes separate", async ({ page }) => {
  await page.goto("/security");
  await expect(page.getByRole("heading", { name: "Attack paths and threat workspace", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: /Maya Chen can reach Clean Project API/ }).click();
  await expect(page.getByRole("heading", { name: "Multi-stage attack flow" })).toBeVisible();
  await expect(page.getByText("3 configured steps")).toBeVisible();
  await expect(page.getByText("0 observed")).toBeVisible();
  await expect(page.getByText(/not evidence that exploitation occurred/)).toBeVisible();
  await page.getByRole("button", { name: "Edit a review copy" }).click();
  await expect(page.getByText("3 review steps")).toBeVisible();
  await page.getByRole("button", { name: "Add analyst step" }).click();
  await expect(page.getByText("4 review steps")).toBeVisible();
  await page.getByLabel("Owner").fill("IAM team");
  await page.getByLabel("Status").selectOption("mitigating");
  await page.reload();
  await expect(page.getByLabel("Owner")).toHaveValue("IAM team");
  await expect(page.getByLabel("Status")).toHaveValue("mitigating");
});

test("standalone report and MITRE Attack Flow exports are sanitized and interoperable", async ({ request }) => {
  const report = await request.get("/api/export/report.html");
  expect(report.ok()).toBeTruthy();
  expect(report.headers()["content-disposition"]).toContain("attachment");
  expect(report.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  const reportBody = await report.text();
  expect(reportBody).toContain("default-src 'none'");
  expect(reportBody).not.toContain("accessToken");
  const flow = await request.get("/api/export/attack-flow.json");
  expect(flow.ok()).toBeTruthy();
  const bundle = await flow.json() as { type: string; objects: Array<{ type: string; spec_version?: string }> };
  expect(bundle.type).toBe("bundle");
  expect(bundle.objects.some((item) => item.type === "attack-flow" && item.spec_version === "2.1")).toBeTruthy();
});

test("fixture findings export is sanitized and evidence-labelled", async ({ request }) => {
  const response = await request.get("/api/export/findings.csv");
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("text/csv");
  const body = await response.text();
  expect(body).toContain('"evidenceClass"');
  expect(body).toContain('"inferred"');
  expect(body).not.toContain("accessToken");
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
