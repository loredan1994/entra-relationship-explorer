import { expect, test } from "@playwright/test";

const coreRoutes = [
  "/overview",
  "/map",
  "/permissions",
  "/changes",
  "/security",
  "/settings",
  "/applications/30000000-0000-4000-8000-000000000001",
];

test("evidence actions stay readable and open the matching evidence", async ({ page }) => {
  await page.goto("/permissions");

  const inspectLink = page.getByRole("link", { name: "Inspect", exact: true }).first();
  await expect(inspectLink).toBeVisible();
  await expect(inspectLink).toHaveCSS("overflow-wrap", "normal");
  await expect(inspectLink).toHaveCSS("white-space", "nowrap");
  await expect(inspectLink.locator("xpath=.."), "Evidence column should reserve action width").toHaveCSS("min-width", "88px");

  const target = await inspectLink.getAttribute("href");
  expect(target).toMatch(/^\/map\?edge=.+/);
  await inspectLink.click();
  await expect(page).toHaveURL(target!);
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toBeVisible();

  await page.getByRole("button", { name: "Table", exact: true }).click();
  const inspectButton = page.getByRole("button", { name: "Inspect", exact: true }).first();
  await expect(inspectButton).toHaveCSS("overflow-wrap", "normal");
  await expect(inspectButton).toHaveCSS("white-space", "nowrap");
});

test("core routes render without UI errors or broken action labels", async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`console: ${message.text()}`);
  });

  for (const route of coreRoutes) {
    const response = await page.goto(route);
    expect(response?.ok(), `${route} should load successfully`).toBeTruthy();

    const audit = await page.evaluate(() => {
      const visible = (element: Element) => {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
      };
      const brokenActions = [...document.querySelectorAll<HTMLElement>(".button, .text-button, .text-link, .primary-nav a")]
        .filter(visible)
        .map((element) => ({
          label: element.innerText.trim(),
          overflowWrap: getComputedStyle(element).overflowWrap,
          wordBreak: getComputedStyle(element).wordBreak,
        }))
        .filter((item) => item.overflowWrap === "anywhere" || item.wordBreak === "break-all");

      return {
        brokenActions,
        bodyWidth: document.body.scrollWidth,
        viewportWidth: window.innerWidth,
      };
    });

    expect(audit.brokenActions, `${route} has action labels that can split mid-word`).toEqual([]);
    expect(audit.bodyWidth, `${route} overflows the ${testInfo.project.name} viewport`).toBeLessThanOrEqual(audit.viewportWidth + 1);
  }

  expect(errors, `browser errors on ${testInfo.project.name}`).toEqual([]);
});

test("new collector objects, policy subtypes, and role scope remain inspectable", async ({ page }) => {
  await page.goto("/map");
  if ((page.viewportSize()?.width ?? 1280) <= 700) await page.getByRole("button", { name: "Filters", exact: true }).click();
  await expect(page.getByRole("checkbox", { name: /Device Directory device/ })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: /Administrative unit Directory scope/ })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: /Federated credential Federated identity credential/ })).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();

  const federationRow = page.getByRole("row").filter({ hasText: "Can federate as" });
  await federationRow.getByRole("button", { name: "Inspect" }).click();
  const inspector = page.getByRole("complementary", { name: "Selected relationship evidence" });
  await expect(inspector).toContainText("https://token.actions.githubusercontent.com");
  await expect(inspector).toContainText("repo:clean-project/orchestrator:ref:refs/heads/main");

  const roleRow = page.getByRole("row").filter({ hasText: "Active in role" });
  await roleRow.getByRole("button", { name: "Inspect" }).click();
  await expect(inspector.getByRole("heading", { name: "Assignment scope" })).toBeVisible();
  await expect(inspector).toContainText("Finance");
  await expect(inspector).toContainText("/administrativeUnits/90000000-0000-4000-8000-000000000002");

  const consentRow = page.getByRole("row").filter({ hasText: "Assigns consent policy" });
  await consentRow.getByRole("button", { name: "Inspect" }).click();
  await expect(inspector).toContainText("Authorization policy");
  await expect(inspector).toContainText("Permission grant policy (consent policy)");
});
