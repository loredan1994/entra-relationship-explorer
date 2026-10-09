import { expect, test } from "@playwright/test";

const sections = [
  ["Overview", "/overview", "See the identities behind every permission."],
  ["Relationship map", "/map", "Relationship map"],
  ["Permissions", "/permissions", "Permissions"],
  ["Changes", "/changes", "Changes"],
  ["Investigations", "/investigations", "Investigations"],
  ["Evidence engine", "/engine", "Reason about access"],
  ["Threat workspace", "/security", "Attack paths and threat workspace"],
  ["Settings", "/settings", "Settings"],
  ["Guide", "/guide", "Understand access. Follow the evidence."],
] as const;

test("every primary tab opens a visible page after scrolling another section", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/guide");
  for (const [label, route, title] of sections) {
    await page.getByRole("main").focus();
    await page.keyboard.press("Control+End");
    const link = page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: label, exact: true });
    await link.click();
    await expect(page).toHaveURL(route);
    await expect(link).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: title, level: 1, exact: true })).toBeInViewport();
  }
  expect(errors).toEqual([]);
});

test("every guide question and local next-step link reaches its named workflow", async ({ page }) => {
  const questions = [
    ["Can we prove, test and plan this access?", "/engine", "Reason about access"],
    ["What did this scan actually collect?", "/investigations?view=coverage", "Collection readiness and evidence coverage"],
    ["How are these identities connected?", "/map", "Relationship map"],
    ["Who has access to this application?", "/investigations?view=applications", "Application access review"],
    ["Which permissions were requested and granted?", "/investigations?view=ledger", "Requested versus granted permissions"],
    ["Which credentials or workload trusts need review?", "/investigations?view=credentials", "Investigations"],
    ["What changed between scans?", "/changes", "Changes"],
    ["What if a configured relationship were removed?", "/investigations?view=scenarios", "What-if access planner"],
    ["Which possible paths should we investigate?", "/security", "Attack paths and threat workspace"],
  ];
  for (const [question, route, heading] of questions) {
    await page.goto("/guide");
    await page.getByRole("link").filter({ hasText: question! }).click();
    await expect(page).toHaveURL(route!);
    await expect(page.getByRole("heading", { name: heading!, exact: true })).toBeVisible();
  }
  for (const [label, route] of [
    ["Open relationship map", "/map"],
    ["Inspect this snapshot’s coverage", "/investigations?view=coverage"],
    ["Connection and data settings", "/settings"],
    ["Open rule laboratory", "/investigations?view=rules"],
  ]) {
    await page.goto("/guide");
    await page.getByRole("link").filter({ hasText: label! }).click();
    await expect(page).toHaveURL(route!);
  }
  await page.goto("/guide");
  await expect(page.getByRole("link", { name: /Read the setup and contributor docs/ })).toHaveAttribute("href", "https://github.com/loredan1994/entra-relationship-explorer#readme");
});

test("tablet navigation can reveal and activate the last tab without clipping content", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "chromium", "Explicit tablet viewport is covered once.");
  await page.setViewportSize({ width: 980, height: 800 });
  await page.goto("/overview");
  const guide = page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Guide", exact: true });
  await guide.click();
  await expect(page).toHaveURL("/guide");
  await expect(guide).toBeInViewport();
  await expect(page.getByRole("heading", { level: 1 })).toBeInViewport();
  const frame = await page.locator(".app-shell").boundingBox();
  expect(frame!.x + frame!.width).toBeLessThanOrEqual(980);
});
