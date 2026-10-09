import { expect, test } from "@playwright/test";

test("browsing and hovering findings does not request evidence exports", async ({ page }) => {
  const exports: string[] = [];
  page.on("request", request => {
    if (new URL(request.url()).pathname.startsWith("/api/export/")) exports.push(request.url());
  });
  await page.goto("/security");
  const findings = page.getByRole("complementary", { name: "Prioritized findings" }).locator(".finding-button");
  for (const index of [0, 1, 2]) {
    await findings.nth(index).click();
    const packet = page.getByRole("link", { name: "Finding packet · Markdown", exact: true });
    await packet.scrollIntoViewIfNeeded();
    await packet.hover();
    await page.waitForLoadState("networkidle");
  }
  expect(exports).toEqual([]);
});

test("one explicit export downloads the requested packet without leaving the investigation", async ({ page }) => {
  const exports: { path: string; rsc: string | undefined }[] = [];
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/export/")) exports.push({ path: url.pathname, rsc: request.headers().rsc });
  });
  await page.goto("/security");
  await page.getByRole("complementary", { name: "Prioritized findings" }).locator(".finding-button").nth(2).click();
  await expect(page.getByRole("region", { name: "Selected finding" })).toBeFocused();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Finding packet · Markdown", exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.md$/);
  expect(await download.failure()).toBeNull();
  await expect(page).toHaveURL("/security");
  expect(exports).toEqual([{ path: "/api/export/evidence-packet.md", rsc: undefined }]);
});
