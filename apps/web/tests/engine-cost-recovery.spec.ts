import { expect, test } from "@playwright/test";

test("a cleared operational cost stays unknown until the analyst explicitly supplies zero or a positive cost", async ({ page }) => {
  await page.goto("/engine?view=plans");
  const cost = page.getByLabel(/^Cost for /);
  await cost.fill("");
  await expect(cost).toHaveValue("");
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.locator(".engine-workspace").getByRole("alert")).toContainText("Enter a cost");
  await expect(page.getByRole("button", { name: "Export sensitive review plans" })).toHaveCount(0);
  await cost.fill("0");
  await expect(page.locator(".engine-workspace").getByRole("alert")).toHaveCount(0);
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.getByRole("heading", { name: "Plan 1 · cost 0", exact: true })).toBeVisible();
  await cost.fill("9");
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.getByRole("heading", { name: "Plan 1 · cost 9", exact: true })).toBeVisible();
});
