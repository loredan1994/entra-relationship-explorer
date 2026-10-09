import { expect, test } from "@playwright/test";

const apiId = "30000000-0000-4000-8000-000000000002";

test("a filtered application bookmark recovers the requested identity instead of presenting another application's details", async ({ page }) => {
  await page.goto(`/investigations?view=applications&q=Expense%20Reporter&identity=${apiId}`);
  await expect(page.getByRole("main").getByRole("status")).toContainText("The requested application identity is hidden by the current filter.");
  await expect(page.getByRole("region", { name: "Selected application access" })).toHaveCount(0);
  await page.getByRole("link", { name: "Clear the filter and inspect the requested application" }).click();
  await expect(page.getByLabel("Filter application names, IDs or publishers")).toHaveValue("");
  await expect(page.getByRole("region", { name: "Selected application access" }).getByRole("heading", { name: "Clean Project API", exact: true })).toBeInViewport();
  await expect(page).toHaveURL(new RegExp(`identity=${apiId}#application-access-detail$`));
});

test("an unavailable application bookmark explains the missing record and leaves other identities selectable", async ({ page }) => {
  await page.goto("/investigations?view=applications&identity=no-longer-collected");
  await expect(page.getByRole("main").getByRole("status")).toContainText("The requested application identity is not in this snapshot.");
  await expect(page.getByRole("region", { name: "Selected application access" })).toHaveCount(0);
  await page.locator("#application-identities").getByRole("link", { name: "Expense Reporter", exact: true }).click();
  await expect(page.getByRole("region", { name: "Selected application access" }).getByRole("heading", { name: "Expense Reporter", exact: true })).toBeInViewport();
  await expect(page.getByRole("main").getByRole("status")).toHaveCount(0);
});
