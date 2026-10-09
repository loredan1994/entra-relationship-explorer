import { expect, test } from "@playwright/test";

test("permission sorting, filters, clearing and the CSV download match what an analyst sees", async ({ page }) => {
  await page.goto("/permissions");
  const status = page.locator(".table-result-count");
  const rows = page.locator(".permissions-data-table tbody tr");
  const originalCount = await rows.count();
  expect(originalCount).toBeGreaterThan(1);
  await expect(status).toContainText("most exposed first");
  await page.getByRole("button", { name: "Exposure", exact: true }).click();
  await expect(status).toContainText("least exposed first");
  await expect(page.getByRole("columnheader", { name: "Exposure" })).toHaveAttribute("aria-sort", "descending");
  const exposureLabels = await rows.locator("td:first-child .severity-pill").allTextContents();
  const rank: Record<string, number> = { Low: 0, Review: 1, "High exposure": 2 };
  expect(exposureLabels.map(label => rank[label])).toEqual(exposureLabels.map(label => rank[label]).sort((a, b) => a! - b!));
  for (const direction of ["A to Z", "Z to A"]) {
    await page.getByRole("button", { name: "Caller", exact: true }).click();
    await expect(status).toContainText(`caller, ${direction}`);
    const labels = await rows.locator("td:nth-child(2) strong").allTextContents();
    expect(labels).toEqual([...labels].sort((a, b) => a.localeCompare(b) * (direction === "A to Z" ? 1 : -1)));
  }
  await page.getByRole("combobox", { name: "Access type", exact: true }).selectOption("delegated");
  await expect(rows).not.toHaveCount(0);
  for (const cell of await rows.locator("td:nth-child(3)").allTextContents()) expect(cell).toContain("Delegated");
  await page.getByLabel("Search callers, resources, or permissions").fill("no-such-synthetic-permission");
  await expect(rows).toHaveCount(0);
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(rows).toHaveCount(originalCount);
  await expect(page.getByRole("combobox", { name: "Access type", exact: true })).toHaveValue("all");
  await page.getByRole("checkbox", { name: "Write-capable only", exact: true }).check();
  await expect(rows).not.toHaveCount(0);
  await expect(status).toContainText("filtered from");
  await page.getByRole("checkbox", { name: "Write-capable only", exact: true }).uncheck();
  await page.getByRole("button", { name: /^High ·/ }).click();
  await expect(rows).toHaveCount(0);
  await expect(page.getByText("No grants match the current filters.")).toBeVisible();
  await page.getByRole("button", { name: /^High ·/ }).click();
  await expect(rows).toHaveCount(originalCount);

  for (const exposure of ["Review", "Low"]) {
    await page.getByRole("button", { name: new RegExp(`^${exposure} ·`) }).click();
    await expect(rows).toHaveCount(1);
    await expect(rows.locator(".severity-pill")).toHaveText(exposure);
    await page.getByRole("button", { name: new RegExp(`^${exposure} ·`) }).click();
    await expect(rows).toHaveCount(originalCount);
  }
  for (const column of ["Access type", "Resource"]) {
    await page.getByRole("button", { name: column, exact: true }).click();
    await expect(status).toContainText(`${column.toLowerCase()}, A to Z`);
    await expect(page.getByRole("columnheader", { name: column, exact: true })).toHaveAttribute("aria-sort", "ascending");
  }

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export CSV", exact: true }).click();
  const download = await downloadPromise;
  expect(await download.failure()).toBeNull();
  expect(download.suggestedFilename()).toMatch(/^entra-relationships-.*\.csv$/);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  const csv = Buffer.concat(chunks).toString("utf8");
  expect(csv).toContain("sourceObjectId");
  expect(csv).toContain("sourceEndpoint");
  expect(csv).toContain("Clean Project");
  expect(csv.split("\r\n").length).toBeGreaterThan(originalCount);
  await expect(page).toHaveURL(/\/permissions$/);
});

test("snapshot selectors explain the earliest selection and the reset returns a usable comparison", async ({ page }) => {
  await page.goto("/changes");
  const earlier = await page.getByLabel("Earlier snapshot").inputValue();
  const later = await page.getByLabel("Later snapshot").inputValue();
  expect(earlier).not.toBe(later);
  await page.getByLabel("Later snapshot").selectOption(earlier);
  await page.getByRole("button", { name: "Compare snapshots", exact: true }).click();
  await expect(page.getByRole("heading", { name: "No earlier snapshot for this selection", exact: true })).toBeVisible();
  await expect(page.getByText("2 retained snapshots", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Compare latest snapshots", exact: true }).click();
  await expect(page.getByLabel("Later snapshot")).toHaveValue(later);
  await expect(page.getByRole("region", { name: "Snapshot change summary" })).toBeVisible();
  const details = page.locator(".change-feed details").first();
  await details.getByText("Field-level changes", { exact: true }).click();
  await expect(details).toHaveAttribute("open", "");
  await expect(details.getByText("Before:", { exact: true }).first()).toBeVisible();
  await expect(details.getByText("After:", { exact: true }).first()).toBeVisible();
  await details.getByText("Field-level changes", { exact: true }).click();
  await expect(details).not.toHaveAttribute("open", "");
});

test("settings explains callback failures safely and its guide and coverage links work", async ({ page }) => {
  await page.goto("/settings?authError=access_denied");
  await expect(page.locator(".settings-card").getByRole("alert")).toContainText("cancelled or access was denied");
  await page.goto("/settings?authError=%3Cscript%3Eprovider-secret%3C%2Fscript%3E");
  await expect(page.locator(".settings-card").getByRole("alert")).toHaveText("Sign-in could not be completed. Start a new sign-in below.");
  await expect(page.locator("body")).not.toContainText("provider-secret");
  await page.getByRole("link", { name: "Workspace guide", exact: true }).click();
  await expect(page).toHaveURL(/\/guide$/);
  await page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("link", { name: /Review collection status, limits and failed reads/ }).click();
  await expect(page).toHaveURL(/\/investigations\?view=coverage$/);
});
