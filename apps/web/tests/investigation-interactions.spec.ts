import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const intelligence = analyzeTenantIntelligence(cleanProjectFixture);
const finding = intelligence.findings.find(candidate => candidate.attackPathId && intelligence.paths.find(path => path.id === candidate.attackPathId)!.steps.length >= 2)!;

test("selecting an application brings its evidence into view and returns to the identities", async ({ page }) => {
  await page.goto("/investigations?view=applications");
  const identities = page.locator("#application-identities");
  const identity = identities.getByRole("link", { name: "Clean Project API", exact: true });
  await identity.click();
  await expect(page).toHaveURL(/identity=.*#application-access-detail$/);
  const detail = page.getByRole("region", { name: "Selected application access" });
  await expect(detail.getByRole("heading", { name: "Clean Project API", exact: true })).toBeInViewport();
  await detail.getByRole("link", { name: "Back to application identities" }).click();
  await expect(identities.getByRole("heading", { name: "Application access review", exact: true })).toBeInViewport();
});

test("application access navigation resets an unsent filter to the records actually displayed", async ({ page }) => {
  await page.goto("/investigations?view=applications&q=Expense%20Reporter");
  const query = page.getByLabel("Filter application names, IDs or publishers");
  await expect(query).toHaveValue("Expense Reporter");
  await expect(page.locator("#application-identities tbody tr")).toHaveCount(1);
  await query.fill("Unsubmitted local search");
  await page.getByRole("navigation", { name: "Investigation tools" }).getByRole("link", { name: "Application access", exact: true }).click();
  await expect(page).toHaveURL(/\/investigations\?view=applications$/);
  await expect(query).toHaveValue("");
  await expect(page.locator("#application-identities").getByRole("link", { name: "Clean Project API", exact: true })).toBeVisible();
});

test("credential filters explain no matches and provide a working reset", async ({ page }) => {
  await page.goto("/investigations?view=credentials");
  await page.getByLabel("Filter identities", { exact: true }).fill("nothing-matches-this-identity");
  await page.getByLabel("Credential state").selectOption("expired");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page.getByRole("heading", { name: "No credential identities match" })).toBeVisible();
  await expect(page.locator(".investigations").getByRole("status")).toContainText("0 matching identities");
  await page.getByRole("link", { name: "Clear credential filters" }).click();
  await expect(page.getByLabel("Filter identities", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Credential state")).toHaveValue("all");
  await expect(page.getByRole("heading", { name: "No credential identities match" })).toHaveCount(0);
  await expect(page.locator(".credential-list").first()).toBeVisible();
});

test("review flow edits reorder, remove, add, retain, and reset actual narratives within stated limits", async ({ page }) => {
  await page.goto(`/security?finding=${finding.id}`);
  await page.getByRole("button", { name: "Edit a review copy" }).click();
  const editor = page.locator(".flow-editor");
  const narratives = editor.getByLabel("Step narrative");
  const initialCount = await narratives.count();
  expect(initialCount).toBeGreaterThanOrEqual(2);
  await narratives.nth(0).fill("First analyst narrative");
  await narratives.nth(1).fill("Second analyst narrative");
  await expect(editor.getByRole("button", { name: "Move up", exact: true }).first()).toBeDisabled();
  await editor.getByRole("button", { name: "Move down", exact: true }).first().click();
  await expect(narratives.nth(0)).toHaveValue("Second analyst narrative");
  await expect(narratives.nth(1)).toHaveValue("First analyst narrative");
  await editor.getByRole("button", { name: "Move up", exact: true }).nth(1).click();
  await expect(narratives.nth(0)).toHaveValue("First analyst narrative");
  await editor.getByRole("button", { name: "Remove", exact: true }).last().click();
  await expect(narratives).toHaveCount(initialCount - 1);
  const add = page.getByRole("button", { name: "Add analyst step", exact: true });
  await add.click();
  await narratives.last().fill("New investigation step");
  await expect(editor.locator("li").last()).toContainText("Analyst-authored step; no evidence edge");
  for (let count = initialCount; count < 20; count++) await add.click();
  await expect(narratives).toHaveCount(20);
  await expect(add).toBeDisabled();
  await expect(page.getByText("Remove a step before adding another.", { exact: false })).toBeVisible();
  await narratives.last().fill("n".repeat(500));
  await narratives.last().press("End");
  await narratives.last().press("x");
  await expect(narratives.last()).toHaveValue("n".repeat(500));
  const owner = page.getByLabel("Owner", { exact: true });
  await owner.fill("o".repeat(160));
  await owner.press("End");
  await owner.press("x");
  await expect(owner).toHaveValue("o".repeat(160));
  const notes = page.getByRole("textbox", { name: "Assumptions and notes", exact: true });
  await notes.fill("a".repeat(4000));
  await notes.press("End");
  await notes.press("x");
  await expect(notes).toHaveValue("a".repeat(4000));
  await page.reload();
  await expect(narratives).toHaveCount(20);
  await expect(narratives.nth(0)).toHaveValue("First analyst narrative");
  await expect(narratives.last()).toHaveValue("n".repeat(500));
  await expect(owner).toHaveValue("o".repeat(160));
  await expect(notes).toHaveValue("a".repeat(4000));
  await page.getByRole("button", { name: "Reset to evidence" }).click();
  await expect(editor).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Edit a review copy" })).toBeEnabled();
  await page.reload();
  await expect(editor).toHaveCount(0);
});

test("finding selection is visible and focusable, with usable deep links and category reset", async ({ page }) => {
  await page.goto(`/security?finding=${finding.id}`);
  const detail = page.getByRole("region", { name: "Selected finding" });
  await expect(detail.getByRole("heading", { name: finding.title, exact: true })).toBeInViewport();
  const queue = page.getByRole("complementary", { name: "Prioritized findings" });
  const next = queue.locator(".finding-button").filter({ hasNotText: finding.title }).first();
  const nextTitle = await next.locator("strong").innerText();
  await next.click();
  await expect(detail.getByRole("heading", { name: nextTitle, exact: true })).toBeInViewport();
  await expect(detail).toBeFocused();
  if (await page.getByRole("button", { name: "Back to findings" }).isVisible()) {
    await page.getByRole("button", { name: "Back to findings" }).click();
    await expect(queue).toBeFocused();
    await expect(queue.getByRole("heading")).toBeInViewport();
  }
  await page.goto("/security?category=ownership");
  await expect(queue.getByRole("heading")).toContainText("ownership findings");
  const ownershipCount = await queue.locator(".finding-button").count();
  await queue.getByRole("button", { name: "Show all", exact: true }).click();
  expect(await queue.locator(".finding-button").count()).toBeGreaterThan(ownershipCount);
  await page.goto("/security?finding=unavailable-synthetic-finding");
  await expect(page.getByRole("status").filter({ hasText: "requested finding or category is unavailable" })).toBeVisible();
});
