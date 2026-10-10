import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const intelligence = analyzeTenantIntelligence(cleanProjectFixture);
const finding = intelligence.findings.find(candidate => candidate.attackPathId)!;
const storageKey = `entra-threat-workspace:${cleanProjectFixture.id}`;

test("a blocked browser save keeps the authored decision usable and reports that it is not persisted", async ({ page, isMobile }) => {
  await page.addInitScript(() => {
    const setItem = Storage.prototype.setItem;
    let unavailable = true;
    window.addEventListener("allow-review-storage", () => { unavailable = false; });
    Storage.prototype.setItem = function (key, value) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
      return setItem.call(this, key, value);
    };
  });
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`/security?finding=${finding.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Application security team");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Application security team");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await expect(page.locator(".record-save-state")).not.toContainText("Decision saved in this browser.");
  await page.getByRole("button", { name: "Edit a review copy" }).click();
  await page.getByLabel("Step narrative").first().fill("An intact local draft");
  await expect(page.getByLabel("Step narrative").first()).toHaveValue("An intact local draft");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await page.evaluate(() => window.dispatchEvent(new Event("allow-review-storage")));
  await page.getByRole("button", { name: "Retry browser save", exact: true }).click();
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  const stored = await page.evaluate(key => JSON.parse(localStorage.getItem(key)!), storageKey);
  expect(stored[finding.id].owner).toBe("Application security team");
  expect(stored[finding.id].flowDraft[0].title).toBe("An intact local draft");
  if (isMobile) await page.getByRole("button", { name: "Back to findings" }).click();
  await page.locator(".finding-button").last().click();
  await expect(page.getByRole("region", { name: "Selected finding", exact: true })).toBeFocused();
  expect(errors).toEqual([]);
});

test("malformed saved review data cannot crash the workspace and does not hide another valid review", async ({ page }) => {
  const other = intelligence.findings.find(candidate => candidate.id !== finding.id)!;
  await page.addInitScript(({ key, corruptId, validId }) => {
    localStorage.setItem(key, JSON.stringify({
      [corruptId]: { disposition: "accepted", owner: 17, flowDraft: [null] },
      [validId]: { disposition: "mitigating", owner: "Retained reviewer", expiresAt: "", assumption: "Keep this valid decision", flowDraft: [] },
    }));
  }, { key: storageKey, corruptId: finding.id, validId: other.id });
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`/security?finding=${finding.id}`);
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("");
  await expect(page.getByRole("main").getByRole("alert")).toContainText("saved review data");
  await page.locator(".finding-button").filter({ has: page.getByText(other.title, { exact: true }) }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Retained reviewer");
  expect(errors).toEqual([]);
});

test("a browser that denies storage access still allows a local review without claiming persistence", async ({ page, isMobile }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", { get() { throw new DOMException("Storage is denied", "SecurityError"); } });
  });
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`/security?finding=${finding.id}`);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Browser storage is unavailable");
  await page.getByLabel("Owner", { exact: true }).fill("Working local draft");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Working local draft");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  if (isMobile) await page.getByRole("button", { name: "Back to findings" }).click();
  await page.locator(".finding-button").last().click();
  await expect(page.getByRole("region", { name: "Selected finding", exact: true })).toBeFocused();
  expect(errors).toEqual([]);
});
