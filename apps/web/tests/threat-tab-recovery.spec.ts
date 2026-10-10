import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const findings = analyzeTenantIntelligence(cleanProjectFixture).findings;
const first = findings[0]!;
const second = findings.find(finding => finding.id !== first.id)!;

test("two open review tabs preserve independent decisions and synchronize their saved context", async ({ page, context }) => {
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await other.goto(`/security?finding=${second.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("First application team");
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await other.getByLabel("Owner", { exact: true }).fill("Second application team");
  await expect(other.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await page.locator(".finding-button").filter({ has: page.getByText(second.title, { exact: true }) }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Second application team");
  await other.reload();
  await other.locator(".finding-button").filter({ has: other.getByText(first.title, { exact: true }) }).click();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("First application team");
  await other.close();
});

test("retrying a blocked browser save preserves another tab's later decision", async ({ page, context }) => {
  await page.addInitScript(() => {
    const original = Storage.prototype.setItem;
    let unavailable = true;
    window.addEventListener("restore-review-storage", () => { unavailable = false; });
    Storage.prototype.setItem = function (key, value) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
      return original.call(this, key, value);
    };
  });
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await other.goto(`/security?finding=${second.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Unsaved first team");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await other.getByLabel("Owner", { exact: true }).fill("Saved second team");
  await expect(other.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Unsaved first team");
  await page.evaluate(() => window.dispatchEvent(new Event("restore-review-storage")));
  await page.getByRole("button", { name: "Retry browser save", exact: true }).click();
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await other.reload();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("Saved second team");
  await other.locator(".finding-button").filter({ has: other.getByText(first.title, { exact: true }) }).click();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("Unsaved first team");
  await other.close();
});

test("a conflicting unsaved field never replaces a newer decision without explicit recovery", async ({ page, context }) => {
  await page.addInitScript(() => {
    const original = Storage.prototype.setItem;
    let unavailable = true;
    window.addEventListener("restore-review-storage", () => { unavailable = false; });
    Storage.prototype.setItem = function (key, value) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
      return original.call(this, key, value);
    };
  });
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await other.goto(`/security?finding=${first.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Unsaved local owner");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await other.getByLabel("Owner", { exact: true }).fill("Newer saved owner");
  await expect(other.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await page.evaluate(() => window.dispatchEvent(new Event("restore-review-storage")));
  await page.getByRole("button", { name: "Retry browser save", exact: true }).click();
  await expect(page.locator(".record-save-state")).toContainText("Another tab changed");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Unsaved local owner");
  await other.reload();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("Newer saved owner");
  await page.getByRole("button", { name: "Reload saved decision", exact: true }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Newer saved owner");
  await page.getByLabel("Assumptions and notes").fill("Reviewed the new owner");
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await other.reload();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("Newer saved owner");
  await expect(other.getByLabel("Assumptions and notes")).toHaveValue("Reviewed the new owner");
  await other.close();
});

test("a decision waiting for another tab completes its save after client navigation", async ({ page, context }) => {
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await other.goto("/overview");
  const key = `entra-threat-workspace:${cleanProjectFixture.id}`;
  await other.evaluate(async storageKey => {
    await new Promise<void>(resolve => {
      void navigator.locks.request(storageKey, () => new Promise<void>(release => {
        (window as unknown as { releaseReviewLock: () => void }).releaseReviewLock = release;
        resolve();
      }));
    });
  }, key);
  await page.getByLabel("Owner", { exact: true }).fill("Save before leaving this finding");
  await expect.soft(page.locator(".record-save-state")).toContainText("Saving the decision");
  await page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Overview", exact: true }).click();
  await expect(page).toHaveURL(/\/overview$/);
  await page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Threat workspace", exact: true }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("");
  await other.evaluate(() => (window as unknown as { releaseReviewLock: () => void }).releaseReviewLock());
  await expect.poll(() => other.evaluate(({ storageKey, id }) => JSON.parse(localStorage.getItem(storageKey) ?? "{}")[id]?.owner, { storageKey: key, id: first.id })).toBe("Save before leaving this finding");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Save before leaving this finding");
  await other.close();
});

test("unavailable browser coordination keeps the local draft and explains its actual recovery requirement", async ({ page }) => {
  await page.addInitScript(() => { Object.defineProperty(navigator, "locks", { value: undefined }); });
  await page.goto(`/security?finding=${first.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Local draft without locking");
  await expect(page.locator(".record-save-state")).toContainText("cannot coordinate review saves");
  await expect(page.locator(".record-save-state")).toContainText("remain in this page");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Local draft without locking");
});

test("editing a newly synchronized field uses the visible value while retaining an unrelated unsaved field", async ({ page, context }) => {
  await page.addInitScript(() => {
    const original = Storage.prototype.setItem;
    let unavailable = true;
    window.addEventListener("restore-review-storage", () => { unavailable = false; });
    Storage.prototype.setItem = function (key, value) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
      return original.call(this, key, value);
    };
  });
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await other.goto(`/security?finding=${first.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Pending owner");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await other.getByLabel("Assumptions and notes").fill("New information from the other tab");
  await expect(other.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await expect(page.getByLabel("Assumptions and notes")).toHaveValue("New information from the other tab");
  await page.getByLabel("Assumptions and notes").fill("Reviewed the new information");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await page.evaluate(() => window.dispatchEvent(new Event("restore-review-storage")));
  await page.getByRole("button", { name: "Retry browser save", exact: true }).click();
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await other.reload();
  await expect(other.getByLabel("Owner", { exact: true })).toHaveValue("Pending owner");
  await expect(other.getByLabel("Assumptions and notes")).toHaveValue("Reviewed the new information");
  await other.close();
});

test("recovered initial storage access also restores synchronization with other tabs", async ({ page, context }) => {
  await page.addInitScript(() => {
    const get = Storage.prototype.getItem, set = Storage.prototype.setItem;
    let unavailable = true;
    window.addEventListener("restore-review-storage", () => { unavailable = false; });
    Storage.prototype.getItem = function (key) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage denied", "SecurityError");
      return get.call(this, key);
    };
    Storage.prototype.setItem = function (key, value) {
      if (unavailable && key.startsWith("entra-threat-workspace:")) throw new DOMException("Storage denied", "SecurityError");
      return set.call(this, key, value);
    };
  });
  const other = await context.newPage();
  await page.goto(`/security?finding=${first.id}`);
  await page.getByLabel("Owner", { exact: true }).fill("Recovered owner");
  await expect(page.locator(".record-save-state")).toContainText("not saved in this browser");
  await page.evaluate(() => window.dispatchEvent(new Event("restore-review-storage")));
  await page.getByRole("button", { name: "Retry browser save", exact: true }).click();
  await expect(page.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await other.goto(`/security?finding=${first.id}`);
  await other.getByLabel("Assumptions and notes").fill("New context after access recovered");
  await expect(other.locator(".record-save-state")).toHaveText("Decision saved in this browser.");
  await expect(page.getByLabel("Assumptions and notes")).toHaveValue("New context after access recovered");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Recovered owner");
  await other.close();
});
