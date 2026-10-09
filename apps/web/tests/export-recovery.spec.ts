import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, test, type Page } from "@playwright/test";

const intelligence = analyzeTenantIntelligence(cleanProjectFixture);
const finding = intelligence.findings.find(candidate => candidate.attackPathId)!;
const exportPath = "/api/export/evidence-packet.md";
const exportLabel = "Finding packet · Markdown";
const packet = "# Synthetic finding packet\n\nConfigured access; not observed activity.\n";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

async function openEditedFinding(page: Page) {
  await page.goto(`/security?finding=${finding.id}`);
  await page.getByRole("button", { name: "Edit a review copy" }).click();
  await page.getByLabel("Step narrative", { exact: true }).first().fill("Keep this analyst hypothesis while exporting");
  await page.getByLabel("Owner", { exact: true }).fill("Synthetic review team");
  await page.getByRole("textbox", { name: "Assumptions and notes", exact: true }).fill("This decision still needs investigation.");
}

async function expectDraftUnchanged(page: Page) {
  await expect(page).toHaveURL(`/security?finding=${finding.id}`);
  await expect(page.getByLabel("Step narrative", { exact: true }).first()).toHaveValue("Keep this analyst hypothesis while exporting");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Synthetic review team");
  await expect(page.getByRole("textbox", { name: "Assumptions and notes", exact: true })).toHaveValue("This decision still needs investigation.");
}

for (const scenario of [
  { status: 401, message: "Sign in again in Settings" },
  { status: 409, message: "Copy any unsaved edits before reloading" },
]) {
  test(`a ${scenario.status} export failure preserves the investigation and explains recovery inline`, async ({ page }) => {
    const requests: string[] = [];
    const downloads: string[] = [];
    page.on("download", download => downloads.push(download.suggestedFilename()));
    await page.route(`**${exportPath}?**`, async route => {
      requests.push(route.request().url());
      await route.fulfill({ status: scenario.status, contentType: "application/json", body: JSON.stringify({ error: "Synthetic export failure" }) });
    });
    await openEditedFinding(page);
    const link = page.getByRole("link", { name: exportLabel, exact: true });
    await expect(link).toHaveAttribute("href", new RegExp(`^${exportPath.replaceAll(".", "\\.")}\\?`));
    await link.click();
    await expect(page.getByRole("status").filter({ hasText: scenario.message })).toBeVisible();
    await expectDraftUnchanged(page);
    expect(requests).toHaveLength(1);
    expect(downloads).toEqual([]);
  });
}

test("a non-JSON export failure keeps edits and retries only after an explicit retry", async ({ page }) => {
  const requests: string[] = [];
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  await page.route(`**${exportPath}?**`, async route => {
    requests.push(route.request().url());
    if (requests.length === 1) {
      await route.fulfill({ status: 503, contentType: "text/html", body: "<html><body>Temporary upstream failure</body></html>" });
      return;
    }
    await route.fulfill({ status: 200, contentType: "text/markdown", headers: { "content-disposition": "attachment; filename=synthetic-finding.md" }, body: packet });
  });
  await openEditedFinding(page);
  await page.getByRole("link", { name: exportLabel, exact: true }).click();
  const error = page.getByRole("status").filter({ hasText: "The export could not be downloaded. Your edits remain in this page." });
  await expect(error).toBeVisible();
  await expectDraftUnchanged(page);
  expect(requests).toHaveLength(1);
  expect(downloads).toEqual([]);

  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Retry export", exact: true }).click();
  const download = await downloaded;
  expect(download.suggestedFilename()).toBe("synthetic-finding.md");
  expect(await download.failure()).toBeNull();
  await expect(error).toHaveCount(0);
  await expectDraftUnchanged(page);
  expect(requests).toHaveLength(2);
  expect(requests[1]).toBe(requests[0]);
  expect(downloads).toEqual(["synthetic-finding.md"]);
});

test("a pending export ignores repeated keyboard activation and produces one download", async ({ page }) => {
  const response = deferred();
  const requests: string[] = [];
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  await page.route(`**${exportPath}?**`, async route => {
    requests.push(route.request().url());
    await response.promise;
    await route.fulfill({ status: 200, contentType: "text/markdown", headers: { "content-disposition": "attachment; filename=synthetic-once.md" }, body: packet });
  });
  try {
    await openEditedFinding(page);
    const link = page.getByRole("link", { name: exportLabel, exact: true });
    await link.click();
    await expect(link).toHaveAttribute("aria-disabled", "true");
    await expect.poll(() => requests.length).toBe(1);
    // Keyboard activation is a real second user action even when the pending
    // link is exposed as disabled to assistive technology.
    await link.press("Enter");
    await link.press("Enter");
    const downloaded = page.waitForEvent("download");
    response.resolve();
    const download = await downloaded;
    expect(await download.failure()).toBeNull();
    await expect(link).not.toHaveAttribute("aria-disabled", "true");
    await page.waitForLoadState("networkidle");
    await expectDraftUnchanged(page);
    expect(requests).toHaveLength(1);
    expect(downloads).toEqual(["synthetic-once.md"]);
  } finally {
    response.resolve();
  }
});

test("selecting a different finding cancels a delayed export instead of downloading stale evidence", async ({ page }) => {
  const response = deferred();
  const handled = deferred();
  const requests: string[] = [];
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  await page.route(`**${exportPath}?**`, async route => {
    requests.push(route.request().url());
    const first = requests.length === 1;
    if (first) await response.promise;
    try {
      await route.fulfill({ status: 200, contentType: "text/markdown", headers: { "content-disposition": `attachment; filename=${first ? "stale" : "current"}-synthetic.md` }, body: packet });
    } finally {
      if (first) handled.resolve();
    }
  });
  try {
    await openEditedFinding(page);
    const link = page.getByRole("link", { name: exportLabel, exact: true });
    await link.click();
    await expect(link).toHaveAttribute("aria-disabled", "true");
    await expect.poll(() => requests.length).toBe(1);
    const queue = page.getByRole("complementary", { name: "Prioritized findings" });
    const next = queue.locator(".finding-button").filter({ hasNotText: finding.title }).first();
    const nextTitle = await next.locator("strong").innerText();
    await next.click();
    await expect(page.getByRole("region", { name: "Selected finding" }).getByRole("heading", { name: nextTitle, exact: true })).toBeVisible();
    response.resolve();
    await handled.promise;
    await page.waitForLoadState("networkidle");
    expect(downloads).toEqual([]);
    await expect(link).not.toHaveAttribute("aria-disabled", "true");

    const downloaded = page.waitForEvent("download");
    await link.click();
    const download = await downloaded;
    expect(download.suggestedFilename()).toBe("current-synthetic.md");
    expect(await download.failure()).toBeNull();
    expect(requests).toHaveLength(2);
    expect(new URL(requests[1]!).searchParams.get("id")).not.toBe(new URL(requests[0]!).searchParams.get("id"));
    expect(downloads).toEqual(["current-synthetic.md"]);
  } finally {
    response.resolve();
  }
});

test("a timed-out export preserves edits and retries without downloading the late response", async ({ page }) => {
  const response = deferred();
  const handled = deferred();
  const requests: string[] = [];
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  await page.route(`**${exportPath}?**`, async route => {
    requests.push(route.request().url());
    const first = requests.length === 1;
    if (first) await response.promise;
    try {
      await route.fulfill({ status: 200, contentType: "text/markdown", headers: { "content-disposition": `attachment; filename=${first ? "late" : "retried"}-synthetic.md` }, body: packet });
    } catch (error) {
      // The timeout aborts the first browser request before this gated response
      // is released. A rejected fulfillment of that cancelled request is valid.
      if (!first || !/abort|cancel/i.test(route.request().failure()?.errorText ?? "")) throw error;
    } finally {
      if (first) handled.resolve();
    }
  });
  try {
    await openEditedFinding(page);
    // Install the clock only after hydration and draft editing have completed.
    await page.clock.install();
    const link = page.getByRole("link", { name: exportLabel, exact: true });
    const aborted = page.waitForEvent("requestfailed", request => new URL(request.url()).pathname === exportPath);
    await link.click();
    await expect(link).toHaveAttribute("aria-disabled", "true");
    await expect.poll(() => requests.length).toBe(1);
    await page.clock.fastForward(30_001);
    await expect(page.getByRole("status").filter({ hasText: "The export timed out" })).toBeVisible();
    expect((await aborted).failure()?.errorText).toMatch(/abort|cancel/i);
    await expect(link).not.toHaveAttribute("aria-disabled", "true");
    await expectDraftUnchanged(page);
    expect(downloads).toEqual([]);
    expect(requests).toHaveLength(1);

    const downloaded = page.waitForEvent("download");
    await page.getByRole("button", { name: "Retry export", exact: true }).click();
    const download = await downloaded;
    expect(download.suggestedFilename()).toBe("retried-synthetic.md");
    expect(await download.failure()).toBeNull();
    await expect(page.getByRole("status").filter({ hasText: "The export timed out" })).toHaveCount(0);
    await expectDraftUnchanged(page);
    expect(requests).toHaveLength(2);
    expect(requests[1]).toBe(requests[0]);

    response.resolve();
    await handled.promise;
    await page.waitForLoadState("networkidle");
    expect(downloads).toEqual(["retried-synthetic.md"]);
  } finally {
    response.resolve();
  }
});
