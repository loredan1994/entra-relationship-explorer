import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { PostgresBackend } from "@entra-explorer/backend";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
const job = { id: "synthetic-scan", status: "running", stage: "Applications", collected: 3, detail: "Collecting synthetic records", completion: null, error: null };
const scanUrl = `**/api/v1/scans/${job.id}`;

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function start(page: Page) {
  await page.route("**/api/v1/scans", route => route.fulfill({ json: { job } }));
  await page.getByRole("button", { name: "Start read-only scan", exact: true }).click();
  await expect(page.getByRole("button", { name: "Scan in progress", exact: true })).toBeDisabled();
}

test.beforeAll(async () => {
  await backend.migrate();
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-not-a-graph-token", accessTokenExpiresAt: Date.now() + 3600000, tokenCache: "synthetic", sessionExpiresAt: Date.now() + 3600000 });
});
test.afterAll(async () => {
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await backend.deleteSession(sessionId, tenantId);
  await backend.close();
});
test.beforeEach(async ({ page, context }) => {
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), route => route.abort());
  await page.clock.install({ time: new Date("2026-10-09T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-09T12:00:01Z"));
  await page.goto("/settings");
});

test("scan polling waits for each response and cancellation rejects an older in-flight status", async ({ page }) => {
  const first = gate();
  const stale = gate();
  let polls = 0;
  let aborted = 0;
  page.on("requestfailed", request => { if (request.url().endsWith(`/scans/${job.id}`) && request.method() === "GET") aborted += 1; });
  await page.route(scanUrl, async route => {
    if (route.request().method() === "DELETE") return route.fulfill({ json: { job: { ...job, status: "cancel_requested", detail: "Finishing current read" } } });
    polls += 1;
    if (polls === 1) {
      await first.promise;
      return route.fulfill({ json: { job: { ...job, collected: 7 } } });
    }
    if (polls === 2) {
      await stale.promise;
      return route.fulfill({ json: { job: { ...job, detail: "Obsolete running response" } } });
    }
    return route.fulfill({ json: { job: { ...job, status: "cancelled", detail: "Stopped safely" } } });
  });
  await start(page);
  await page.clock.runFor(1_000);
  await expect.poll(() => polls).toBe(1);
  await page.clock.runFor(4_000);
  expect(polls).toBe(1);
  first.release();
  await expect(page.getByText("Collecting synthetic records · 7 records")).toBeVisible();
  await page.clock.runFor(1_000);
  await expect.poll(() => polls).toBe(2);
  await page.getByRole("button", { name: "Cancel scan", exact: true }).click();
  await expect(page.getByText("Cancellation requested", { exact: true })).toBeVisible();
  await expect.poll(() => aborted).toBe(1);
  stale.release();
  await expect(page.getByRole("button", { name: "Cancelling safely", exact: true })).toBeDisabled();
  await expect(page.getByText("Obsolete running response · 3 records")).toHaveCount(0);
  await page.clock.runFor(1_000);
  await expect(page.getByText("Scan cancelled", { exact: true })).toBeVisible();
  await page.clock.runFor(10_000);
  expect(polls).toBe(3);
});

test("polling recovers from HTTP, malformed, offline, timed-out and mismatched responses without overlap", async ({ page }) => {
  const stalled = gate();
  let polls = 0;
  await page.route(scanUrl, async route => {
    polls += 1;
    if (polls === 1) return route.fulfill({ status: 503, json: { error: "Status service unavailable." } });
    if (polls === 2) return route.fulfill({ contentType: "application/json", body: "{" });
    if (polls === 3) return route.abort("internetdisconnected");
    if (polls === 4) { await stalled.promise; return route.fulfill({ json: { job } }); }
    if (polls === 5) return route.fulfill({ json: { job: { ...job, id: "another-scan" } } });
    return route.fulfill({ json: { job: { ...job, collected: 19 } } });
  });
  await start(page);
  await page.clock.runFor(1_000);
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveText("Status service unavailable. Retrying automatically.");
  await page.clock.runFor(1_999);
  expect(polls).toBe(1);
  await page.clock.runFor(1);
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveText("Scan status could not be refreshed. Check the connection and try again. Retrying automatically.");
  await page.clock.runFor(4_000);
  await expect.poll(() => polls).toBe(3);
  await expect(page.locator(".scan-control").getByRole("alert")).toContainText("Check the connection");
  await page.clock.runFor(8_000);
  await expect.poll(() => polls).toBe(4);
  await page.clock.runFor(14_999);
  expect(polls).toBe(4);
  await page.clock.runFor(1);
  await expect(page.locator(".scan-control").getByRole("alert")).toContainText("The request timed out");
  stalled.release();
  await page.clock.runFor(10_000);
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveText("The server returned an invalid scan response. Try again. Retrying automatically.");
  await page.clock.runFor(10_000);
  await expect(page.getByText("Collecting synthetic records · 19 records")).toBeVisible();
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveCount(0);
  expect(polls).toBe(6);
});

test("failed actions remain retryable and sign-out reloads only after confirmed success", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  let starts = 0;
  let cancellations = 0;
  let signOuts = 0;
  let documentNavigations = 0;
  // Next also emits same-document history navigation after hydration. Count
  // actual document requests so the assertion measures reloads, not router events.
  page.on("request", request => { if (request.isNavigationRequest() && request.frame() === page.mainFrame()) documentNavigations += 1; });
  await page.route("**/api/v1/scans", route => {
    starts += 1;
    if (starts === 1) return route.abort("internetdisconnected");
    if (starts === 2) return route.fulfill({ status: 503, json: { error: "Scanning temporarily unavailable." } });
    if (starts === 3) return route.fulfill({ json: { job: { ...job, status: "unexpected" } } });
    return route.fulfill({ json: { job } });
  });
  await page.route(scanUrl, route => {
    if (route.request().method() === "GET") return route.fulfill({ json: { job } });
    cancellations += 1;
    if (cancellations === 1) return route.fulfill({ status: 503, json: { error: "Please retry cancellation.", job: { ...job, status: "cancelled" } } });
    if (cancellations === 2) return route.fulfill({ contentType: "application/json", body: "{" });
    return route.fulfill({ json: { job: { ...job, status: "cancelled" } } });
  });
  await page.route("**/api/auth/sign-out", route => {
    signOuts += 1;
    if (signOuts === 1) return route.fulfill({ status: 500, json: { error: "Sign-out temporarily unavailable.", signedOut: true } });
    if (signOuts === 2) return route.fulfill({ json: { signedOut: false } });
    return route.fulfill({ json: { signedOut: true } });
  });
  for (const message of ["Check the connection", "Scanning temporarily unavailable.", "invalid scan response"]) {
    await page.getByRole("button", { name: "Start read-only scan", exact: true }).click();
    await expect(page.locator(".scan-control").getByRole("alert")).toContainText(message);
    await expect(page.getByRole("button", { name: "Start read-only scan", exact: true })).toBeEnabled();
  }
  await page.getByRole("button", { name: "Start read-only scan", exact: true }).click();
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveCount(0);
  for (const message of ["Please retry cancellation.", "Cancellation failed. Check the connection"]) {
    await page.getByRole("button", { name: "Cancel scan", exact: true }).click();
    await expect(page.locator(".scan-control").getByRole("alert")).toContainText(message);
    await expect(page.getByRole("button", { name: "Cancel scan", exact: true })).toBeEnabled();
    await expect(page.getByText("Scan cancelled", { exact: true })).toHaveCount(0);
  }
  await page.getByRole("button", { name: "Cancel scan", exact: true }).click();
  await expect(page.getByText("Scan cancelled", { exact: true })).toBeVisible();
  for (const message of ["Sign-out temporarily unavailable.", "Sign-out could not be confirmed."]) {
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(page.locator(".scan-control").getByRole("alert")).toContainText(message);
    await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeEnabled();
    expect(documentNavigations).toBe(0);
  }
  const reloaded = page.waitForEvent("load");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await reloaded;
  expect(documentNavigations).toBe(1);
  expect(pageErrors).toEqual([]);
});

test("leaving settings aborts a pending poll and prevents a stale completion from reloading the next page", async ({ page }) => {
  const pending = gate();
  let polls = 0;
  let aborted = 0;
  let navigations = 0;
  page.on("requestfailed", request => { if (request.url().endsWith(`/scans/${job.id}`)) aborted += 1; });
  await page.route(scanUrl, async route => {
    polls += 1;
    await pending.promise;
    await route.fulfill({ json: { job: { ...job, status: "complete", completion: "complete" } } });
  });
  await start(page);
  await page.clock.runFor(1_000);
  await expect.poll(() => polls).toBe(1);
  await page.getByRole("link", { name: "Workspace guide", exact: true }).click();
  await expect(page).toHaveURL(/\/guide$/);
  await expect.poll(() => aborted).toBe(1);
  page.on("framenavigated", frame => { if (frame === page.mainFrame()) navigations += 1; });
  pending.release();
  await page.clock.runFor(20_000);
  await expect(page).toHaveURL(/\/guide$/);
  expect(navigations).toBe(0);
  expect(polls).toBe(1);
});

test("a stalled action times out and leaving settings aborts a retry", async ({ page }) => {
  const pending = gate();
  let starts = 0;
  let aborted = 0;
  page.on("requestfailed", request => { if (request.url().endsWith("/api/v1/scans")) aborted += 1; });
  await page.route("**/api/v1/scans", async route => {
    starts += 1;
    await pending.promise;
    await route.fulfill({ json: { job } });
  });
  await page.getByRole("button", { name: "Start read-only scan", exact: true }).click();
  await expect(page.getByRole("button", { name: "Starting scan…", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeDisabled();
  await page.clock.runFor(15_000);
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveText("The scan could not start. The request timed out. Try again.");
  await page.getByRole("button", { name: "Start read-only scan", exact: true }).click();
  await expect.poll(() => starts).toBe(2);
  await page.getByRole("link", { name: "Workspace guide", exact: true }).click();
  await expect(page).toHaveURL(/\/guide$/);
  await expect.poll(() => aborted).toBe(2);
  pending.release();
  await page.clock.runFor(20_000);
  expect(starts).toBe(2);
});
