import { randomUUID } from "node:crypto";
import { expect, test, type BrowserContext } from "@playwright/test";
import { PostgresBackend } from "@entra-explorer/backend";
import { cleanProjectFixture } from "@entra-explorer/domain";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
let sessionId: string;
const createdJobs = new Set<string>();

async function enqueueTestScan() {
  const job = await backend.enqueueScan(tenantId, sessionId);
  createdJobs.add(job.id);
  return job;
}

async function signIn(context: BrowserContext) {
  sessionId = randomUUID();
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-not-a-graph-token", accessTokenExpiresAt: Date.now() + 3600000, tokenCache: "synthetic", sessionExpiresAt: Date.now() + 3600000 });
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
}

test.beforeAll(async () => { await backend.migrate(); });
test.beforeEach(async ({ context, page }) => {
  // Also recover this isolated fixture after an interrupted earlier test run.
  const leftover = await backend.getLatestJob(tenantId);
  if (leftover && ["queued", "running", "cancel_requested"].includes(leftover.status)) {
    const cancelled = await backend.requestScanCancellation(leftover.id, tenantId);
    if (cancelled?.status === "cancel_requested" && cancelled.workerId) await backend.cancelJob(cancelled.id, cancelled.workerId);
  }
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await signIn(context);
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), route => route.abort());
  await page.clock.install({ time: new Date("2026-10-09T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-09T12:00:01Z"));
});
test.afterEach(async () => {
  // Retention intentionally preserves queued/running work. Explicitly finish
  // jobs created by this test so a session-loss case cannot leak an active scan
  // into the next case's otherwise empty tenant workspace.
  for (const id of createdJobs) {
    const job = await backend.requestScanCancellation(id, tenantId);
    if (job?.status === "cancel_requested" && job.workerId) await backend.cancelJob(id, job.workerId);
  }
  createdJobs.clear();
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await backend.deleteSession(sessionId, tenantId);
});
test.afterAll(async () => { await backend.close(); });

test("a lost real session stops scan polling, exposes sign-in recovery and resumes the retained job after sign-in", async ({ page, context }) => {
  const job = await enqueueTestScan();
  await page.goto("/settings");
  await expect(page.getByRole("button", { name: "Scan in progress", exact: true })).toBeDisabled();
  let polls = 0;
  page.on("request", request => { if (request.method() === "GET" && request.url().endsWith(`/api/v1/scans/${job.id}`)) polls += 1; });
  await backend.deleteSession(sessionId, tenantId);
  await page.clock.runFor(1_000);
  await expect(page.locator(".scan-control").getByRole("alert")).toContainText("Your session has expired.");
  await expect(page.getByRole("link", { name: "Sign in again", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel scan", exact: true })).toHaveCount(0);
  await expect(page.getByText(/Progress below is the last known status/)).toBeVisible();
  await page.clock.runFor(60_000);
  expect(polls).toBe(1);
  // Test the recovery navigation without contacting Microsoft. The synthetic
  // callback restores a real database session before returning to Settings.
  await page.route("**/api/auth/sign-in", async route => {
    await signIn(context);
    await route.fulfill({ status: 302, headers: { location: "/settings?connected=1" } });
  });
  await page.getByRole("link", { name: "Sign in again", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\?connected=1$/);
  await expect(page.getByRole("button", { name: "Scan in progress", exact: true })).toBeDisabled();
  await expect(page.locator(".scan-control").getByRole("alert")).toHaveCount(0);
  await page.getByRole("button", { name: "Cancel scan", exact: true }).click();
  await expect(page.getByText("Scan cancelled", { exact: true })).toBeVisible();
  expect((await backend.getJob(job.id, tenantId))?.status).toBe("cancelled");
});

for (const action of ["start", "cancel"] as const) {
  test(`a lost session during ${action} replaces dead actions with a sign-in link`, async ({ page }) => {
    if (action === "cancel") await enqueueTestScan();
    await page.goto("/settings");
    await backend.deleteSession(sessionId, tenantId);
    await page.getByRole("button", { name: action === "start" ? "Start read-only scan" : "Cancel scan", exact: true }).click();
    await expect(page.locator(".scan-control").getByRole("alert")).toContainText("Your session has expired.");
    await expect(page.getByRole("link", { name: "Sign in again", exact: true })).toHaveAttribute("href", "/api/auth/sign-in");
    await expect(page.getByRole("button", { name: action === "start" ? "Start read-only scan" : "Cancel scan", exact: true })).toHaveCount(0);
  });
}

test("a connected workspace without scans gives useful export recovery instead of a failing download", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("link", { name: "Export relationship table", exact: true })).toHaveCount(0);
  await expect(page.getByText("Complete a read-only scan to export tenant relationships.")).toBeVisible();
  await page.getByRole("navigation", { name: "Product sections" }).getByRole("link", { name: "Permissions", exact: true }).click();
  await expect(page.getByRole("link", { name: "Export CSV", exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Scan tenant to enable exports", exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByRole("button", { name: "Start read-only scan", exact: true })).toBeEnabled();
});


test("large permission inventories load the next page and expand permission values without losing filters", async ({ page }) => {
  const job = await enqueueTestScan();
  await backend.claimNextJob("permission-controls-test", tenantId);
  const grant = cleanProjectFixture.edges.find(edge => edge.type === "CAN_CALL_AS_APP")!;
  const snapshot = {
    ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const,
    tenant: { tenantId, tenantLabel: "Synthetic permission controls" }, scannedAt: new Date().toISOString(),
    nodes: cleanProjectFixture.nodes.map(node => ({ ...node, tenantId })),
    edges: Array.from({ length: 55 }, (_, index) => ({ ...grant, tenantId, id: `synthetic-grant-${index}`, permissions: ["Api.Read", "Api.Write", "Jobs.Read", "Jobs.Write", "Events.Read", "Events.Write"] })),
  };
  await backend.completeJob(job.id, "permission-controls-test", snapshot, new Date(0));
  await page.goto("/permissions");
  const rows = page.locator(".permissions-data-table tbody tr");
  await expect(rows).toHaveCount(50);
  await expect(page.locator(".table-result-count")).toContainText("Showing 50 of 55 grants");
  await page.getByRole("button", { name: "Show 5 more of 5 remaining", exact: true }).click();
  await expect(rows).toHaveCount(55);
  await expect(page.getByRole("button", { name: /more of .* remaining/ })).toHaveCount(0);
  const first = rows.first();
  await expect(first.locator(".permission-pills > span")).toHaveCount(4);
  await first.getByRole("button", { name: "+2 more", exact: true }).click();
  await expect(first.locator(".permission-pills > span")).toHaveCount(6);
  await first.getByRole("button", { name: "Show fewer", exact: true }).click();
  await expect(first.locator(".permission-pills > span")).toHaveCount(4);
  await page.getByLabel("Search callers, resources, or permissions").fill("Jobs.Read");
  await expect(rows).toHaveCount(50);
  await expect(page.getByRole("button", { name: "Show 5 more of 5 remaining", exact: true })).toBeVisible();
});
