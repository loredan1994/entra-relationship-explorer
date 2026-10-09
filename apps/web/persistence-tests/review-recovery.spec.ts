import { randomUUID } from "node:crypto";
import { PostgresBackend } from "@entra-explorer/backend";
import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });

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

test("retrying a failed review read clears its stale error without losing another finding's unsaved decision", async ({ page, context }) => {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("review-recovery-test", tenantId);
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const, tenant: { tenantId, tenantLabel: "Synthetic review recovery" }, scannedAt: new Date().toISOString(), nodes: cleanProjectFixture.nodes.map(node => ({ ...node, tenantId })), edges: cleanProjectFixture.edges.map(edge => ({ ...edge, tenantId })) };
  await backend.completeJob(job.id, "review-recovery-test", snapshot, new Date(0));
  const [first, second] = analyzeTenantIntelligence(snapshot).findings;
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const forbiddenCalls: string[] = [];
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), async route => { forbiddenCalls.push(route.request().url()); await route.abort(); });
  let failuresRemaining = 2;
  await page.route("**/api/v1/threat-reviews/**", async route => {
    const id = decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1)!);
    if (route.request().method() === "GET" && id === first!.id && failuresRemaining-- > 0) {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "Synthetic temporary database outage" }) });
    } else await route.continue();
  });
  await page.goto(`/security?finding=${first!.id}`);
  await expect(page.locator(".record-save-state")).toContainText("The review could not be loaded");
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  await page.locator(".finding-button").filter({ has: page.getByText(second!.title, { exact: true }) }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.getByLabel("Owner", { exact: true }).fill("Retain this unsaved owner");
  await page.locator(".finding-button").filter({ has: page.getByText(first!.title, { exact: true }) }).click();
  await expect(page.locator(".record-save-state")).toContainText("The review could not be loaded");
  await page.getByRole("button", { name: "Retry review load", exact: true }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await expect(page.locator(".record-save-state")).not.toContainText("could not be loaded");
  await expect(page.getByRole("button", { name: "Retry review load", exact: true })).toHaveCount(0);
  await page.locator(".finding-button").filter({ has: page.getByText(second!.title, { exact: true }) }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Retain this unsaved owner");
  await expect(page.locator(".record-save-state")).toContainText("Unsaved decision");
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.locator(".record-save-state")).toHaveText("Decision registered in the tenant record.");
  expect((await backend.getThreatReview(tenantId, snapshot.id, second!.id))?.owner).toBe("Retain this unsaved owner");
  expect(forbiddenCalls).toEqual([]);
});
