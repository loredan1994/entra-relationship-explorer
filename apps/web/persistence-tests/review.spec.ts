import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { PostgresBackend } from "@entra-explorer/backend";
import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
async function publishSnapshot() {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("browser-test", tenantId);
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const, tenant: { tenantId, tenantLabel: "Synthetic persistence test" }, scannedAt: new Date().toISOString(), nodes: cleanProjectFixture.nodes.map(n => ({ ...n, tenantId })), edges: cleanProjectFixture.edges.map(e => ({ ...e, tenantId })) };
  await backend.completeJob(job.id, "browser-test", snapshot, new Date(0));
  return snapshot;
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

test("two analysts cannot overwrite each other or save a stale decision onto a new scan", async ({ page, context }) => {
  const initial = await publishSnapshot();
  const findingId = analyzeTenantIntelligence(initial).findings[0]!.id;
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const forbiddenCalls: string[] = [];
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), async route => { forbiddenCalls.push(route.request().url()); await route.abort(); });
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/threat-reviews/**", async route => { if (route.request().method() === "GET") await pending; await route.continue(); });
  await page.goto("/security");
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  release();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  const second = await context.newPage();
  await second.goto("/security");
  await expect(second.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.getByLabel("Owner", { exact: true }).fill("First analyst");
  await second.getByLabel("Owner", { exact: true }).fill("Competing analyst");
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  await second.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(second.getByText(/Review conflict:/)).toBeVisible();
  expect((await backend.getThreatReview(tenantId, initial.id, findingId))!.owner).toBe("First analyst");

  await page.getByLabel("Owner", { exact: true }).fill("Unsaved old-screen decision");
  const next = await publishSnapshot();
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("A newer scan is available. Reload and review its evidence before saving.")).toBeVisible();
  expect(await backend.getThreatReview(tenantId, next.id, findingId)).toBeNull();
  expect((await backend.getThreatReview(tenantId, initial.id, findingId))!.owner).toBe("First analyst");
  await page.reload();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("");
  await expect(page.getByText("A prior decision is available.")).toBeVisible();
  expect(forbiddenCalls).toEqual([]);
});

test("a delayed save stays bound to its finding across selection changes", async ({ page, context }) => {
  const snapshot = await publishSnapshot();
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await page.goto("/security");
  const buttons = page.locator(".finding-queue .finding-button");
  const first = page.locator(".finding-queue .finding-button.active");
  const firstTitle = await first.locator("strong").innerText();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.getByLabel("Owner", { exact: true }).fill("Saved while switching");
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  let savingId = "";
  await page.route("**/api/v1/threat-reviews/**", async route => {
    if (route.request().method() === "PUT") {
      savingId = decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1)!);
      await pending;
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Saving the decision…")).toBeVisible();
  await buttons.filter({ hasNotText: firstTitle }).first().click();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.getByLabel("Owner", { exact: true }).fill("Other unsaved finding");
  await buttons.filter({ hasText: firstTitle }).click();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Saved while switching");
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save decision", exact: true })).toBeDisabled();
  await buttons.filter({ hasNotText: firstTitle }).first().click();
  release();
  await expect.poll(async () => (await backend.getThreatReview(tenantId, snapshot.id, savingId))?.owner).toBe("Saved while switching");
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Other unsaved finding");
  await expect(page.getByText("Unsaved decision. Choose Save decision to register it.")).toBeVisible();
  await buttons.filter({ hasText: firstTitle }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  await page.getByLabel("Owner", { exact: true }).fill("New edit after save");
  await expect(page.getByText("Unsaved decision. Choose Save decision to register it.")).toBeVisible();
  expect((await backend.getThreatReview(tenantId, snapshot.id, savingId))!.owner).toBe("Saved while switching");
});

test("saved queue decisions and acceptance reminders appear before individual reviews finish loading", async ({ page, context }) => {
  const snapshot = await publishSnapshot();
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const forbiddenCalls: string[] = [];
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), async route => { forbiddenCalls.push(route.request().url()); await route.abort(); });
  await page.goto("/security");
  const queue = page.locator(".finding-queue");
  const initialTitle = await queue.locator(".finding-button.active strong").innerText();
  const otherTitles = await queue.locator(".finding-button").filter({ hasNotText: initialTitle }).locator("strong").allTextContents();
  expect(otherTitles.length).toBeGreaterThanOrEqual(2);
  const acceptedTitle = otherTitles[0]!;
  const mitigatingTitle = otherTitles[1]!;
  const accepted = queue.locator(".finding-button").filter({ has: page.getByText(acceptedTitle, { exact: true }) });
  const mitigating = queue.locator(".finding-button").filter({ has: page.getByText(mitigatingTitle, { exact: true }) });
  const expiry = new Date(Date.now() + 7 * 86_400_000).toISOString().slice(0, 10);

  await accepted.click();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  const acceptedId = await page.locator(".review-panel dl div").filter({ has: page.getByText("Finding ID", { exact: true }) }).locator("code").innerText();
  await page.locator(".review-panel").getByLabel("Status").selectOption("accepted");
  await page.getByLabel("Owner", { exact: true }).fill("Application security team");
  await page.getByLabel("Review / acceptance expiry", { exact: true }).fill(expiry);
  await page.getByLabel("Assumptions and notes", { exact: true }).fill("Synthetic exception pending a reviewed deployment next week.");
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  const savedAcceptance = await backend.getThreatReview(tenantId, snapshot.id, acceptedId);
  expect(savedAcceptance?.revision).toBeTruthy();

  await mitigating.click();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.locator(".review-panel").getByLabel("Status").selectOption("mitigating");
  await page.getByLabel("Owner", { exact: true }).fill("Platform team");
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();

  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  let expectedRevision: unknown;
  await page.route("**/api/v1/threat-reviews/**", async route => {
    if (route.request().method() === "GET") await pending;
    if (route.request().method() === "PUT") expectedRevision = route.request().postDataJSON().expectedRevision;
    await route.continue();
  });
  await page.reload();
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  await expect(queue.locator(".finding-button.active strong")).toHaveText(initialTitle);
  await expect(queue.locator(".finding-button.active em")).toHaveText("open");
  await expect(accepted.locator("em")).toHaveText("accepted");
  await expect(mitigating.locator("em")).toHaveText("mitigating");
  const due = page.locator(".lifecycle-filters").getByRole("button", { name: /acceptance due/ });
  await expect(due.locator("span")).toHaveText("1");
  await due.click();
  await expect(queue.locator(".finding-button")).toHaveCount(1);
  await expect(accepted).toBeVisible();
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save decision", exact: true })).toBeDisabled();

  release();
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Application security team");
  await expect(page.locator(".review-panel").getByLabel("Status")).toHaveValue("accepted");
  await expect(page.getByLabel("Review / acceptance expiry", { exact: true })).toHaveValue(expiry);
  await page.getByLabel("Owner", { exact: true }).fill("Revalidated application security team");
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  expect(expectedRevision).toBe(savedAcceptance!.revision);
  expect((await backend.getThreatReview(tenantId, snapshot.id, acceptedId))?.owner).toBe("Revalidated application security team");
  expect(forbiddenCalls).toEqual([]);
});
