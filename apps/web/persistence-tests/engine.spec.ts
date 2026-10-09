import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { PostgresBackend } from "@entra-explorer/backend";
import { cleanProjectFixture } from "@entra-explorer/domain";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
async function publishSnapshot(edgeCount?: number) {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("engine-browser-test", tenantId);
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const, tenant: { tenantId, tenantLabel: "Synthetic engine test" }, scannedAt: new Date().toISOString(), nodes: cleanProjectFixture.nodes.map(n => ({ ...n, tenantId })), edges: cleanProjectFixture.edges.map(e => ({ ...e, tenantId })) };
  if (edgeCount) snapshot.edges = Array.from({ length: edgeCount }, (_, i) => ({ ...snapshot.edges[0]!, id: `paging-edge-${i}`, permissions: [`Paging.Permission.${i}`] }));
  await backend.completeJob(job.id, "engine-browser-test", snapshot, new Date(0));
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

test("engine navigation starts a fresh query when a new scan replaces the displayed evidence", async ({ page, context }) => {
  const first = await publishSnapshot();
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const writes: string[] = [];
  page.on("request", request => { if (!["GET", "HEAD"].includes(request.method())) writes.push(request.url()); });
  await page.goto("/engine?view=proof");
  await expect(page.locator(".engine-workspace > .trust-note")).toContainText(first.id);
  await page.getByLabel("Permission ID (required)").fill("old-snapshot-query");
  await page.getByRole("button", { name: "Evaluate recorded evidence" }).click();
  await expect(page.getByRole("heading", { name: "Result: refuted", exact: true })).toBeVisible();
  const second = await publishSnapshot();
  // A client navigation retains component state unless it is bound to the snapshot.
  await page.getByRole("navigation", { name: "Engine workflows" }).getByRole("link", { name: "Access compiler", exact: true }).click();
  await expect(page.locator(".engine-workspace > .trust-note")).toContainText(second.id);
  const permission = second.edges.find(edge => edge.type === "CAN_CALL_AS_APP" && edge.permissionIds?.length)!.permissionIds![0]!;
  await expect(page.getByLabel("Permission ID (required)")).toHaveValue(permission);
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  expect(writes).toEqual([]);
});

test("large relationship tables paginate, retain deep-link evidence and reset when filtering", async ({ page, context }) => {
  await publishSnapshot(123);
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await page.goto("/map?edge=paging-edge-112");
  await expect(page.getByRole("status").filter({ hasText: "Showing 101–123 of 123" })).toBeVisible();
  await expect(page.locator(".relationship-table tr")).toHaveCount(24);
  await expect(page.locator(".relationship-table tr.selected")).toContainText("Paging.Permission.112");
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText("Paging.Permission.112");
  await expect(page.getByRole("button", { name: "Next relationships" })).toBeDisabled();
  await page.getByRole("button", { name: "Previous relationships" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Showing 51–100 of 123" })).toBeVisible();
  await expect(page.locator(".relationship-table tr")).toHaveCount(51);
  await page.getByPlaceholder("Name or permission", { exact: true }).fill("Paging.Permission.122");
  await expect(page.getByRole("status").filter({ hasText: "Showing 1–1 of 1" })).toBeVisible();
  await expect(page.locator(".relationship-table tr")).toHaveCount(2);
  await expect(page.getByRole("button", { name: "Next relationships" })).toHaveCount(0);
  await page.locator(".relationship-table").getByRole("button", { name: "Inspect" }).click();
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText("Paging.Permission.122");
});
