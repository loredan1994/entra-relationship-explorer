import { randomUUID } from "node:crypto";
import { PostgresBackend } from "@entra-explorer/backend";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });

async function publishInventory(count: number, parallel = false) {
  const base = cleanProjectFixture.edges.find(edge => edge.type === "CAN_CALL_AS_APP")!;
  const caller = { ...cleanProjectFixture.nodes.find(node => node.id === base.sourceId)!, tenantId };
  const resource = { ...cleanProjectFixture.nodes.find(node => node.id === base.targetId)!, tenantId };
  const resources = Array.from({ length: parallel ? 1 : count }, (_, index) => ({ ...resource, id: `synthetic-resource-${index}`, label: `Resource ${String(index).padStart(3, "0")}` }));
  const snapshot: TenantSnapshot = {
    ...cleanProjectFixture, id: randomUUID(), mode: "tenant", tenant: { tenantId, tenantLabel: "Synthetic map scale test" }, scannedAt: new Date().toISOString(), nodes: [caller, ...resources],
    edges: Array.from({ length: count }, (_, index) => ({ ...base, tenantId, id: `synthetic-edge-${index}`, targetId: resources[parallel ? 0 : index]!.id, type: index % 2 ? "CAN_CALL_DELEGATED" : "CAN_CALL_AS_APP", permissions: [`Synthetic.Read.${String(index).padStart(3, "0")}`] })),
  };
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("map-scale-test", tenantId);
  await backend.completeJob(job.id, "map-scale-test", snapshot, new Date(0));
  return snapshot;
}

test.beforeAll(async () => {
  await backend.migrate();
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await backend.createSession({ id: sessionId, tenantId, account: {}, accessToken: "synthetic-not-a-graph-token", accessTokenExpiresAt: Date.now() + 3600000, tokenCache: "synthetic", sessionExpiresAt: Date.now() + 3600000 });
});
test.beforeEach(async ({ context }) => {
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), route => route.abort());
});
test.afterAll(async () => {
  await backend.pruneExpiredData(tenantId, new Date("9999-01-01"));
  await backend.deleteSession(sessionId, tenantId);
  await backend.close();
});

test("search and object bounds retain a selected late relationship and Table restores the complete inventory", async ({ page }) => {
  await publishInventory(125);
  await page.goto("/map?q=Synthetic.Read.124");
  await expect(page.getByRole("status").filter({ hasText: "recorded relationships" })).toHaveText("Showing 1–1 of 1 recorded relationships.");
  await page.getByRole("button", { name: "Inspect", exact: true }).click();
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await expect(page.locator(".entity-node")).toHaveCount(2);
  await expect(page.locator(".connection-label")).toHaveCount(1);
  await expect(page.locator(".connection-label")).toContainText("Synthetic.Read.124");
  await expect(page.getByRole("heading", { name: "No relationships match" })).toHaveCount(0);
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  const status = page.getByRole("status").filter({ hasText: "recorded relationships" });
  await expect(status).toHaveText("Showing 101–125 of 125 recorded relationships.");
  const finalRow = page.getByRole("row").filter({ hasText: "Synthetic.Read.124" });
  await finalRow.getByRole("button", { name: "Inspect", exact: true }).click();
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await expect(page.locator(".entity-node")).toHaveCount(15);
  await expect(page.locator(".connection-label[aria-pressed=true]")).toContainText("Synthetic.Read.124");
  await expect(page.locator(".scope-banner")).toContainText("14 of 125 matching relationships for this object");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(status).toHaveText("Showing 101–125 of 125 recorded relationships.");
  await page.getByRole("button", { name: "Previous relationships" }).click();
  await expect(status).toHaveText("Showing 51–100 of 125 recorded relationships.");
  await page.getByRole("button", { name: "Previous relationships" }).click();
  await expect(status).toHaveText("Showing 1–50 of 125 recorded relationships.");
  await expect(page.getByRole("button", { name: "Previous relationships" })).toBeDisabled();
});

test("parallel grants have a bounded map, retain a deep-linked selection, and stay complete in Table", async ({ page }) => {
  await publishInventory(250, true);
  await page.goto("/map?edge=synthetic-edge-249");
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await expect(page.locator(".entity-node")).toHaveCount(2);
  await expect(page.locator(".connection-label")).toHaveCount(50);
  await expect(page.locator(".connection-label[aria-pressed=true]")).toContainText("Synthetic.Read.249");
  await expect(page.locator(".scope-banner")).toContainText("50 of 250 matching relationships for this object");
  await page.getByRole("button", { name: "Clear one-hop focus", exact: true }).click();
  await expect(page.getByRole("button", { name: "Table", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("status").filter({ hasText: "recorded relationships" })).toHaveText("Showing 201–250 of 250 recorded relationships.");
  await expect(page.getByRole("row")).toHaveCount(51);
  await expect(page.getByRole("button", { name: "Next relationships" })).toBeDisabled();
});

test("permission sorting and filters operate over all grants beyond the first page", async ({ page }) => {
  await publishInventory(125);
  await page.goto("/permissions");
  const rows = page.locator(".permissions-data-table tbody tr");
  await expect(rows).toHaveCount(50);
  await page.getByRole("button", { name: "Resource", exact: false }).click();
  await page.getByRole("button", { name: "Resource", exact: false }).click();
  await expect(rows.first()).toContainText("Resource 124");
  await expect(page.getByRole("status").filter({ hasText: "Showing" })).toContainText("resource, Z to A");
  await page.getByRole("button", { name: "Show 50 more of 75 remaining" }).click();
  await expect(rows).toHaveCount(100);
  await page.getByRole("combobox", { name: "Access type", exact: true }).selectOption("delegated");
  await expect(rows).toHaveCount(50);
  await expect(rows.first()).toContainText("Resource 123");
  await expect(page.getByRole("status").filter({ hasText: "Showing" })).toContainText("50 of 62 grants");
  await page.getByRole("textbox", { name: "Search callers, resources, or permissions" }).fill("Synthetic.Read.123");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("Resource 123");
  await rows.first().getByRole("link", { name: "Inspect", exact: true }).click();
  await expect(page).toHaveURL(/\/map\?edge=synthetic-edge-123$/);
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText("Synthetic.Read.123");
});

test("broadening a map search retains the inspected relationship without recentering ordinary inspection", async ({ page }) => {
  await publishInventory(125);
  await page.goto("/map");
  await page.getByRole("button", { name: "Map", exact: true }).click();
  const search = page.getByPlaceholder("Name or permission", { exact: true });
  await search.fill("Synthetic.Read.124");
  await expect(page.locator(".connection-label")).toHaveCount(1);
  await page.getByRole("button", { name: "Fit", exact: true }).click();
  const canvas = page.locator(".relationship-canvas");
  await canvas.focus();
  await page.keyboard.press("ArrowRight");
  const scaler = page.locator(".canvas-scaler");
  const beforeInspect = await scaler.getAttribute("style");
  await page.locator(".connection-label").click();
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText("Synthetic.Read.124");
  await expect(scaler).toHaveAttribute("style", beforeInspect!);
  await search.fill("");
  await expect(page.locator(".entity-node")).toHaveCount(15);
  await expect(page.locator(".connection-label[aria-pressed=true]")).toContainText("Synthetic.Read.124");
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toContainText("Synthetic.Read.124");
});
