import { randomUUID } from "node:crypto";
import { PostgresBackend } from "@entra-explorer/backend";
import { analyzeTenantIntelligence, cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { expect, test } from "@playwright/test";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });

async function publish(scannedAt: string): Promise<TenantSnapshot> {
  const snapshot: TenantSnapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant", tenant: { tenantId, tenantLabel: "Synthetic export binding" }, scannedAt,
    nodes: cleanProjectFixture.nodes.map(node => ({ ...node, tenantId })), edges: cleanProjectFixture.edges.map(edge => ({ ...edge, tenantId })) };
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("export-binding-test", tenantId);
  await backend.completeJob(job.id, "export-binding-test", snapshot, new Date(0));
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

test("a new scan cannot silently replace the evidence exported by an already open finding", async ({ page, context }) => {
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), route => route.abort());
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const displayed = await publish(new Date(Date.now() - 60000).toISOString());
  const finding = analyzeTenantIntelligence(displayed).findings.find(candidate => candidate.attackPathId)!;
  await page.goto(`/security?finding=${encodeURIComponent(finding.id)}`);
  await expect(page.getByLabel("Owner", { exact: true })).toBeEnabled();
  await page.getByLabel("Owner", { exact: true }).fill("Unsaved original decision");
  const downloadUrls = await page.locator('a[href^="/api/export/"]').evaluateAll(links => links.map(link => (link as HTMLAnchorElement).href));
  expect(downloadUrls).toHaveLength(5);
  expect(downloadUrls.every(url => new URL(url).searchParams.get("snapshot") === displayed.id)).toBe(true);
  const newer = await publish(new Date().toISOString());
  expect(newer.id).not.toBe(displayed.id);
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  const response = page.waitForResponse(result => new URL(result.url()).pathname === "/api/export/evidence-packet.md");
  await page.getByRole("link", { name: "Finding packet · Markdown", exact: true }).click();
  expect((await response).status()).toBe(409);
  await expect(page.getByRole("status").filter({ hasText: "displayed snapshot" })).toBeVisible();
  await expect(page).toHaveURL(`/security?finding=${encodeURIComponent(finding.id)}`);
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("Unsaved original decision");
  for (const url of downloadUrls) expect((await page.request.get(url)).status()).toBe(409);
  expect(downloads).toEqual([]);
  expect((await backend.recentAccessEvents(tenantId)).filter(event => event.action === "export" && event.sessionId === sessionId)).toEqual([]);
});
