import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { PostgresBackend } from "@entra-explorer/backend";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { compileSnapshot, exportInvestigation } from "@entra-explorer/engine";

const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const sessionId = randomUUID();
const backend = new PostgresBackend({ connectionString: process.env.TEST_DATABASE_URL!, encryptionKey: Buffer.alloc(32, 7) });
async function publishSnapshot(withTrust = false) {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("engine-browser-test", tenantId);
  const nodes = structuredClone(cleanProjectFixture.nodes).filter(n => withTrust || n.kind !== "federatedCredential").map(n => ({ ...n, tenantId }));
  if (withTrust) {
    nodes.find(n => n.kind === "federatedCredential")!.federationTrust = { issuer: "https://issuer.example.test", subject: "repo:synthetic/project:ref:refs/heads/main", audiences: ["api://AzureADTokenExchange"], unsupported: [] };
    nodes[1]!.credentials = structuredClone(nodes[0]!.credentials);
  }
  const snapshot: TenantSnapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant", tenant: { tenantId, tenantLabel: "Synthetic engine interaction test" }, scannedAt: new Date().toISOString(), nodes, edges: [] };
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
  await backend.deleteSession(sessionId, tenantId); await backend.close();
});

test("a snapshot with no permission grants still offers contracts, independent replay and honest empty federation feedback", async ({ page, context }) => {
  const snapshot = await publishSnapshot();
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const forbiddenCalls: string[] = [];
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), async route => { forbiddenCalls.push(route.request().url()); await route.abort(); });
  await page.goto("/engine?view=contracts");
  const editor = page.getByLabel("Access contract", { exact: true });
  await expect(editor).toBeVisible();
  await editor.fill(JSON.stringify({ version: 1, tenantId, id: "empty-grants-intent", kind: "only-principals", resourceId: "30000000-0000-4000-8000-000000000002", permissionId: "sample-read", allowedPrincipalIds: [] }));
  await page.getByRole("button", { name: "Evaluate contract and semantic changes" }).click();
  await expect(page.locator(".engine-result")).toContainText("pass");
  await page.goto("/engine?view=verify");
  await expect(page.getByLabel("Investigation package", { exact: true })).toBeVisible();
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  await expect(page.getByRole("button", { name: "Export investigation package", exact: true })).toBeDisabled();
  await expect(page.getByText("Evaluate a valid query above to enable package export. You can still verify an existing package below.")).toBeVisible();
  const grant = cleanProjectFixture.edges.find(e => e.type === "CAN_CALL_AS_APP")!;
  const packet = (await exportInvestigation(compileSnapshot(cleanProjectFixture), { tenantId: cleanProjectFixture.tenant.tenantId, kind: "application-permission", principalId: grant.sourceId, resourceId: grant.targetId, permissionId: grant.permissionIds![0]! }, "pseudonymized")).package;
  await page.getByLabel("Investigation package", { exact: true }).setInputFiles({ name: "other-synthetic-tenant.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(packet)) });
  await expect(page.getByRole("status").filter({ hasText: "Integrity and proof replay verified locally" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  await expect(page.locator(".trust-note")).toContainText(snapshot.id);
  await page.goto("/engine?view=federation");
  await page.getByLabel("issuer", { exact: true }).fill("https://issuer.example.test");
  await page.getByLabel("subject", { exact: true }).fill("synthetic-subject");
  await page.getByRole("button", { name: "Compare exact claims" }).click();
  await expect(page.getByRole("status").filter({ hasText: "No federated workload trusts are recorded" })).toBeVisible();
  expect(forbiddenCalls).toEqual([]);
});

test("federation claims are exact, edits clear results, and changing credential identity clears the old draft", async ({ page, context }) => {
  await publishSnapshot(true);
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await page.goto("/engine?view=federation");
  await page.getByLabel("issuer", { exact: true }).fill("https://issuer.example.test");
  await page.getByLabel("subject", { exact: true }).fill("repo:synthetic/project:ref:refs/heads/main");
  await page.getByRole("button", { name: "Compare exact claims" }).click();
  const result = page.getByRole("status").filter({ hasText: "Compared supplied claims" });
  await expect(result).toContainText("GitHub main: supported");
  await page.getByLabel("subject", { exact: true }).fill("repo:synthetic/project:ref:refs/heads/Main");
  await expect(result).toHaveCount(0);
  await page.getByRole("button", { name: "Compare exact claims" }).click();
  await expect(result).toContainText("GitHub main: refuted");
  await page.getByLabel("audience", { exact: true }).fill("different-audience");
  await expect(result).toHaveCount(0);
  await page.getByRole("button", { name: "Compare exact claims" }).click();
  await expect(result).toContainText("GitHub main: refuted");
  await page.goto("/engine?view=rotation");
  await page.getByRole("button", { name: "Create a rotation-plan template" }).click();
  const editor = page.getByLabel("Declared deployment plan");
  await expect(editor).toHaveValue(/10000000-0000-4000-8000-000000000001\/sample-new-key/);
  await page.getByLabel("Identity with credential metadata").selectOption("10000000-0000-4000-8000-000000000002");
  await expect(editor).toHaveCount(0);
  await page.getByRole("button", { name: "Create a rotation-plan template" }).click();
  await expect(editor).toHaveValue(/10000000-0000-4000-8000-000000000002\/sample-new-key/);
});

test("contract comparison names the retained prior snapshot while evaluating the edited intent", async ({ page, context }) => {
  const previous = await publishSnapshot();
  await publishSnapshot();
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await page.goto("/engine?view=contracts");
  await page.getByLabel("Access contract", { exact: true }).fill(JSON.stringify({ version: 1, tenantId, id: "required-integration", kind: "require-grant", principalId: "30000000-0000-4000-8000-000000000001", resourceId: "30000000-0000-4000-8000-000000000002", permissionId: "sample-read" }));
  await page.getByRole("button", { name: "Evaluate contract and semantic changes" }).click();
  await expect(page.locator(".engine-result")).toContainText("fail");
  await expect(page.getByText(`Compared with ${previous.id}:`, { exact: false })).toContainText("0 added / 0 absent semantic paths");
  await expect(page.getByText(`Compared with ${previous.id}:`, { exact: false })).toContainText("Complete relevant evidence");
});
