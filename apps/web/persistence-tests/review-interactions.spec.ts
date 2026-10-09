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

test("review flow loading and saving disable every editor while preserving the complete authored decision", async ({ page, context }) => {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("review-interaction-test", tenantId);
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const, tenant: { tenantId, tenantLabel: "Synthetic review interactions" }, scannedAt: new Date().toISOString(), nodes: cleanProjectFixture.nodes.map(node => ({ ...node, tenantId })), edges: cleanProjectFixture.edges.map(edge => ({ ...edge, tenantId })) };
  await backend.completeJob(job.id, "review-interaction-test", snapshot, new Date(0));
  const intelligence = analyzeTenantIntelligence(snapshot);
  const finding = intelligence.findings.find(candidate => candidate.attackPathId && intelligence.paths.find(path => path.id === candidate.attackPathId)!.steps.length >= 2)!;
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  const forbiddenCalls: string[] = [];
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), async route => { forbiddenCalls.push(route.request().url()); await route.abort(); });
  let releaseLoad!: () => void;
  const loading = new Promise<void>(resolve => { releaseLoad = resolve; });
  let releaseSave!: () => void;
  const saving = new Promise<void>(resolve => { releaseSave = resolve; });
  await page.route("**/api/v1/threat-reviews/**", async route => {
    if (route.request().method() === "GET") await loading;
    if (route.request().method() === "PUT") await saving;
    await route.continue();
  });
  await page.goto(`/security?finding=${finding.id}`);
  const edit = page.getByRole("button", { name: "Edit a review copy" });
  await expect(edit).toBeDisabled();
  await expect(page.getByText("Loading the saved review…", { exact: true })).toBeVisible();
  await expect(page.getByText("Review controls are unavailable while the saved decision loads.")).toBeVisible();
  await expect(page.getByLabel("Owner", { exact: true })).toBeDisabled();
  releaseLoad();
  await expect(edit).toBeEnabled();
  await edit.click();
  const editor = page.locator(".flow-editor");
  const narratives = editor.getByLabel("Step narrative");
  await narratives.first().fill("Validated first path step");
  await narratives.nth(1).fill("Validated second path step");
  await editor.getByRole("button", { name: "Move down", exact: true }).first().click();
  await expect(narratives.first()).toHaveValue("Validated second path step");
  await editor.getByRole("button", { name: "Move up", exact: true }).nth(1).click();
  await editor.getByRole("button", { name: "Remove", exact: true }).last().click();
  await page.getByRole("button", { name: "Add analyst step" }).click();
  await narratives.last().fill("a".repeat(500));
  await page.getByLabel("Owner", { exact: true }).fill("o".repeat(160));
  await page.getByRole("textbox", { name: "Assumptions and notes", exact: true }).fill("n".repeat(4000));
  const expectedNarratives = await Promise.all((await narratives.all()).map(input => input.inputValue()));
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Saving the decision…", { exact: true })).toBeVisible();
  await expect(page.getByText("Review controls are unavailable while the decision is saving.")).toBeVisible();
  for (const input of await narratives.all()) await expect(input).toBeDisabled();
  for (const button of await editor.getByRole("button").all()) await expect(button).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reset to evidence" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Add analyst step" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save decision", exact: true })).toBeDisabled();
  releaseSave();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  const saved = await backend.getThreatReview(tenantId, snapshot.id, finding.id);
  expect(saved?.flowDraft?.map(step => step.title)).toEqual(expectedNarratives);
  expect(saved?.owner).toBe("o".repeat(160));
  expect(saved?.assumption).toBe("n".repeat(4000));
  expect(saved?.flowDraft?.at(-1)?.evidenceEdgeId).toBeNull();
  await page.reload();
  await expect(narratives).toHaveCount(expectedNarratives.length);
  expect(await Promise.all((await narratives.all()).map(input => input.inputValue()))).toEqual(expectedNarratives);
  await expect(page.getByLabel("Owner", { exact: true })).toHaveValue("o".repeat(160));
  await expect(page.getByRole("textbox", { name: "Assumptions and notes", exact: true })).toHaveValue("n".repeat(4000));

  const response = await page.request.put(`/api/v1/threat-reviews/${finding.id}?snapshot=${snapshot.id}`, {
    headers: { origin: "http://127.0.0.1:3101" },
    data: { expectedRevision: saved!.revision, disposition: "open", owner: saved!.owner, assumption: saved!.assumption, flowDraft: [...saved!.flowDraft!, { id: "oversized-narrative", title: "x".repeat(501), evidenceEdgeId: null }] },
  });
  expect(response.status()).toBe(400);
  expect((await backend.getThreatReview(tenantId, snapshot.id, finding.id))?.revision).toBe(saved!.revision);
  expect((await backend.getThreatReview(tenantId, snapshot.id, finding.id))?.flowDraft?.map(step => step.title)).toEqual(expectedNarratives);
  await page.getByRole("button", { name: "Reset to evidence" }).click();
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  await page.reload();
  await expect(edit).toBeEnabled();
  await expect(editor).toHaveCount(0);
  expect((await backend.getThreatReview(tenantId, snapshot.id, finding.id))?.flowDraft).toEqual([]);
  expect(forbiddenCalls).toEqual([]);
});

test("a generated review with long object labels saves immediately and retains the full source explanation", async ({ page, context }) => {
  const job = await backend.enqueueScan(tenantId, sessionId);
  await backend.claimNextJob("long-label-review-test", tenantId);
  const snapshot = { ...cleanProjectFixture, id: randomUUID(), mode: "tenant" as const, tenant: { tenantId, tenantLabel: "Synthetic long-label review" }, scannedAt: new Date().toISOString(), nodes: cleanProjectFixture.nodes.map(node => ({ ...node, tenantId, label: node.label.padEnd(250, "x") })), edges: cleanProjectFixture.edges.map(edge => ({ ...edge, tenantId })) };
  await backend.completeJob(job.id, "long-label-review-test", snapshot, new Date(0));
  const intelligence = analyzeTenantIntelligence(snapshot);
  const finding = intelligence.findings.find(candidate => candidate.attackPathId && intelligence.paths.find(path => path.id === candidate.attackPathId)!.steps.some(step => step.explanation.length > 500))!;
  const path = intelligence.paths.find(candidate => candidate.id === finding.attackPathId)!;
  const longIndex = path.steps.findIndex(step => step.explanation.length > 500);
  const fullExplanation = path.steps[longIndex]!.explanation;
  expect(fullExplanation.length).toBeGreaterThan(500);
  await context.addCookies([{ name: "entra_explorer_session", value: sessionId, url: "http://127.0.0.1:3101", httpOnly: true, sameSite: "Lax" }]);
  await context.route(url => ["graph.microsoft.com", "login.microsoftonline.com"].includes(url.hostname), route => route.abort());
  await page.goto(`/security?finding=${finding.id}`);
  const edit = page.getByRole("button", { name: "Edit a review copy" });
  await expect(edit).toBeEnabled();
  await edit.click();
  await expect(page.getByText("Long source explanations start as shortened review summaries", { exact: false })).toBeVisible();
  const longStep = page.locator(".flow-editor > li").nth(longIndex);
  await expect(longStep.getByLabel("Step narrative")).toHaveValue(`${fullExplanation.slice(0, 499)}…`);
  await longStep.getByText("Full source explanation", { exact: true }).click();
  await expect(longStep.locator("details p")).toHaveText(fullExplanation);
  await page.getByRole("button", { name: "Save decision", exact: true }).click();
  await expect(page.getByText("Decision registered in the tenant record.")).toBeVisible();
  const saved = await backend.getThreatReview(tenantId, snapshot.id, finding.id);
  expect(saved?.flowDraft).toHaveLength(path.steps.length);
  expect(saved!.flowDraft!.every(step => step.title.length <= 500)).toBe(true);
  expect(saved!.flowDraft![longIndex]!.evidenceEdgeId).toBe(path.steps[longIndex]!.edgeId);
  await page.reload();
  await expect(page.locator(".flow-editor > li")).toHaveCount(path.steps.length);
  await longStep.getByText("Full source explanation", { exact: true }).click();
  await expect(longStep.locator("details p")).toHaveText(fullExplanation);
  await page.getByRole("button", { name: "Reset to evidence" }).click();
  await expect(page.locator(".attack-flow > li").nth(longIndex).locator("strong")).toHaveText(fullExplanation);
});
