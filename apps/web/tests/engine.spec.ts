import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const views = ["proof", "authorization", "time", "plans", "policy", "federation", "rotation", "gaps", "contracts", "verify"];

test("all ten engine workflows render accessibly without network writes or viewport overflow", async ({ page }) => {
  const errors: string[] = [], writes: string[] = [];
  page.on("pageerror", e => errors.push(e.message));
  page.on("request", r => { if (!["GET", "HEAD"].includes(r.method())) writes.push(r.url()); });
  for (const view of views) {
    await page.goto(`/engine?view=${view}`);
    await expect(page.getByRole("heading", { name: "Reason about access", exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Engine workflows" }).getByRole("link")).toHaveCount(10);
    expect(await page.evaluate(() => document.body.scrollWidth <= window.innerWidth + 1), view).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations, view).toEqual([]);
  }
  expect(errors).toEqual([]); expect(writes).toEqual([]);
});

test("access compiler exposes exact permission proof and clears irrelevant permission filters when switching queries", async ({ page }) => {
  await page.goto("/engine?view=authorization");
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  await expect(page.locator(".engine-paths")).toContainText("70000000-0000-4000-8000-000000000003");
  await page.getByLabel("Permission ID (required)").fill("not-a-configured-permission");
  await page.getByRole("button", { name: "Evaluate recorded evidence" }).click();
  await expect(page.getByRole("heading", { name: "Result: refuted", exact: true })).toBeVisible();
  await page.getByLabel("Question type").selectOption("ownership");
  await page.getByLabel("Principal", { exact: true }).selectOption("50000000-0000-4000-8000-000000000001");
  await page.getByLabel("Resource or group").selectOption("10000000-0000-4000-8000-000000000001");
  await page.getByRole("button", { name: "Evaluate recorded evidence" }).click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
});

test("planner proposes a change and honors a protected grant without applying it", async ({ page }) => {
  await page.goto("/engine?view=plans");
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.getByRole("heading", { name: "Plan 1 · cost 1" })).toBeVisible();
  await page.getByText("Protect required application integrations", { exact: true }).click();
  await page.locator(".scenario-choices").getByRole("checkbox").first().check();
  await expect(page.getByRole("heading", { name: "Plan 1 · cost 1" })).toHaveCount(0);
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.locator(".engine-result")).toContainText("infeasible");
});

test("contract changes recompute failures and reject cross-tenant intent", async ({ page }) => {
  await page.goto("/engine?view=contracts");
  const editor = page.getByLabel("Access contract", { exact: true });
  await page.getByRole("button", { name: "Evaluate contract and semantic changes" }).click();
  await expect(page.locator(".engine-result")).toContainText("pass");
  const contract = JSON.parse(await editor.inputValue()); contract.allowedPrincipalIds = [];
  await editor.fill(JSON.stringify(contract));
  await page.getByRole("button", { name: "Evaluate contract and semantic changes" }).click();
  await expect(page.locator(".engine-result")).toContainText("fail");
  await editor.fill(JSON.stringify({ ...contract, tenantId: "foreign" }));
  await page.getByRole("button", { name: "Evaluate contract and semantic changes" }).click();
  await expect(page.locator(".engine-workspace").getByRole("alert")).toContainText("Cross-tenant");
});

test("portable package downloads, replays offline and rejects tampered facts", async ({ page }) => {
  await page.goto("/engine?view=verify");
  const exportButton = page.getByRole("button", { name: "Export investigation package", exact: true });
  await expect(exportButton).toBeDisabled();
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  const downloadPromise = page.waitForEvent("download"); await exportButton.click();
  const stream = await (await downloadPromise).createReadStream(); const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  const packet = JSON.parse(Buffer.concat(chunks).toString());
  expect(packet.sharing).toBe("pseudonymized"); expect(JSON.stringify(packet)).not.toContain("Clean Project");
  const upload = (data: unknown) => ({ name: "investigation.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(data)) });
  await page.getByLabel("Investigation package", { exact: true }).setInputFiles(upload(packet));
  await expect(page.getByRole("status").filter({ hasText: "Integrity and proof replay verified locally" })).toBeVisible();
  packet.snapshot.edges[0].permissionIds = ["tampered"];
  await page.getByLabel("Investigation package", { exact: true }).setInputFiles(upload(packet));
  await expect(page.getByRole("status").filter({ hasText: "integrity check failed" })).toBeVisible();
});

test("empty synthetic policy coverage produces counterexamples and unconfirmed deployments stay unknown", async ({ page }) => {
  await page.goto("/engine?view=policy");
  await page.getByRole("button", { name: "Find policy counterexamples" }).click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  await page.goto("/engine?view=rotation");
  await page.getByRole("button", { name: "Create a rotation-plan template" }).click();
  const editor = page.getByLabel("Declared deployment plan");
  const plan = JSON.parse(await editor.inputValue()); expect(plan.deployments.every((d: { availableFrom: unknown }) => d.availableFrom === null)).toBe(true);
  await page.getByRole("button", { name: "Simulate credential continuity" }).click();
  await expect(page.getByRole("heading", { name: "Result: unknown", exact: true })).toBeVisible();
  for (const deployment of plan.deployments) deployment.availableFrom = plan.horizon.startsAt;
  plan.clockSkewSeconds = 0;
  await editor.fill(JSON.stringify(plan)); await page.getByRole("button", { name: "Simulate credential continuity" }).click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
});
