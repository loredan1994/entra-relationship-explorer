import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("ledger explains reconciliation and preserves consent audience through filtering", async ({ page }) => {
  await page.goto("/investigations?view=ledger");
  await expect(page.getByRole("heading", { name: "Requested versus granted permissions" })).toBeVisible();
  await expect(page.getByRole("cell", { name: /^requested and granted/ })).toBeVisible();
  await expect(page.getByRole("cell", { name: /^granted not requested/ })).toBeVisible();
  await expect(page.getByRole("cell", { name: /^requested not granted/ })).toBeVisible();
  await expect(page.getByRole("cell", { name: "All users", exact: true })).toBeVisible();
  await page.getByLabel("Filter identities, resources, permissions or status").fill("Api.Export");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page.getByRole("row")).toHaveCount(2);
  await expect(page.getByRole("cell", { name: /^requested not granted/ })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("credential workbench distinguishes expired key from valid replacement", async ({ page }) => {
  await page.goto("/investigations?view=credentials");
  const registration = page.locator("article").filter({ hasText: "sample-old-key" });
  await expect(registration).toContainText("Retired deployment key · expired");
  await expect(registration).toContainText("Replacement certificate · valid");
  await expect(registration).toContainText("An expired credential has a valid replacement");
  await expect(registration).toContainText("repo:clean-project/orchestrator:ref:refs/heads/main");
});

test("what-if removes a control path while preserving alternatives, and resets without writes", async ({ page }) => {
  await page.goto("/investigations?view=scenarios");
  const writes: string[] = [];
  page.on("request", request => { if (!["GET", "HEAD"].includes(request.method())) writes.push(request.url()); });
  // The summary strip is a div with a label; use its stable accessible annotation.
  const counters = page.locator('[aria-label="Scenario results"]');
  const baseline = Number(await counters.locator("article").first().locator("strong").textContent());
  expect(baseline).toBeGreaterThan(1);
  const ownership = page.locator(".scenario-choices label").filter({ hasText: "70000000-0000-4000-8000-000000000006" }).getByRole("checkbox");
  await ownership.check();
  await expect(counters.locator("article").nth(1).locator("strong")).not.toHaveText("0");
  await expect(counters.locator("article").nth(2).locator("strong")).not.toHaveText("0");
  await expect(page.getByText("1 excluded /", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Rank candidate changes" }).click();
  await expect(page.getByRole("heading", { name: "Candidate changes" })).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export review plan" }).click();
  expect((await downloadPromise).suggestedFilename()).toBe("entra-scenario.json");
  await page.getByRole("button", { name: "Reset scenario" }).click();
  await expect(ownership).not.toBeChecked();
  await expect(counters.locator("article").nth(2).locator("strong")).toHaveText(String(baseline));
  expect(writes).toEqual([]);
});

test("timeline shows field-level consent changes and unknown audit attribution", async ({ page }) => {
  await page.goto("/changes");
  await expect(page.getByLabel("Earlier snapshot")).toHaveValue("80000000-0000-4000-8000-000000000000");
  await expect(page.getByLabel("Later snapshot")).toHaveValue("80000000-0000-4000-8000-000000000001");
  const consent = page.locator(".change-list article").filter({ hasText: "CAN_CALL_DELEGATED" });
  await consent.getByText("Field-level changes").click();
  await expect(consent).toContainText('"single-user"');
  await expect(consent).toContainText('"all-users"');
  await expect(consent).toContainText("Actor unknown");
  await page.getByLabel("Earlier snapshot").selectOption("80000000-0000-4000-8000-000000000001");
  await page.getByRole("button", { name: "Compare snapshots" }).click();
  await expect(page.getByText("The selected pair is unavailable or out of order.", { exact: false })).toBeVisible();
});

test("coverage and rule laboratory render with clear collection boundaries", async ({ page }) => {
  await page.goto("/investigations");
  await expect(page.getByRole("heading", { name: "Collection readiness and evidence coverage" })).toBeVisible();
  await expect(page.getByText("Optional activity is not included in this synthetic sample.").first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("link", { name: "Rule laboratory" }).click();
  await expect(page.getByRole("heading", { name: "Synthetic rule laboratory" })).toBeVisible();
  await expect(page.locator("pre")).toContainText("pnpm rule:lab replay");
});

test("scenario import restores exclusions, rejects a foreign tenant, and leaves the current plan intact", async ({ page }) => {
  await page.goto("/investigations?view=scenarios");
  const writes: string[] = [];
  page.on("request", request => { if (!["GET", "HEAD"].includes(request.method())) writes.push(request.url()); });
  const ownership = page.locator(".scenario-choices label").filter({ hasText: "70000000-0000-4000-8000-000000000006" }).getByRole("checkbox");
  await ownership.check();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export review plan" }).click();
  const downloaded = await downloadPromise;
  const stream = await downloaded.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  const plan = JSON.parse(Buffer.concat(chunks).toString());
  await page.getByRole("button", { name: "Reset scenario" }).click();
  await expect(ownership).not.toBeChecked();
  const file = (data: unknown) => ({ name: "scenario.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(data)) });
  await page.getByLabel("Import review plan").setInputFiles(file(plan));
  await expect(ownership).toBeChecked();
  await expect(page.locator(".investigation-card").getByRole("status")).toContainText("Results were recomputed");
  await page.getByLabel("Import review plan").setInputFiles(file({ ...plan, tenantId: "other" }));
  await expect(page.locator(".investigation-card").getByRole("status")).toContainText("different tenant");
  await expect(ownership).toBeChecked();
  expect(writes).toEqual([]);
});

test("interactive rule lab shows failures, negative cases and rejects tenant imports without requests", async ({ page }) => {
  await page.goto("/investigations?view=rules");
  const writes: string[] = [];
  page.on("request", request => { if (!["GET", "HEAD"].includes(request.method())) writes.push(request.url()); });
  await page.getByRole("button", { name: "Replay synthetic case" }).click();
  await expect(page.locator(".rule-laboratory").getByRole("status")).toContainText("Passed");
  const editor = page.getByLabel("Synthetic scenario JSON");
  const positive = JSON.parse(await editor.inputValue());
  positive.expectations[0].minimum = 0; positive.expectations[0].maximum = 0;
  await editor.fill(JSON.stringify(positive));
  await expect(page.getByRole("region", { name: "Rule replay results" })).toHaveCount(0);
  await page.getByRole("button", { name: "Replay synthetic case" }).click();
  await expect(page.locator(".rule-laboratory").getByRole("status")).toContainText("Failed");
  await page.getByRole("button", { name: "Load negative case" }).click();
  await page.getByRole("button", { name: "Replay synthetic case" }).click();
  await expect(page.locator(".rule-laboratory").getByRole("status")).toContainText("Passed");
  await expect(page.getByRole("cell", { name: "0", exact: true })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await editor.fill(JSON.stringify({ ...positive, tenantId: "real-data-is-not-accepted" }));
  await page.getByRole("button", { name: "Replay synthetic case" }).click();
  await expect(page.locator(".rule-laboratory").getByRole("alert")).toContainText("tenant exports are not accepted");
  expect(writes).toEqual([]);
});

test("timeline exposes the individual replacement certificate and ledger keeps consent in the inspector", async ({ page }) => {
  await page.goto("/changes");
  const history = page.getByRole("region", { name: "Credential and trust history" });
  await expect(history).toContainText("sample-new-key");
  await expect(history).toContainText("Replacement certificate");
  await expect(history.locator(".change-kind")).toHaveText("added");
  await page.goto("/investigations?view=ledger");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "All users", exact: true }) });
  await row.getByRole("link", { name: "Inspect relationship" }).click();
  await expect(page.getByText("Consent audience", { exact: true })).toBeVisible();
  await expect(page.locator(".evidence-facts")).toContainText("All users");
  await expect(page.getByText("Consent principal ID", { exact: true })).toBeVisible();
});

test("application access review filters identities, separates consent and links to original evidence", async ({ page }) => {
  await page.goto("/investigations?view=applications");
  await expect(page.getByRole("heading", { name: "Application access review", exact: true })).toBeVisible();
  await page.getByLabel("Filter application names, IDs or publishers").fill("30000000-0000-4000-8000-000000000002");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  const selected = page.getByRole("region", { name: "Selected application access" });
  await expect(selected.getByRole("heading", { name: "Clean Project API", exact: true })).toBeVisible();
  await expect(selected).toContainText("sample-publisher");
  await expect(selected).toContainText("10000000-0000-4000-8000-000000000002");
  await expect(page.getByRole("cell", { name: "This organization (single tenant)", exact: true })).toBeVisible();
  await expect(selected.getByRole("cell").filter({ hasText: "All users" })).toBeVisible();
  await expect(selected).toContainText("Missing activity does not establish inactivity");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await selected.getByRole("link", { name: "Inspect relationship" }).first().click();
  await expect(page).toHaveURL(/\/map\?edge=/);
  await expect(page.locator(".entity-pair")).toContainText("30000000-0000-4000-8000-000000000002");
  await expect(page.locator(".evidence-facts")).toContainText("71000000-0000-4000-8000-000000000001");
  await page.goto("/investigations?view=applications&q=Expense%20Reporter");
  await expect(page.getByRole("row").nth(1)).toContainText("Unknown — not recorded");
  await page.getByLabel("Filter application names, IDs or publishers").fill("No matching identity");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page.getByText("No application identities match this filter.")).toBeVisible();
  await expect(page.getByRole("region", { name: "Selected application access" })).toHaveCount(0);
});
