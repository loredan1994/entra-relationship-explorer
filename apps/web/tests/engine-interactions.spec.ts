import { expect, test, type Download, type Page } from "@playwright/test";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { compileSnapshot, exportInvestigation } from "@entra-explorer/engine";

const caller = "30000000-0000-4000-8000-000000000001";
const resource = "30000000-0000-4000-8000-000000000002";
const owner = "50000000-0000-4000-8000-000000000001";
const group = "60000000-0000-4000-8000-000000000001";
const role = "93000000-0000-4000-8000-000000000001";
const scope = "/administrativeUnits/90000000-0000-4000-8000-000000000002";
const query = { tenantId: cleanProjectFixture.tenant.tenantId, kind: "application-permission" as const, principalId: caller, resourceId: resource, permissionId: "sample-read" };
const upload = (value: unknown, name = "investigation.json") => ({ name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(value)) });
async function readDownload(download: Download) {
  const stream = await download.createReadStream(), chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString());
}
async function downloadFrom(page: Page, name: string) {
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name, exact: true }).click();
  return readDownload(await downloaded);
}

// Hold browser work at the actual asynchronous boundary, without timing guesses.
async function holdNextDigest(page: Page) {
  await page.evaluate(() => {
    const original = crypto.subtle.digest.bind(crypto.subtle);
    const target = window as unknown as { releaseDigest: () => Promise<void>; digestHeld: boolean };
    target.digestHeld = false;
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    crypto.subtle.digest = async (...args) => {
      // Next also hashes navigation/cache data; delay only the package integrity body.
      if (!new TextDecoder().decode(args[1]).includes('"format":"entra-investigation/1"')) return original(...args);
      crypto.subtle.digest = original;
      const result = await original(...args);
      target.digestHeld = true;
      await held;
      return result;
    };
    target.releaseDigest = async () => {
      release();
      await new Promise(resolve => setTimeout(resolve, 0));
    };
  });
}
async function waitForDigest(page: Page) {
  await page.waitForFunction(() => (window as unknown as { digestHeld: boolean }).digestHeld);
}
async function releaseDigest(page: Page) {
  await page.evaluate(() => (window as unknown as { releaseDigest: () => Promise<void> }).releaseDigest());
}

test("query controls keep user context, exact role scope and optional permission semantics distinct", async ({ page }) => {
  await page.goto("/engine?view=authorization");
  const evaluate = page.getByRole("button", { name: "Evaluate recorded evidence" });
  const kind = page.getByLabel("Question type");
  const principal = page.getByLabel("Principal", { exact: true });
  const target = page.getByLabel("Resource or group");
  await kind.selectOption("delegated-permission");
  await principal.selectOption("30000000-0000-4000-8000-000000000003");
  await page.getByLabel("Permission ID (required)").fill("sample-read-scope");
  await page.getByRole("combobox", { name: "User context", exact: true }).selectOption(owner);
  await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: unknown", exact: true })).toBeVisible();
  await page.getByText("Inspect reproducible result", { exact: true }).click();
  const details = page.locator(".engine-json pre");
  expect(JSON.parse(await details.innerText()).query.userId).toBe(owner);
  await kind.selectOption("assignment");
  await principal.selectOption(group); await target.selectOption(caller);
  await page.getByLabel("Permission ID (optional)").fill(""); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  expect(JSON.parse(await details.innerText()).query.userId).toBeUndefined();
  await kind.selectOption("membership"); await principal.selectOption(owner); await target.selectOption(group); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: unknown", exact: true })).toBeVisible();
  expect(JSON.parse(await details.innerText()).query.permissionId).toBeUndefined();
  await kind.selectOption("active-role"); await target.selectOption(role);
  await page.getByLabel("Exact directory scope").fill(scope); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  expect(JSON.parse(await details.innerText()).query.directoryScopeId).toBe(scope);
  await page.getByLabel("Exact directory scope").fill("/"); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: unknown", exact: true })).toBeVisible();
  await kind.selectOption("eligible-role"); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: unknown", exact: true })).toBeVisible();
  await kind.selectOption("control-path"); await principal.selectOption(caller); await target.selectOption(resource); await evaluate.click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  expect(JSON.parse(await details.innerText()).query.directoryScopeId).toBeUndefined();
  await page.locator(".engine-paths").getByRole("link").first().click();
  await expect(page).toHaveURL(/\/map\?edge=/);
  await expect(page.getByRole("complementary", { name: "Selected relationship evidence" })).toBeVisible();
});

test("clearing a rotation draft keeps the editor usable and exports the replacement plan", async ({ page }) => {
  await page.goto("/engine?view=rotation");
  await page.getByRole("button", { name: "Create a rotation-plan template" }).click();
  const editor = page.getByLabel("Declared deployment plan");
  const plan = JSON.parse(await editor.inputValue());
  await editor.fill("");
  await expect(editor).toBeVisible();
  await page.getByRole("button", { name: "Simulate credential continuity" }).click();
  await expect(page.locator(".engine-workspace").getByRole("alert")).toHaveText("Enter a rotation plan before simulating continuity.");
  plan.clockSkewSeconds = 0;
  for (const deployment of plan.deployments) deployment.availableFrom = plan.horizon.startsAt;
  await editor.fill(JSON.stringify(plan));
  await expect(page.locator(".engine-workspace").getByRole("alert")).toHaveCount(0);
  await page.getByRole("button", { name: "Simulate credential continuity" }).click();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  const exported = await downloadFrom(page, "Export sensitive rotation model");
  expect(exported.plan).toEqual(plan); expect(exported.result.intervals.length).toBeGreaterThan(0);
  await editor.fill("{");
  await expect(page.getByRole("button", { name: "Export sensitive rotation model" })).toHaveCount(0);
  await page.getByRole("button", { name: "Simulate credential continuity" }).click();
  await expect(page.locator(".engine-workspace").getByRole("alert")).toBeVisible();
});

test("contract templates recover from invalid JSON and export their own evaluated intent", async ({ page }) => {
  await page.goto("/engine?view=contracts");
  const template = page.getByLabel("Choose a contract template");
  const editor = page.getByLabel("Access contract", { exact: true });
  const evaluate = page.getByRole("button", { name: "Evaluate contract and semantic changes" });
  await editor.fill("{"); await evaluate.click();
  await expect(page.locator(".engine-workspace").getByRole("alert")).toBeVisible();
  await template.selectOption("require-grant");
  await expect(page.locator(".engine-workspace").getByRole("alert")).toHaveCount(0);
  await evaluate.click();
  await expect(page.locator(".engine-result")).toContainText("pass");
  expect(await downloadFrom(page, "Export sensitive contract")).toEqual(JSON.parse(await editor.inputValue()));
  await template.selectOption("no-control-path"); await evaluate.click();
  await expect(page.locator(".engine-result")).toContainText("fail");
  await expect(page.getByText("No prior retained snapshot is available for comparison.")).toBeVisible();
  await page.getByText("Contract schema", { exact: true }).click();
  await expect(page.locator("details").filter({ has: page.getByText("Contract schema", { exact: true }) }).locator("pre")).toContainText("no-control-path");
});

test("planner cost and policy intent edits invalidate old exports and recompute", async ({ page }) => {
  await page.goto("/engine?view=plans");
  await page.getByLabel(/^Cost for /).fill("7");
  await page.getByRole("button", { name: "Compare proposed changes" }).click();
  await expect(page.getByRole("heading", { name: "Plan 1 · cost 7", exact: true })).toBeVisible();
  const plan = await downloadFrom(page, "Export sensitive review plans");
  expect(plan.plans[0].cost).toBe(7); expect(plan.plans[0].residualPaths).toEqual([]);
  await page.getByLabel(/^Cost for /).fill("2");
  await expect(page.getByRole("button", { name: "Export sensitive review plans" })).toHaveCount(0);
  await page.goto("/engine?view=policy");
  await page.getByRole("combobox", { name: "Intent", exact: true }).selectOption("compliantDevice");
  await page.getByRole("button", { name: "Find policy counterexamples" }).click();
  const policy = await downloadFrom(page, "Export sensitive scenarios for comparison");
  expect(policy.witnesses.length).toBeGreaterThan(0);
  await page.getByLabel("User object IDs, comma-separated, or All").fill(owner);
  await page.getByLabel("Resource application IDs, comma-separated, or All").fill("20000000-0000-4000-8000-000000000002");
  await expect(page.getByRole("button", { name: "Export sensitive scenarios for comparison" })).toHaveCount(0);
  await page.getByRole("combobox", { name: "Intent", exact: true }).selectOption("block");
  await page.getByRole("button", { name: "Find policy counterexamples" }).click();
  await expect(page.getByRole("heading", { name: "Counterexample 1", exact: true })).toBeVisible();
});

test("a newer package selection owns verification even when an older file finishes last", async ({ page }) => {
  const packet = (await exportInvestigation(compileSnapshot(cleanProjectFixture), query, "pseudonymized")).package;
  await page.addInitScript(() => {
    const original = File.prototype.text;
    File.prototype.text = async function () {
      if (this.name === "older-invalid.json") await new Promise<void>(resolve => {
        (window as unknown as { releaseFile: () => void }).releaseFile = resolve;
      });
      return original.call(this);
    };
  });
  await page.goto("/engine?view=verify");
  const input = page.getByLabel("Investigation package", { exact: true });
  await input.setInputFiles({ name: "older-invalid.json", mimeType: "application/json", buffer: Buffer.from("{") });
  await expect(page.getByRole("status").filter({ hasText: "Verifying older-invalid.json locally" })).toBeVisible();
  await input.setInputFiles(upload(packet, "latest.json"));
  const current = page.getByRole("status").filter({ hasText: "Integrity and proof replay verified locally for latest.json" });
  await expect(current).toBeVisible();
  await page.evaluate(async () => { (window as unknown as { releaseFile: () => void }).releaseFile(); await new Promise(resolve => setTimeout(resolve, 0)); });
  await expect(current).toBeVisible();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toBeVisible();
  await input.setInputFiles({ name: "too-large.json", mimeType: "application/json", buffer: Buffer.alloc(5_000_001, " ") });
  await expect(page.getByRole("status").filter({ hasText: "must be at most 5 MB" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toHaveCount(0);
  await input.setInputFiles(upload(packet, "latest.json"));
  await expect(current).toBeVisible();
});

test("a newer invalid package supersedes a valid verification already hashing", async ({ page }) => {
  const packet = (await exportInvestigation(compileSnapshot(cleanProjectFixture), query, "pseudonymized")).package;
  await page.goto("/engine?view=verify");
  await holdNextDigest(page);
  const input = page.getByLabel("Investigation package", { exact: true });
  await input.setInputFiles(upload(packet, "older-valid.json"));
  await waitForDigest(page);
  await expect(page.getByRole("status").filter({ hasText: "Verifying older-valid.json locally" })).toBeVisible();
  await input.setInputFiles(upload({ format: "invalid" }, "latest-invalid.json"));
  const error = page.locator(".engine-workspace").getByRole("status").filter({ hasNotText: "Verifying" });
  await expect(error).toBeVisible(); const message = await error.innerText();
  await releaseDigest(page);
  await expect(error).toHaveText(message);
  await expect(page.getByRole("heading", { name: "Result: supported", exact: true })).toHaveCount(0);
});

test("export is pending once and changing the evaluated query cancels the old download", async ({ page }) => {
  await page.goto("/engine?view=verify");
  await holdNextDigest(page);
  const downloads: Download[] = []; page.on("download", value => downloads.push(value));
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  await page.getByRole("button", { name: "Export investigation package", exact: true }).click();
  await waitForDigest(page);
  await expect(page.getByRole("button", { name: "Exporting investigation package…", exact: true })).toBeDisabled();
  await expect(page.getByRole("status").filter({ hasText: "Preparing the investigation package locally" })).toBeVisible();
  await page.getByLabel("Permission ID (required)").fill("sample-write");
  await page.getByRole("button", { name: "Evaluate recorded evidence" }).click();
  await releaseDigest(page);
  expect(downloads).toHaveLength(0);
  await expect(page.getByRole("button", { name: "Export investigation package", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save private mapping separately" })).toHaveCount(0);
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  await page.getByRole("checkbox", { name: "Replace identifiers with stable per-export pseudonyms" }).uncheck();
  const packet = await downloadFrom(page, "Export investigation package");
  expect(packet.query.permissionId).toBe("sample-write"); expect(packet.sharing).toBe("identified");
  await expect(page.getByRole("button", { name: "Save private mapping separately" })).toHaveCount(0);
});

test("changing export disclosure options invalidates pending work and its private mapping", async ({ page }) => {
  await page.goto("/engine?view=verify"); await holdNextDigest(page);
  const downloads: Download[] = []; page.on("download", value => downloads.push(value));
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  await page.getByRole("button", { name: "Export investigation package", exact: true }).click();
  await waitForDigest(page);
  await page.getByRole("checkbox", { name: /I understand this export/ }).uncheck(); await releaseDigest(page);
  expect(downloads).toHaveLength(0);
  await page.getByRole("checkbox", { name: /I understand this export/ }).check();
  const packet = await downloadFrom(page, "Export investigation package");
  const mapping = await downloadFrom(page, "Save private mapping separately");
  expect(packet.sharing).toBe("pseudonymized"); expect(mapping[caller]).toBe(packet.query.principalId);
  await page.getByRole("checkbox", { name: "Replace identifiers with stable per-export pseudonyms" }).uncheck();
  await expect(page.getByRole("button", { name: "Save private mapping separately" })).toHaveCount(0);
});


test("time and evidence-gap results expose recorded instants and proposed GETs without performing reads", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", request => { if (!["GET", "HEAD"].includes(request.method())) writes.push(request.url()); });
  await page.goto("/engine?view=time");
  await expect(page.getByText("1 retained snapshots. A scan is not an atomic transaction; repeated observations do not prove continuous existence.")).toBeVisible();
  await page.getByText("Inspect reproducible result", { exact: true }).click();
  const timeline = JSON.parse(await page.locator(".engine-json pre").innerText());
  expect(timeline.paths[0].collectedInstants).toEqual([new Date(cleanProjectFixture.scannedAt).toISOString()]);
  await page.goto("/engine?view=gaps");
  await page.getByLabel("Question type").selectOption("membership");
  await page.getByLabel("Principal", { exact: true }).selectOption(owner);
  await page.getByLabel("Resource or group").selectOption(group);
  await page.getByRole("button", { name: "Evaluate recorded evidence" }).click();
  await expect(page.getByText("GET /groups/{group-id}/members", { exact: true })).toBeVisible();
  await expect(page.getByText("Permission availability is unverified; these proposals do not change consent.")).toBeVisible();
  await page.getByText("Inspect reproducible result", { exact: true }).click();
  const proposed = JSON.parse(await page.locator(".engine-json pre").innerText());
  expect(proposed.plans[0].mayResolve).toEqual(["coverage:groupMemberships"]);
  expect(proposed.plans[0].requiredScopes).toEqual(["Directory.Read.All"]);
  expect(writes).toEqual([]);
});
