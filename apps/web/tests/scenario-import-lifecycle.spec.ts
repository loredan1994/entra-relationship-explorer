import { cleanProjectFixture, createScenarioPlan, SCENARIO_EDGE_TYPES } from "@entra-explorer/domain";
import { expect, test, type Page } from "@playwright/test";

const eligible = cleanProjectFixture.edges.filter(edge => edge.evidence.configured && (SCENARIO_EDGE_TYPES as readonly string[]).includes(edge.type));
const [older, newer] = eligible;
const upload = (ids: string[], name = "current-review.json") => ({ name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(createScenarioPlan(cleanProjectFixture, ids))) });
const choice = (page: Page, id: string) => page.locator(".scenario-choices label").filter({ hasText: id }).getByRole("checkbox");

async function openWithDelayedFile(page: Page) {
  await page.addInitScript(() => {
    const original = File.prototype.text;
    File.prototype.text = async function () {
      const target = window as unknown as { releaseScenarioFile: () => void; scenarioReadFinished: boolean };
      if (this.name !== "slow-review.json") return original.call(this);
      target.scenarioReadFinished = false;
      await new Promise<void>(resolve => { target.releaseScenarioFile = resolve; });
      try { return await original.call(this); }
      finally { target.scenarioReadFinished = true; }
    };
  });
  await page.goto("/investigations?view=scenarios");
}
async function releaseFile(page: Page) {
  await page.evaluate(async () => {
    const target = window as unknown as { releaseScenarioFile: () => void; scenarioReadFinished: boolean };
    target.releaseScenarioFile();
    while (!target.scenarioReadFinished) await new Promise(resolve => setTimeout(resolve, 0));
    await new Promise(requestAnimationFrame);
  });
}

test("the last chosen scenario import wins when an older file finishes reading later", async ({ page }) => {
  await openWithDelayedFile(page);
  const input = page.getByLabel("Import review plan");
  await input.setInputFiles(upload([older!.id], "slow-review.json"));
  await input.setInputFiles(upload([newer!.id]));
  await expect(choice(page, newer!.id)).toBeChecked();
  await releaseFile(page);
  await expect(choice(page, newer!.id)).toBeChecked();
  await expect(choice(page, older!.id)).not.toBeChecked();
});

test("Reset cancels an in-flight scenario import and clears obsolete import feedback", async ({ page }) => {
  await openWithDelayedFile(page);
  const input = page.getByLabel("Import review plan");
  await input.setInputFiles(upload([newer!.id]));
  await expect(page.locator(".investigation-card").getByRole("status")).toContainText("Imported 1 exclusions");
  await input.setInputFiles(upload([older!.id], "slow-review.json"));
  await page.getByRole("button", { name: "Reset scenario", exact: true }).click();
  await releaseFile(page);
  await expect(page.locator(".scenario-choices input:checked")).toHaveCount(0);
  await expect(page.locator(".investigation-card").getByRole("status")).toHaveCount(0);
});

test("a stale failed import cannot replace a newer manual scenario edit with an error", async ({ page }) => {
  await openWithDelayedFile(page);
  await page.getByLabel("Import review plan").setInputFiles({ name: "slow-review.json", mimeType: "application/json", buffer: Buffer.from("{") });
  await choice(page, newer!.id).check();
  await releaseFile(page);
  await expect(choice(page, newer!.id)).toBeChecked();
  await expect(page.locator(".investigation-card").getByRole("status")).toHaveCount(0);
});

test("choosing a ranked candidate supersedes a pending imported scenario", async ({ page }) => {
  await openWithDelayedFile(page);
  await page.getByRole("button", { name: "Rank candidate changes", exact: true }).click();
  const candidate = page.getByRole("heading", { name: "Candidate changes", exact: true }).locator("..").getByRole("button").first();
  await candidate.click();
  const candidateId = await page.locator(".scenario-choices label").filter({ has: page.locator("input:checked") }).locator("code").innerText();
  const different = eligible.find(edge => edge.id !== candidateId)!;
  await page.getByLabel("Import review plan").setInputFiles(upload([different.id], "slow-review.json"));
  await candidate.click();
  await releaseFile(page);
  await expect(choice(page, candidateId)).toBeChecked();
  await expect(choice(page, different.id)).not.toBeChecked();
  await expect(page.locator(".investigation-card").getByRole("status")).toHaveCount(0);
});

test("a successful import message is removed when its exclusions are edited", async ({ page }) => {
  await page.goto("/investigations?view=scenarios");
  await page.getByLabel("Import review plan").setInputFiles(upload([older!.id]));
  await expect(page.locator(".investigation-card").getByRole("status")).toContainText("Imported 1 exclusions");
  await choice(page, newer!.id).check();
  await expect(page.locator(".scenario-choices input:checked")).toHaveCount(2);
  await expect(page.locator(".investigation-card").getByRole("status")).toHaveCount(0);
});
