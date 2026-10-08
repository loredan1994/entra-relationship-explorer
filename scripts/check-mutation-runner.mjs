import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Exercise the installed runner end-to-end. A deliberately weak test must leave
// one arithmetic mutant alive, while nested boundary assertions must kill theirs.
// This fixture is separate from the production mutation suite and its 95% gate.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const modules = join(root, "packages/domain/node_modules");
const runner = join(await realpath(join(modules, "@stryker-mutator/core")), "bin/stryker.js");
const directory = await mkdtemp(join(tmpdir(), "entra-mutation-canary-"));
try {
  await mkdir(join(directory, "src"));
  await mkdir(join(directory, "test"));
  await symlink(modules, join(directory, "node_modules"), "dir");
  await writeFile(join(directory, "package.json"), JSON.stringify({ private: true, type: "module" }));
  await writeFile(join(directory, "vitest.config.mjs"), "export default { test: { environment: 'node' } };\n");
  await writeFile(join(directory, "src/policy.ts"), `
export function add(a: number, b: number): number { return a + b; }
export function allowed(value: number): boolean { return value <= 3; }
`);
  await writeFile(join(directory, "test/policy.test.ts"), `
import { describe, expect, it } from 'vitest';
import { add, allowed } from '../src/policy';
describe('policy [v2]', () => {
  describe('app (delegated)', () => {
    it('adds', () => { expect(add(0, 0)).toBe(0); });
    it('adds negative', () => { expect(allowed(4)).toBe(false); });
    it('checks boundary + safety', () => {
      expect(allowed(2)).toBe(true);
      expect(allowed(3)).toBe(true);
      expect(allowed(4)).toBe(false);
    });
  });
});
`);
  await writeFile(join(directory, "stryker.config.json"), JSON.stringify({
    testRunner: "vitest", coverageAnalysis: "perTest", concurrency: 1,
    mutate: ["src/policy.ts"], reporters: ["json"], incremental: false,
    thresholds: { break: null }, plugins: ["@stryker-mutator/vitest-runner"],
  }));
  const result = spawnSync(process.execPath, [runner, "run"], {
    cwd: directory, encoding: "utf8", timeout: 120_000,
    env: { ...process.env, GITHUB_STEP_SUMMARY: "" },
  });
  assert.equal(result.status, 0, `Mutation runner failed: ${result.error?.message ?? result.stderr ?? result.stdout}`);
  const report = JSON.parse(await readFile(join(directory, "reports/mutation/mutation.json"), "utf8"));
  const mutants = Object.values(report.files).flatMap(file => file.mutants);
  const weak = mutants.find(mutant => mutant.mutatorName === "ArithmeticOperator" && mutant.replacement === "a - b");
  assert.ok(weak, "The deliberate weak-test arithmetic mutation must be generated");
  assert.equal(weak.status, "Survived", "The runner must not report an untested distinction as killed");
  assert.equal(weak.testsCompleted, 1, "Select only its covering test, not a prefix-matching sibling or zero tests");
  const boundaries = mutants.filter(mutant => mutant.location.start.line === 3);
  assert.ok(boundaries.length >= 3, "The boundary fixture must generate multiple semantic mutations");
  for (const mutant of boundaries) {
    assert.equal(mutant.status, "Killed", `Nested boundary assertion must kill ${mutant.mutatorName}: ${mutant.replacement}`);
    assert.ok(mutant.killedBy?.length, "Record the actual assertion that killed each boundary mutation");
  }
  console.log(`Mutation runner compatibility passed: ${boundaries.length} boundary mutations killed; deliberate arithmetic survivor selected exactly one test.`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
