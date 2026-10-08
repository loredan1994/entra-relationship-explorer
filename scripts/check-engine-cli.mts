import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { query, snapshot } from "../packages/engine/src/test-support.ts";

const workspace = fileURLToPath(new URL("../apps/web/", import.meta.url));
const require = createRequire(new URL("../apps/web/package.json", import.meta.url));
const script = fileURLToPath(new URL("./engine.mts", import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "entra-engine-cli-synthetic-"));
let checks = 0;
async function save(name: string, value: unknown) { const path = join(directory, name); await writeFile(path, JSON.stringify(value), { mode: 0o600 }); return path; }
function run(expected: number, ...args: string[]) {
  const result = spawnSync(process.execPath, ["--import", require.resolve("tsx"), script, ...args], { cwd: workspace, encoding: "utf8", timeout: 15_000 });
  assert.equal(result.status, expected, result.stderr); assert.equal(result.error, undefined); checks++;
  return result;
}
try {
  const present = await save("snapshot.json", snapshot()); const absent = await save("absent.json", snapshot([]));
  const incomplete = snapshot([]); incomplete.completion.collectors = [];
  const unknown = await save("unknown.json", incomplete); const q = await save("query.json", query);
  assert.equal(JSON.parse(run(0, "proof", present, q).stdout).verdict, "supported");
  assert.equal(JSON.parse(run(1, "proof", absent, q).stdout).verdict, "refuted");
  assert.equal(JSON.parse(run(2, "proof", unknown, q).stdout).verdict, "unknown");
  const contract = await save("contract.json", { version: 1, tenantId: query.tenantId, id: "required", kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" });
  assert.equal(JSON.parse(run(0, "contract", present, contract).stdout).status, "pass");
  assert.equal(JSON.parse(run(1, "contract", absent, contract).stdout).status, "fail");
  assert.equal(JSON.parse(run(2, "contract", unknown, contract).stdout).status, "unknown");
  const comparison = JSON.parse(run(0, "compare", present, absent, contract).stdout);
  assert.equal(comparison.complete, true); assert.equal(comparison.removedPaths.length, 1);
  const output = join(directory, "investigation.json"); run(0, "export", present, q, output);
  const packet = await readFile(output, "utf8"); assert.ok(!packet.includes("synthetic-tenant")); assert.ok(!packet.includes("privateMapping"));
  if (process.platform !== "win32") assert.equal((await stat(output)).mode & 0o777, 0o600);
  assert.equal(JSON.parse(run(0, "verify", output).stdout).verified, true);
  run(2, "export", present, q, output); assert.equal(await readFile(output, "utf8"), packet);
  if (process.platform !== "win32") { const link = join(directory, "link.json"); await symlink(output, link); run(2, "export", present, q, link); assert.equal(await readFile(output, "utf8"), packet); }
  await writeFile(output, packet.replace('"digest":"', '"digest":"0'));
  assert.match(run(2, "verify", output).stderr, /integrity check failed/);
  const invalid = join(directory, "invalid.json"); await writeFile(invalid, '{"sensitive-marker":"never-print-me"');
  const failure = run(2, "proof", invalid, q); assert.equal(failure.stderr.trim(), "Invalid JSON input."); assert.equal(failure.stdout, "");
  assert.match(run(2, "proof").stderr, /required file argument/);
  assert.match(run(2, "not-a-command").stderr, /^Usage:/);
  process.stdout.write(JSON.stringify({ checks, offline: true, fixtures: "synthetic", temporaryFilesRemoved: true }) + "\n");
} finally { await rm(directory, { recursive: true, force: true }); }
