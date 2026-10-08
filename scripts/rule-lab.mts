import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanProjectFixture, replayRuleLabCase } from "../packages/domain/src/index.ts";

const [command, argument] = process.argv.slice(2);
const file = argument ? resolve(fileURLToPath(new URL("../", import.meta.url)), argument) : null;
if (!file || !["scaffold", "replay"].includes(command ?? "")) throw new Error("Usage: pnpm rule:lab scaffold|replay <scenario.json>");
if (command === "scaffold") {
  // Exclusive creation preserves existing contributor work.
  await writeFile(file, JSON.stringify({ schemaVersion: 1, name: "Owner control regression", fixture: "clean-project-v1", removeEdgeIds: cleanProjectFixture.edges.filter(e => ["OWNS", "FEDERATES_AS"].includes(e.type)).map(e => e.id), expectations: [{ ruleId: "ERE-IAM-001", version: 1, minimum: 0, maximum: 0 }] }, null, 2) + "\n", { flag: "wx" });
  console.log(`Created synthetic scenario: ${file}`);
} else {
  const source = await readFile(file, "utf8");
  if (Buffer.byteLength(source, "utf8") > 100_000) throw new Error("Scenario exceeds 100 KB.");
  const result = replayRuleLabCase(JSON.parse(source));
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) process.exitCode = 1;
}
