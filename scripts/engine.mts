import { readFile, writeFile, stat } from "node:fs/promises";
import { compileSnapshot, evaluateAuthorization, evaluateContract, compareContract, parseContract, exportInvestigation, verifyInvestigation, canonical, type AuthorizationQuery } from "../packages/engine/src/index.ts";
import type { TenantSnapshot } from "../packages/domain/src/types.ts";

async function textFile(path: string | undefined, limit = 10_000_000): Promise<string> {
  if (!path) throw new Error("A required file argument is missing.");
  if ((await stat(path)).size > limit) throw new Error("Input file exceeds its size limit.");
  return readFile(path, "utf8");
}
const [command, first, second, third] = process.argv.slice(2);
try {
  let result: unknown;
  if (command === "verify") {
    result = await verifyInvestigation(await textFile(first, 5_000_000));
  } else if (["proof", "contract", "export", "compare"].includes(command ?? "")) {
    const model = compileSnapshot(JSON.parse(await textFile(first)) as TenantSnapshot);
    if (command === "contract") {
      const report = evaluateContract(model, parseContract(await textFile(second, 100_000)));
      result = report; process.exitCode = report.status === "pass" ? 0 : report.status === "fail" ? 1 : 2;
    } else if (command === "compare") {
      const after = compileSnapshot(JSON.parse(await textFile(second)) as TenantSnapshot);
      result = compareContract(model, after, parseContract(await textFile(third, 100_000)));
    } else {
      const query = JSON.parse(await textFile(second, 100_000)) as AuthorizationQuery;
      if (command === "export") {
        if (!third) throw new Error("Supply a new output filename. Existing files are never overwritten.");
        const packet = await exportInvestigation(model, query, "pseudonymized");
        await writeFile(third, `${canonical(packet.package)}\n`, { flag: "wx", mode: 0o600 });
        result = { written: third, sharing: "pseudonymized", notice: "Sensitive topology remains. The private mapping was not saved. Run verify to replay offline." };
      } else {
        const proof = evaluateAuthorization(model, query); result = proof;
        process.exitCode = proof.verdict === "supported" ? 0 : proof.verdict === "refuted" ? 1 : 2;
      }
    }
  } else throw new Error("Usage: pnpm engine proof SNAPSHOT QUERY | contract SNAPSHOT CONTRACT | compare BEFORE AFTER CONTRACT | export SNAPSHOT QUERY NEW_OUTPUT | verify PACKAGE");
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  // Inputs may contain tenant facts. Do not print a raw parser exception or stack.
  const message = error instanceof SyntaxError ? "Invalid JSON input." : error instanceof Error ? error.message : "Engine command failed.";
  process.stderr.write(`${message}\n`); process.exitCode = 2;
}
