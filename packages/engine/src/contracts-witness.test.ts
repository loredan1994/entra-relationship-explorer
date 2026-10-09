import { expect, it } from "vitest";
import { evaluateContract, type AccessContract } from "./contracts";
import { compileSnapshot } from "./model";
import { edge, query, snapshot } from "./test-support";

const control: AccessContract = { version: 1, tenantId: query.tenantId, id: "no-control", kind: "no-control-path", sourceIds: ["person"], resourceIds: ["resource"] };
function alternatives() {
  return snapshot([
    edge("a-short-owner", "person", "client", "OWNS"),
    edge("z-long-owner", "person", "blueprint", "OWNS"),
    edge("instance", "blueprint", "client", "INSTANTIATES_AS"),
    edge("grant", "client", "resource"),
  ]);
}

it.each(["partial", "endpoint", "record"])("a contract violation uses its complete witness rather than a shorter alternative missing %s", missing => {
  const source = alternatives();
  const short = source.edges[0]!;
  if (missing === "partial") short.evidence.completeness = "partial";
  if (missing === "endpoint") short.evidence.sourceEndpoint = "";
  if (missing === "record") short.evidence.sourceRecordIds = [];
  const result = evaluateContract(compileSnapshot(source), control);
  expect(result.status).toBe("fail");
  expect(result.witnesses[0]!.paths).toEqual([["z-long-owner", "instance", "grant"]]);
  expect(result.missing).toContain("relationship:a-short-owner:complete-source");
});

it("keeps the selected shortest contract witness and its derivation indices aligned", () => {
  const source = alternatives();
  source.edges[0]!.id = "z-short-owner";
  source.edges[1]!.id = "a-long-owner";
  const witness = evaluateContract(compileSnapshot(source), control).witnesses[0]!;
  expect(witness.paths).toEqual([["z-short-owner", "grant"]]);
  expect(witness.derivation.filter(step => step.id.startsWith("path:"))).toEqual([
    expect.objectContaining({ id: "path:0:step:0", inputs: ["relationship:z-short-owner"] }),
    expect.objectContaining({ id: "path:0:step:1", inputs: ["relationship:grant", "path:0:step:0"] }),
  ]);
  expect(witness.derivation.find(step => step.id === "query")!.inputs.filter(id => id.startsWith("path:"))).toEqual(["path:0:step:1"]);
});

it("does not invent a contract violation when every alternative is incomplete", () => {
  const source = alternatives();
  source.edges[0]!.evidence.completeness = "partial";
  source.edges[1]!.evidence.completeness = "partial";
  expect(evaluateContract(compileSnapshot(source), control)).toMatchObject({ status: "unknown", witnesses: [] });
});

it("an allowlist violation identifies the grant that actually resolves the forbidden permission", () => {
  const source = snapshot([edge("a-unresolved", "client", "resource"), edge("z-resolved", "client", "resource")]);
  delete source.edges[0]!.permissionIds;
  const only: AccessContract = { version: 1, tenantId: query.tenantId, id: "no-callers", kind: "only-principals", resourceId: "resource", permissionId: "read-id", allowedPrincipalIds: [] };
  const result = evaluateContract(compileSnapshot(source), only);
  expect(result.status).toBe("fail");
  expect(result.witnesses[0]!.paths).toEqual([["z-resolved"]]);
  expect(result.missing).toContain("relationship:a-unresolved:permission-ids");
});
