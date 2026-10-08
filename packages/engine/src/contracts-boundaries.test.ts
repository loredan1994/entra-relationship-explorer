import { expect, it } from "vitest";
import { compileSnapshot, compareContract, evaluateContract, parseContract, type AccessContract } from "./index";
import { edge, node, query, snapshot } from "./test-support";
const only: AccessContract = { version: 1, id: "only", tenantId: query.tenantId, kind: "only-principals", allowedPrincipalIds: [], permissionId: "read-id", resourceId: "resource" };
const control: AccessContract = { version: 1, id: "no-control", tenantId: query.tenantId, kind: "no-control-path", sourceIds: ["person"], resourceIds: ["resource"] };
it.each([null, [], true, false, 12, "contract"])("rejects non-object contract %j with a schema error", value => {
  expect(() => parseContract(JSON.stringify(value))).toThrow("Contract must be an object.");
});
it.each(["tenantId", "id", "resourceId", "permissionId"])("validates required scalar %s at the 500-character boundary", key => {
  for (const value of [null, 3, false, [], "", "x".repeat(501)]) expect(() => parseContract(JSON.stringify({ ...only, [key]: value }))).toThrow("Invalid contract identifier.");
  expect(parseContract(JSON.stringify({ ...only, [key]: "x".repeat(500) }))).toHaveProperty(key, "x".repeat(500));
  const missing: Record<string, unknown> = { ...only }; delete missing[key];
  expect(() => parseContract(JSON.stringify(missing))).toThrow("Unknown or missing contract fields.");
});
it.each([null, "person", {}, [null], [""], ["valid", 5], ["a", "a"], ["x".repeat(501)]])("rejects an invalid selector list %j", list => {
  expect(() => parseContract(JSON.stringify({ ...only, allowedPrincipalIds: list }))).toThrow("Invalid contract ID list.");
});
it("accepts empty allowlists and exact list limits but requires control query targets", () => {
  expect(parseContract(JSON.stringify(only))).toEqual(only);
  for (const key of ["sourceIds", "resourceIds"]) expect(() => parseContract(JSON.stringify({ ...control, [key]: [] }))).toThrow("Contract requires targets.");
  const ids = Array.from({ length: 100 }, (_, i) => `id-${i}`);
  expect(parseContract(JSON.stringify({ ...only, allowedPrincipalIds: ids }))).toMatchObject({ allowedPrincipalIds: ids });
  expect(parseContract(JSON.stringify({ ...only, allowedPrincipalIds: ["x".repeat(500)] }))).toMatchObject({ allowedPrincipalIds: ["x".repeat(500)] });
  expect(() => parseContract(JSON.stringify({ ...only, allowedPrincipalIds: [...ids, "one-more"] }))).toThrow("Invalid contract ID list.");
  for (const kind of [3, "constructor", "future"]) expect(() => parseContract(JSON.stringify({ ...only, kind }))).toThrow("Unsupported contract schema.");
});
it("enforces UTF-8 byte size including valid JSON whitespace at exactly 100 KB", () => {
  const json = JSON.stringify({ ...only, id: "é" });
  const exact = json + " ".repeat(100_000 - new TextEncoder().encode(json).length);
  expect(parseContract(exact).id).toBe("é");
  expect(() => parseContract(exact + " ")).toThrow("Contract exceeds 100 KB.");
});
it("checks only unapproved application grants to the selected resource", () => {
  const s = snapshot([edge("owned", "person", "resource", "OWNS"), edge("other-resource", "client", "blueprint"), edge("delegated", "other", "resource", "CAN_CALL_DELEGATED")]);
  expect(evaluateContract(compileSnapshot(s), only)).toMatchObject({ status: "pass", queries: 0, witnesses: [], missing: [], verdict: "supported" });
  s.edges.push(edge("allowed", "client", "resource"));
  expect(evaluateContract(compileSnapshot(s), { ...only, allowedPrincipalIds: ["client"] }).queries).toBe(0);
});
it("never passes a contract by selecting the allowed variant of a conflicting record", () => {
  const s = snapshot(); s.nodes.push(node("z-rogue"));
  s.edges.push({ ...s.edges[0]!, sourceId: "z-rogue" });
  const result = evaluateContract(compileSnapshot(s), { ...only, allowedPrincipalIds: ["client"] });
  expect(result.status).toBe("unknown"); expect(result.verdict).toBe("unknown"); expect(result.missing).toContain("relationship:grant");
});
it("a no-control contract needs owner inventory and both target identities", () => {
  const s = snapshot([]); s.completion.collectors!.find(c => c.id === "owners")!.state = "denied";
  expect(evaluateContract(compileSnapshot(s), control)).toMatchObject({ status: "unknown", missing: ["coverage:owners"] });
  s.completion.collectors!.find(c => c.id === "owners")!.state = "complete";
  s.nodes = s.nodes.filter(n => n.id !== "person" && n.id !== "resource");
  expect(evaluateContract(compileSnapshot(s), control).missing).toEqual(["object:person", "object:resource"]);
});
it("returns one shortest witness with deterministic tie ordering", () => {
  const s = snapshot([edge("z-direct", "person", "client", "OWNS"), edge("a-direct", "person", "client", "OWNS"), edge("long", "person", "blueprint", "OWNS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"), edge("grant", "client", "resource")]);
  const result = evaluateContract(compileSnapshot(s), control);
  expect(result.status).toBe("fail"); expect(result.witnesses[0]!.paths).toEqual([["a-direct", "grant"]]);
});
it("limits total contract traversal, reports unfinished queries and never overruns its budget", () => {
  const s = snapshot([edge("a", "client", "resource"), edge("b", "client", "resource")]);
  const required: AccessContract = { version: 1, id: "required", tenantId: query.tenantId, kind: "require-grant", principalId: "client", resourceId: "resource", permissionId: "read-id" };
  const m = compileSnapshot(s);
  expect(evaluateContract(m, required, 1)).toMatchObject({ status: "unknown", queries: 0, missing: ["budget:contract"], limits: { steps: 0, maxSteps: 1, exhausted: true } });
  expect(evaluateContract(m, required, 2)).toMatchObject({ status: "unknown", queries: 1, missing: ["budget:contract", "budget:search"], limits: { steps: 2, maxSteps: 2, exhausted: true } });
  expect(evaluateContract(m, required, 3)).toMatchObject({ status: "pass", queries: 1, missing: [], limits: { steps: 3, maxSteps: 3, exhausted: false } });
  const partial = compareContract(m, m, required, 2); expect(partial.complete).toBe(false); expect(partial.addedPaths).toEqual([]); expect(partial.removedPaths).toEqual([]);
  for (const value of [0, 250_001]) expect(() => evaluateContract(m, required, value)).toThrow("Invalid contract steps budget.");
  const chain = { ...control, sourceIds: ["person", "other"] }; const limits = evaluateContract(m, chain, 2).limits;
  expect(limits).toEqual({ steps: 1, maxSteps: 2, exhausted: true });
});
it("reports semantic removals, incomplete comparisons and cross-tenant rejection", () => {
  const before = compileSnapshot(snapshot()), after = compileSnapshot(snapshot([]));
  const diff = compareContract(before, after, only);
  expect(diff.addedPaths).toEqual([]); expect(diff.removedPaths).toEqual(['[{"permissionIds":["read-id"],"sourceId":"client","targetId":"resource","type":"CAN_CALL_AS_APP"}]']); expect(diff.complete).toBe(true);
  const partial = snapshot(); partial.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = "denied";
  expect(compareContract(compileSnapshot(partial), after, only).complete).toBe(false);
  expect(compareContract(before, compileSnapshot(partial), only).complete).toBe(false);
  const foreign = { ...after, tenantId: "different" };
  expect(() => compareContract(before, foreign, { ...only, tenantId: "different" })).toThrow("Cross-tenant");
});
