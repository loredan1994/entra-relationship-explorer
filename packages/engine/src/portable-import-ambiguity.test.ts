import { expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot, exportInvestigation, verifyInvestigation } from "./index";
import { query, snapshot } from "./test-support";

async function investigation() {
  return canonical((await exportInvestigation(compileSnapshot(snapshot()), query)).package);
}

it.each([
  ["discarded secret field", '"proof"', '{"clientSecret":"synthetic-not-a-secret"}'],
  ["discarded foreign tenant", '"query"', JSON.stringify({ ...query, tenantId: "another-synthetic-tenant" })],
  ["discarded unsupported query", '"query"', JSON.stringify({ ...query, kind: "execute-script" })],
  ["escaped property name", '"pro\\u006ff"', "null"],
  ["escaped first character", '"\\u0070roof"', "null"],
])("rejects ambiguous investigation JSON containing a %s", async (_label, key, discarded) => {
  const original = await investigation();
  const ambiguous = `{${key}:${discarded},${original.slice(1)}`;
  // The digest and native JavaScript interpretation are unchanged: verification
  // must reject the ambiguous document itself, before any overwritten value disappears.
  expect(JSON.parse(ambiguous)).toEqual(JSON.parse(original));
  await expect(verifyInvestigation(ambiguous)).rejects.toThrow("Duplicate investigation field");
});

it("rejects excessive raw nesting before a later duplicate could discard it", async () => {
  const original = await investigation();
  const ambiguous = `{"proof":${"[".repeat(80)}0${"]".repeat(80)},${original.slice(1)}`;
  expect(JSON.parse(ambiguous)).toEqual(JSON.parse(original));
  await expect(verifyInvestigation(ambiguous)).rejects.toThrow("Investigation exceeds structural limits");
});

it("retains the depth boundary for empty containers without counting strings as containers", async () => {
  await expect(verifyInvestigation("[".repeat(25) + "]".repeat(25))).rejects.toThrow("Invalid investigation document");
  await expect(verifyInvestigation("[".repeat(26) + "]".repeat(26))).rejects.toThrow("Investigation exceeds structural limits");
});

it.each([false, true])("rejects repeated nested configuration evidence even when its first value is %s", async first => {
  const original = await investigation();
  const ambiguous = original.replace('"configured":true', `"configured":${first},"configured":true`);
  expect(JSON.parse(ambiguous)).toEqual(JSON.parse(original));
  await expect(verifyInvestigation(ambiguous)).rejects.toThrow("Duplicate investigation field");
});

it("rejects escaped duplicate names inside nested proof objects", async () => {
  const original = await investigation();
  const ambiguous = original.replace('"verdict":"supported"', '"verdict":"refuted","ver\\u0064ict" \n\t: "supported"');
  expect(JSON.parse(ambiguous)).toEqual(JSON.parse(original));
  await expect(verifyInvestigation(ambiguous)).rejects.toThrow("Duplicate investigation field");
});

it("preserves separate object scopes, insignificant whitespace and key-like text inside evidence strings", async () => {
  const source = snapshot();
  source.edges[0]!.evidence.sourceRecordIds = ['{"proof":0,"proof":1}', '[{]:\\"escaped"', "braces{[and]}slash\\"];
  const packet = (await exportInvestigation(compileSnapshot(source), query)).package;
  const text = JSON.stringify(packet, null, "\t");
  const result = await verifyInvestigation(text);
  expect(result.proof.verdict).toBe("supported");
  expect(result.proof.facts.find(fact => fact.id === "relationship:grant")?.sourceRecordIds).toEqual([
    "[{]:\\\"escaped\"", "braces{[and]}slash\\", '{"proof":0,"proof":1}',
  ]);
});

it.each(['{"a":"unterminated}', '{"a":"trailing\\', '{"a":1,}', '{"a" 1}', '{"a":"invalid\\q"}', '"value":0'])("keeps rejecting invalid JSON syntax: %s", async text => {
    await expect(verifyInvestigation(text)).rejects.toThrow();
  });
