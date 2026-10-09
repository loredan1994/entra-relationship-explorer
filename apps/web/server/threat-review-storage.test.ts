import { expect, it } from "vitest";
import { restoreBrowserReviews } from "../components/threat-review-storage";

const valid = { disposition: "mitigating", owner: "Application team", assumption: "Validate this path", expiresAt: "2026-10-30", flowDraft: [{ id: "step-1", title: "An analyst narrative", evidenceEdgeId: null }] };

it("restores an authored draft exactly without treating browser text as additional fields", () => {
  const result = restoreBrowserReviews(JSON.stringify({ finding: { ...valid, unexpected: "ignored" }, other: valid }), ["finding"]);
  expect(result).toEqual({ records: { finding: valid }, discarded: false });
});

it("restores old decisions without a flow and permits an empty narrative while it is being edited", () => {
  const { flowDraft: _, ...legacy } = valid;
  expect(restoreBrowserReviews(JSON.stringify({ finding: legacy }), ["finding"]).records.finding).toEqual({ ...legacy, flowDraft: [] });
  expect(restoreBrowserReviews(JSON.stringify({ finding: { ...valid, flowDraft: [{ id: "new-step", title: "", evidenceEdgeId: null }] } }), ["finding"]).records.finding?.flowDraft[0]?.title).toBe("");
});

it.each(["{", "null", "[]", "1", '"unexpected"'])("rejects the malformed stored document %s without throwing", source => {
  expect(restoreBrowserReviews(source, ["finding"])).toEqual({ records: {}, discarded: true });
});

it.each([
  null, [], { ...valid, owner: 17 }, { ...valid, disposition: ["open"] }, { ...valid, disposition: "unrecognized" },
  { ...valid, owner: "x".repeat(161) }, { ...valid, assumption: "x".repeat(4001) },
  { ...valid, expiresAt: "2026-02-30" }, { ...valid, expiresAt: "2026-10" },
  { ...valid, flowDraft: null }, { ...valid, flowDraft: [null] },
  { ...valid, flowDraft: [...valid.flowDraft, ...valid.flowDraft] },
  { ...valid, flowDraft: [{ id: "", title: "Step", evidenceEdgeId: null }] },
  { ...valid, flowDraft: [{ id: "step", title: "x".repeat(501), evidenceEdgeId: null }] },
  { ...valid, flowDraft: [{ id: "step", title: "Step", evidenceEdgeId: {} }] },
  { ...valid, flowDraft: [{ id: "step", title: "Step", evidenceEdgeId: " " }] },
  { ...valid, flowDraft: Array.from({ length: 21 }, (_, id) => ({ id: String(id), title: "Step", evidenceEdgeId: null })) },
])("keeps valid neighboring reviews when one stored draft is malformed (%#)", invalid => {
  const result = restoreBrowserReviews(JSON.stringify({ invalid, valid }), ["invalid", "valid"]);
  expect(result).toEqual({ records: { valid }, discarded: true });
});

it("does not report missing storage as corruption", () => {
  expect(restoreBrowserReviews(null, ["finding"])).toEqual({ records: {}, discarded: false });
});
