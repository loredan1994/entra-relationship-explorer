import { expect, it } from "vitest";
import { EMPTY_REVIEW, mergeBrowserReviewDrafts } from "../components/threat-review-storage";

it("preserves other findings and merges independently edited fields on the same decision", () => {
  const saved = { first: { ...EMPTY_REVIEW, assumption: "Keep the other tab's rationale" }, second: { ...EMPTY_REVIEW, owner: "Another application team" } };
  const result = mergeBrowserReviewDrafts(saved, { first: { original: EMPTY_REVIEW, changes: { owner: "My application team" } } });
  expect(result).toEqual({ records: { first: { ...saved.first, owner: "My application team" }, second: saved.second }, conflicts: [] });
  expect(saved.first.owner).toBe("");
});

it("refuses a stale same-field replacement without blocking an independent finding", () => {
  const first = { ...EMPTY_REVIEW, owner: "Newer reviewer" };
  expect(mergeBrowserReviewDrafts({ first }, {
    first: { original: EMPTY_REVIEW, changes: { owner: "Stale reviewer" } },
    second: { original: EMPTY_REVIEW, changes: { assumption: "An independent decision" } },
  })).toEqual({ records: { first, second: { ...EMPTY_REVIEW, assumption: "An independent decision" } }, conflicts: ["first"] });
});

it("accepts the same already-saved value when recovering a possibly completed write", () => {
  const first = { ...EMPTY_REVIEW, owner: "Agreed owner" };
  expect(mergeBrowserReviewDrafts({ first }, { first: { original: EMPTY_REVIEW, changes: { owner: "Agreed owner" } } })).toEqual({ records: { first }, conflicts: [] });
});

it("treats a removed saved decision and changed flow narratives as conflicts", () => {
  const original = { ...EMPTY_REVIEW, owner: "Previous owner", flowDraft: [{ id: "step", title: "Original step", evidenceEdgeId: null }] };
  expect(mergeBrowserReviewDrafts({}, { first: { original, changes: { owner: "New local owner" } } }).conflicts).toEqual(["first"]);
  const current = { ...original, flowDraft: [{ id: "step", title: "New saved narrative", evidenceEdgeId: null }] };
  expect(mergeBrowserReviewDrafts({ first: current }, { first: { original, changes: { flowDraft: [] } } })).toEqual({ records: { first: current }, conflicts: ["first"] });
});
