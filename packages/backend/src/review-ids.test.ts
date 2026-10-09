import { expect, it } from "vitest";
import { canonicalReviewIds } from "./review-ids";

it("canonicalizes repeated IDs without changing exact identifiers or caller order", () => {
  const ids = Object.freeze(["", "finding-b", "finding-a", "finding-b", " finding-a", ""]);
  expect(canonicalReviewIds(ids)).toEqual(["finding-b", "finding-a", " finding-a"]);
  expect(canonicalReviewIds([])).toEqual([]);
});

it("accepts exactly 10,000 distinct findings and rejects overflow rather than dropping decisions", () => {
  const ids = Array.from({ length: 10_000 }, (_, i) => `finding-${i}`);
  expect(canonicalReviewIds([...ids, ...ids, ""])).toEqual(ids);
  expect(() => canonicalReviewIds([...ids, "overflow"])).toThrow("A review read supports at most 10,000 distinct finding IDs.");
});
