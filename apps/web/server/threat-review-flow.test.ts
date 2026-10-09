import { describe, expect, it } from "vitest";
import { createThreatFlowDraft } from "../lib/threat-review-flow";

describe("generated threat review summaries", () => {
  it("keeps an explanation at the exact UI/API boundary and retains its evidence reference", () => {
    const explanation = "a".repeat(500);
    expect(createThreatFlowDraft([{ edgeId: "edge-1", explanation }])).toEqual([{ id: "edge-1", title: explanation, evidenceEdgeId: "edge-1" }]);
  });
  it("starts long-label explanations with a bounded visible summary without mutating source evidence", () => {
    const source = "Source ".padEnd(250, "s"), target = "Target ".padEnd(250, "t");
    const step = { edgeId: "edge-1", explanation: `${source} can control ${target}.` };
    const before = structuredClone(step);
    const [draft] = createThreatFlowDraft([step]);
    expect(draft!.title).toBe(`${step.explanation.slice(0, 499)}…`);
    expect(draft!.title.length).toBe(500);
    expect(draft!.evidenceEdgeId).toBe(step.edgeId);
    expect(step).toEqual(before);
  });
  it("does not split a surrogate pair at the generated summary boundary", () => {
    const [draft] = createThreatFlowDraft([{ edgeId: "edge-1", explanation: `${"a".repeat(498)}😀 end` }]);
    expect(draft!.title).toBe(`${"a".repeat(498)}…`);
    expect(draft!.title.length).toBeLessThanOrEqual(500);
  });
});
