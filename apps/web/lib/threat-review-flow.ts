import type { AttackStep } from "@entra-explorer/domain";
import { THREAT_REVIEW_LIMITS } from "./threat-review-limits";

// Only newly generated summaries are shortened. Existing analyst text is never rewritten.
export function createThreatFlowDraft(steps: Pick<AttackStep, "edgeId" | "explanation">[]) {
  return steps.map(item => ({
    id: item.edgeId,
    title: item.explanation.length <= THREAT_REVIEW_LIMITS.title
      ? item.explanation
      : `${item.explanation.slice(0, THREAT_REVIEW_LIMITS.title - 1).replace(/[\uD800-\uDBFF]$/u, "")}…`,
    evidenceEdgeId: item.edgeId,
  }));
}
