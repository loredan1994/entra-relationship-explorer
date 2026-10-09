import { THREAT_REVIEW_LIMITS } from "../lib/threat-review-limits";

export type Disposition = "open" | "mitigating" | "accepted" | "resolved";
export interface FlowDraftStep { id: string; title: string; evidenceEdgeId: string | null; }
export interface ReviewRecord { disposition: Disposition; owner: string; expiresAt: string; assumption: string; flowDraft: FlowDraftStep[]; }

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function boundedText(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length <= limit;
}
function reviewRecord(value: unknown): ReviewRecord | null {
  if (!object(value) || typeof value.disposition !== "string" || !["open", "mitigating", "accepted", "resolved"].includes(value.disposition)) return null;
  if (!boundedText(value.owner, THREAT_REVIEW_LIMITS.owner) || !boundedText(value.assumption, THREAT_REVIEW_LIMITS.assumption)) return null;
  if (typeof value.expiresAt !== "string" || (value.expiresAt !== "" && (!/^\d{4}-\d{2}-\d{2}$/.test(value.expiresAt) || !Number.isFinite(Date.parse(value.expiresAt)) || new Date(value.expiresAt).toISOString().slice(0, 10) !== value.expiresAt))) return null;
  const candidates = value.flowDraft === undefined ? [] : value.flowDraft;
  if (!Array.isArray(candidates) || candidates.length > THREAT_REVIEW_LIMITS.flowDraft) return null;
  const flowDraft: FlowDraftStep[] = [];
  const ids = new Set<string>();
  for (const step of candidates) {
    if (!object(step) || !boundedText(step.id, THREAT_REVIEW_LIMITS.id) || !step.id.trim() || ids.has(step.id) || !boundedText(step.title, THREAT_REVIEW_LIMITS.title)) return null;
    if (step.evidenceEdgeId !== null && (!boundedText(step.evidenceEdgeId, THREAT_REVIEW_LIMITS.evidenceEdgeId) || !step.evidenceEdgeId.trim())) return null;
    ids.add(step.id);
    flowDraft.push({ id: step.id, title: step.title, evidenceEdgeId: step.evidenceEdgeId });
  }
  return { disposition: value.disposition as Disposition, owner: value.owner, expiresAt: value.expiresAt, assumption: value.assumption, flowDraft };
}

/** Recover valid browser drafts independently; storage is untrusted and may contain an older schema. */
export function restoreBrowserReviews(source: string | null, findingIds: readonly string[]): { records: Record<string, ReviewRecord>; discarded: boolean } {
  if (source === null) return { records: {}, discarded: false };
  let parsed: unknown;
  try { parsed = JSON.parse(source); } catch { return { records: {}, discarded: true }; }
  if (!object(parsed)) return { records: {}, discarded: true };
  const records: Record<string, ReviewRecord> = {};
  let discarded = false;
  for (const id of findingIds) {
    if (!Object.hasOwn(parsed, id)) continue;
    const record = reviewRecord(parsed[id]);
    if (record) records[id] = record;
    else discarded = true;
  }
  return { records, discarded };
}
