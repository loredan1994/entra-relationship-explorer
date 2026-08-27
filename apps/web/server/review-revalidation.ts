import type { ThreatReview } from "@entra-explorer/backend";

/** Build a new snapshot-scoped decision without silently extending stale assurance. */
export function revalidateThreatReview(prior: ThreatReview, currentSnapshotId: string, now = new Date()): ThreatReview {
  const acceptanceExpired = prior.disposition === "accepted" && (!prior.expiresAt || prior.expiresAt < now.toISOString().slice(0, 10));
  const mustReopen = prior.disposition === "resolved" || acceptanceExpired;
  return {
    ...prior,
    snapshotId: currentSnapshotId,
    disposition: mustReopen ? "open" : prior.disposition,
    expiresAt: acceptanceExpired ? null : prior.expiresAt,
    updatedAt: now.toISOString(),
  };
}
