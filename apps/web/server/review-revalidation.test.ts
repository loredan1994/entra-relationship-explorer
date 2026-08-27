import { describe, expect, it } from "vitest";
import { revalidateThreatReview } from "./review-revalidation";

const prior = (disposition: "open" | "mitigating" | "accepted" | "resolved", expiresAt: string | null = null) => ({
  findingId: "finding-1", snapshotId: "snap-prior", tenantId: "11111111-1111-4111-8111-111111111111",
  disposition, owner: "IAM", expiresAt, assumption: "Reviewed evidence", flowDraft: [], updatedAt: "2026-08-01T00:00:00.000Z",
});
const now = new Date("2026-08-27T12:00:00.000Z");

describe("review revalidation", () => {
  it("copies an active decision into the new snapshot only when invoked", () => {
    expect(revalidateThreatReview(prior("mitigating"), "snap-current", now)).toMatchObject({ snapshotId: "snap-current", disposition: "mitigating", owner: "IAM", updatedAt: now.toISOString() });
  });

  it("reopens a finding that had been marked resolved", () => {
    expect(revalidateThreatReview(prior("resolved"), "snap-current", now).disposition).toBe("open");
  });

  it("does not extend an expired or undated acceptance", () => {
    expect(revalidateThreatReview(prior("accepted", "2026-08-26"), "snap-current", now)).toMatchObject({ disposition: "open", expiresAt: null });
    expect(revalidateThreatReview(prior("accepted"), "snap-current", now)).toMatchObject({ disposition: "open", expiresAt: null });
  });

  it("preserves an acceptance that still has a future review date", () => {
    expect(revalidateThreatReview(prior("accepted", "2026-08-28"), "snap-current", now)).toMatchObject({ disposition: "accepted", expiresAt: "2026-08-28" });
  });

  it("treats an acceptance as active through its stated expiry date", () => {
    expect(revalidateThreatReview(prior("accepted", "2026-08-27"), "snap-current", now)).toMatchObject({ disposition: "accepted", expiresAt: "2026-08-27" });
  });
});
