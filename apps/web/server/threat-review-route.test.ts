import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const getServerSession = vi.fn();
const recentSnapshots = vi.fn();
const getThreatReview = vi.fn();
const priorThreatReviews = vi.fn();
const upsertThreatReview = vi.fn();
const recordAccess = vi.fn();

vi.mock("./config", () => ({ getEntraConfig: () => ({ enabled: true, tenantId: cleanProjectFixture.tenant.tenantId, redirectUri: "http://127.0.0.1:3200/api/auth/callback" }) }));
vi.mock("./backend", () => ({ getBackend: async () => ({ recentSnapshots, getThreatReview, priorThreatReviews, upsertThreatReview, recordAccess }) }));
vi.mock("./auth/session-store", () => ({ SESSION_COOKIE: "entra_explorer_session", getServerSession: (...args: unknown[]) => getServerSession(...args) }));

const route = await import("../app/api/v1/threat-reviews/[id]/route");
const snapshot = { ...cleanProjectFixture, mode: "tenant" as const };
const findingId = analyzeTenantIntelligence(snapshot).findings[0]!.id;
const session = { id: "session-1", tenantId: snapshot.tenant.tenantId };
const prior = { findingId, snapshotId: "snap-prior", tenantId: snapshot.tenant.tenantId, disposition: "resolved" as const, owner: "IAM", expiresAt: null, assumption: "Removed by approved change", flowDraft: [], updatedAt: "2026-08-26T00:00:00.000Z" };

function request(body: unknown, origin = "http://127.0.0.1:3200") {
  return new NextRequest(`http://127.0.0.1:3200/api/v1/threat-reviews/${findingId}?snapshot=${snapshot.id}`, { method: "POST", headers: { origin, "content-type": "application/json", cookie: "entra_explorer_session=session-cookie" }, body: JSON.stringify({ expectedRevision: null, ...(body as object) }) });
}

beforeEach(() => {
  vi.clearAllMocks();
  getServerSession.mockResolvedValue(session);
  recentSnapshots.mockResolvedValue([snapshot]);
  getThreatReview.mockResolvedValue(null);
  priorThreatReviews.mockResolvedValue([prior]);
  upsertThreatReview.mockImplementation(async (review) => review);
  recordAccess.mockResolvedValue(undefined);
});

describe("threat review revalidation route", () => {
  it("requires authentication and same-origin authorization", async () => {
    getServerSession.mockResolvedValueOnce(null);
    expect((await route.POST!(request({ sourceSnapshotId: prior.snapshotId }), { params: Promise.resolve({ id: findingId }) }))!.status).toBe(401);
    expect((await route.POST!(request({ sourceSnapshotId: prior.snapshotId }, "https://attacker.example"), { params: Promise.resolve({ id: findingId }) }))!.status).toBe(403);
    expect(upsertThreatReview).not.toHaveBeenCalled();
  });

  it("rejects a stale or missing source review", async () => {
    expect((await route.POST!(request({}), { params: Promise.resolve({ id: findingId }) }))!.status).toBe(400);
    expect((await route.POST!(request({ sourceSnapshotId: "stale" }), { params: Promise.resolve({ id: findingId }) }))!.status).toBe(409);
  });

  it("creates a current snapshot review, reopens resolved context, and audits revalidation", async () => {
    const response = (await route.POST!(request({ sourceSnapshotId: prior.snapshotId }), { params: Promise.resolve({ id: findingId }) }))!;
    expect(response.status).toBe(200);
    expect(upsertThreatReview).toHaveBeenCalledWith(expect.objectContaining({ findingId, snapshotId: snapshot.id, disposition: "open", owner: "IAM" }), session.id, null);
    expect(recordAccess).toHaveBeenCalledWith(snapshot.tenant.tenantId, session.id, "revalidate", "threat_review", findingId);
    expect(recentSnapshots).toHaveBeenCalledWith(snapshot.tenant.tenantId, 20);
  });

  it("returns current and prior decisions together without copying either", async () => {
    getThreatReview.mockResolvedValue({ ...prior, snapshotId: snapshot.id, disposition: "open" });
    const response = (await route.GET!(request({}), { params: Promise.resolve({ id: findingId }) }))!;
    expect(await response.json()).toMatchObject({ review: { snapshotId: snapshot.id }, priorReview: { snapshotId: prior.snapshotId } });
    expect(upsertThreatReview).not.toHaveBeenCalled();
  });
});


describe("snapshot-bound decision writes", () => {
  it("rejects a decision submitted from a previous scan even when the finding ID still exists", async () => {
    recentSnapshots.mockResolvedValue([{ ...snapshot, id: "newer-snapshot" }, snapshot]);
    const response = await route.PUT(request({ disposition: "open" }), { params: Promise.resolve({ id: findingId }) });
    expect(response!.status).toBe(409);
    expect(upsertThreatReview).not.toHaveBeenCalled();
  });
  it("returns a review conflict without claiming a concurrent edit was saved", async () => {
    upsertThreatReview.mockRejectedValue(new Error("Review conflict: another decision was saved."));
    const response = await route.PUT(request({ disposition: "open", expectedRevision: "old-revision" }), { params: Promise.resolve({ id: findingId }) });
    expect(response!.status).toBe(409);
    expect(upsertThreatReview).toHaveBeenCalledWith(expect.objectContaining({ snapshotId: snapshot.id }), session.id, "old-revision");
  });
});

it.each(["2026-02-30", "2026-13-01", "2026-00-10"])("rejects impossible acceptance date %s", async expiresAt => {
  const response = await route.PUT(request({ disposition: "accepted", owner: "IAM", assumption: "Reviewed", expiresAt }), { params: Promise.resolve({ id: findingId }) });
  expect(response!.status).toBe(400);
  expect(upsertThreatReview).not.toHaveBeenCalled();
});

it.each(["PUT", "POST"] as const)("rejects an oversized %s before storing a review", async method => {
  const response = await route[method](request({ disposition: "open", sourceSnapshotId: prior.snapshotId, assumption: "x".repeat(131_072) }), { params: Promise.resolve({ id: findingId }) });
  expect(response!.status).toBe(413);
  expect(upsertThreatReview).not.toHaveBeenCalled();
  expect(recordAccess).not.toHaveBeenCalled();
});
