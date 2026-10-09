import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { beforeEach, describe, expect, it, vi } from "vitest";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";

const getEntraConfig = vi.fn();
const getServerSession = vi.fn();
const recentSnapshots = vi.fn();
const priorThreatReviews = vi.fn();
const currentThreatReviews = vi.fn();
const cookieGet = vi.fn();

vi.mock("./config", () => ({ getEntraConfig: () => getEntraConfig() }));
vi.mock("./backend", () => ({ getBackend: async () => ({ recentSnapshots, priorThreatReviews, currentThreatReviews }) }));
vi.mock("./auth/session-store", () => ({
  SESSION_COOKIE: "entra_explorer_session",
  getServerSession: (...args: unknown[]) => getServerSession(...args),
}));
vi.mock("next/headers", () => ({ cookies: async () => ({ get: cookieGet }) }));

const { loadCurrentSnapshot, loadThreatReviewContext, loadSnapshotContext, loadSnapshotHistory } = await import("./current-snapshot");

const liveConfig = { enabled: true, tenantId: TENANT };

/** A tenant snapshot distinguishable from the synthetic sample data. */
function tenantSnapshot(id: string, scannedAt = "2026-08-26T10:00:00.000Z"): TenantSnapshot {
  return { ...cleanProjectFixture, id, tenant: { tenantId: TENANT, tenantLabel: "Contoso" }, scannedAt, mode: "tenant" };
}

beforeEach(() => {
  vi.clearAllMocks();
  getEntraConfig.mockReturnValue(liveConfig);
  cookieGet.mockReturnValue({ value: "session-cookie" });
  getServerSession.mockResolvedValue({ id: "session-1", tenantId: TENANT });
  recentSnapshots.mockResolvedValue([]);
  priorThreatReviews.mockResolvedValue([]);
  currentThreatReviews.mockResolvedValue([]);
});

describe("demo mode", () => {
  it("serves the sample snapshot and never reaches the database when live access is off", async () => {
    getEntraConfig.mockReturnValue({ enabled: false, reason: "disabled" });
    const context = await loadSnapshotContext();
    expect(context).toEqual({ snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "demo", liveEnabled: false });
    expect(recentSnapshots).not.toHaveBeenCalled();
    expect(getServerSession).not.toHaveBeenCalled();
  });
});

describe("signed-out state", () => {
  it("reports signed-out when no session cookie is present", async () => {
    cookieGet.mockReturnValue(undefined);
    getServerSession.mockResolvedValue(null);
    const context = await loadSnapshotContext();
    expect(context.state).toBe("signed-out");
    expect(context.liveEnabled).toBe(true);
    expect(getServerSession).toHaveBeenCalledWith(undefined, liveConfig);
  });

  it("reports signed-out when the session has expired or cannot be read", async () => {
    getServerSession.mockResolvedValue(null);
    expect((await loadSnapshotContext()).state).toBe("signed-out");
    expect(recentSnapshots).not.toHaveBeenCalled();
  });

  it("refuses a session belonging to a different tenant than the configured one", async () => {
    getServerSession.mockResolvedValue({ id: "session-1", tenantId: OTHER_TENANT });
    const context = await loadSnapshotContext();
    expect(context.state).toBe("signed-out");
    expect(context.snapshot).toBe(cleanProjectFixture);
    expect(recentSnapshots).not.toHaveBeenCalled();
  });

  it("passes the session cookie value through to the session lookup", async () => {
    await loadSnapshotContext();
    expect(getServerSession).toHaveBeenCalledWith("session-cookie", liveConfig);
  });
});

describe("connected state", () => {
  it("reports no-snapshot when a valid session has never completed a scan", async () => {
    recentSnapshots.mockResolvedValue([]);
    const context = await loadSnapshotContext();
    expect(context.state).toBe("no-snapshot");
    expect(context.snapshot).toBe(cleanProjectFixture);
    expect(context.history).toEqual([cleanProjectFixture]);
    // Live access is configured and the session is valid: only the scan is missing,
    // so the UI must still offer scanning rather than sign-in.
    expect(context.liveEnabled).toBe(true);
  });

  it("serves tenant data only once a snapshot exists", async () => {
    const newest = tenantSnapshot("snap-new", "2026-08-26T10:00:00.000Z");
    const older = tenantSnapshot("snap-old", "2026-08-01T10:00:00.000Z");
    recentSnapshots.mockResolvedValue([newest, older]);
    const context = await loadSnapshotContext();
    expect(context.state).toBe("connected");
    expect(context.snapshot).toBe(newest);
    expect(context.history).toEqual([newest, older]);
    expect(context.liveEnabled).toBe(true);
  });

  it("reads snapshots scoped to the session's own tenant", async () => {
    recentSnapshots.mockResolvedValue([tenantSnapshot("snap-1")]);
    await loadSnapshotContext(7);
    expect(recentSnapshots).toHaveBeenCalledWith(TENANT, 7);
  });

  it("defaults to a bounded history page", async () => {
    await loadSnapshotContext();
    expect(recentSnapshots).toHaveBeenCalledWith(TENANT, 10);
  });
});

describe("every state that is not connected shows sample data", () => {
  it.each([
    ["demo", () => getEntraConfig.mockReturnValue({ enabled: false, reason: "off" })],
    ["signed-out", () => getServerSession.mockResolvedValue(null)],
    ["no-snapshot", () => recentSnapshots.mockResolvedValue([])],
  ])("%s renders the synthetic fixture, so the UI can label it", async (state, arrange) => {
    arrange();
    const context = await loadSnapshotContext();
    expect(context.state).toBe(state);
    expect(context.snapshot).toBe(cleanProjectFixture);
    expect(context.snapshot.mode).toBe("fixture");
  });

  it("marks a connected snapshot as tenant mode, so it is never mistaken for sample data", async () => {
    recentSnapshots.mockResolvedValue([tenantSnapshot("snap-1")]);
    expect((await loadSnapshotContext()).snapshot.mode).toBe("tenant");
  });
});

describe("convenience readers", () => {
  it("asks for a single snapshot when only the current one is needed", async () => {
    const snapshot = tenantSnapshot("snap-1");
    recentSnapshots.mockResolvedValue([snapshot]);
    expect(await loadCurrentSnapshot()).toBe(snapshot);
    expect(recentSnapshots).toHaveBeenCalledWith(TENANT, 1);
  });

  it("returns the history list at the requested depth", async () => {
    const snapshots = [tenantSnapshot("a"), tenantSnapshot("b")];
    recentSnapshots.mockResolvedValue(snapshots);
    expect(await loadSnapshotHistory(2)).toEqual(snapshots);
    expect(recentSnapshots).toHaveBeenCalledWith(TENANT, 2);
  });

  it("falls back to the sample snapshot for both readers when signed out", async () => {
    getServerSession.mockResolvedValue(null);
    expect(await loadCurrentSnapshot()).toBe(cleanProjectFixture);
    expect(await loadSnapshotHistory()).toEqual([cleanProjectFixture]);
  });
});

describe("prior review context", () => {
  it("batch-loads only reviews for the authenticated snapshot tenant", async () => {
    const snapshot = tenantSnapshot("snap-current");
    priorThreatReviews.mockResolvedValue([{ findingId: "finding-1" }]);
    expect(await loadThreatReviewContext(snapshot, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [{ findingId: "finding-1" }] });
    expect(priorThreatReviews).toHaveBeenCalledWith(TENANT, snapshot.id, ["finding-1"]);
  });

  it("includes all current queue decisions without exposing notes, ownership, flow drafts or edit revisions", async () => {
    const snapshot = tenantSnapshot("snap-current");
    currentThreatReviews.mockResolvedValue([
      { findingId: "finding-1", disposition: "accepted", expiresAt: "2026-10-10", assumption: "Private rationale", owner: "Private owner", flowDraft: [{ title: "Private draft" }], revision: "opaque-edit-revision", tenantId: TENANT, snapshotId: snapshot.id },
      { findingId: "finding-2", disposition: "mitigating", expiresAt: null },
    ]);
    const result = await loadThreatReviewContext(snapshot, ["finding-1", "finding-2"]);
    expect(result).toEqual({ currentReviews: [
      { findingId: "finding-1", disposition: "accepted", expiresAt: "2026-10-10" },
      { findingId: "finding-2", disposition: "mitigating", expiresAt: null },
    ], priorReviews: [] });
    expect(currentThreatReviews).toHaveBeenCalledWith(TENANT, snapshot.id, ["finding-1", "finding-2"]);
    expect(getServerSession).toHaveBeenCalledOnce();
  });

  it.each([5_000, 5_001, 10_000, 10_001])("batches all %i requested findings without duplicating or truncating decisions", async count => {
    const snapshot = tenantSnapshot("snap-large");
    const ids = Array.from({ length: count }, (_, i) => `finding-${i}`);
    currentThreatReviews.mockImplementation(async (_tenant, _snapshot, batch: string[]) => batch.map(findingId => ({ findingId, disposition: "accepted", expiresAt: "2026-10-10" })));
    priorThreatReviews.mockImplementation(async (_tenant, _snapshot, batch: string[]) => batch.map(findingId => ({ findingId, snapshotId: "prior" })));
    const result = await loadThreatReviewContext(snapshot, [...ids, ids[0]!]);
    expect(result.currentReviews.map(review => review.findingId)).toEqual(ids);
    expect(result.priorReviews.map(review => review.findingId)).toEqual(ids);
    for (const read of [currentThreatReviews, priorThreatReviews]) {
      expect(read).toHaveBeenCalledTimes(Math.ceil(count / 5_000));
      for (let start = 0; start < ids.length; start += 5_000) {
        expect(read).toHaveBeenNthCalledWith(start / 5_000 + 1, TENANT, snapshot.id, ids.slice(start, start + 5_000));
      }
    }
  });

  it("does not query reviews for fixtures, empty input, signed-out sessions, or a mismatched tenant", async () => {
    expect(await loadThreatReviewContext(cleanProjectFixture, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });
    expect(await loadThreatReviewContext(tenantSnapshot("snap"), [])).toEqual({ currentReviews: [], priorReviews: [] });
    getServerSession.mockResolvedValue(null);
    expect(await loadThreatReviewContext(tenantSnapshot("snap"), ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });
    getServerSession.mockResolvedValue({ id: "session-1", tenantId: OTHER_TENANT });
    expect(await loadThreatReviewContext(tenantSnapshot("snap"), ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });
    expect(priorThreatReviews).not.toHaveBeenCalled();
    expect(currentThreatReviews).not.toHaveBeenCalled();
  });

  it("keeps every independent live-mode and tenant guard effective", async () => {
    const tenant = tenantSnapshot("snap");
    getEntraConfig.mockReturnValue({ enabled: false, reason: "off" });
    expect(await loadThreatReviewContext(tenant, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });

    getEntraConfig.mockReturnValue(liveConfig);
    expect(await loadThreatReviewContext({ ...tenant, mode: "fixture" }, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });

    const otherSnapshot = { ...tenant, tenant: { tenantId: OTHER_TENANT, tenantLabel: "Other" }, nodes: tenant.nodes.map((item) => ({ ...item, tenantId: OTHER_TENANT })), edges: tenant.edges.map((item) => ({ ...item, tenantId: OTHER_TENANT })) };
    getServerSession.mockResolvedValue({ id: "session-1", tenantId: OTHER_TENANT });
    expect(await loadThreatReviewContext(otherSnapshot, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });

    getServerSession.mockResolvedValue({ id: "session-1", tenantId: TENANT });
    expect(await loadThreatReviewContext(otherSnapshot, ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });
    expect(priorThreatReviews).not.toHaveBeenCalled();
    expect(currentThreatReviews).not.toHaveBeenCalled();
  });

  it("handles an absent session cookie without dereferencing it", async () => {
    cookieGet.mockReturnValue(undefined);
    getServerSession.mockResolvedValue(null);
    expect(await loadThreatReviewContext(tenantSnapshot("snap"), ["finding-1"])).toEqual({ currentReviews: [], priorReviews: [] });
    expect(getServerSession).toHaveBeenCalledWith(undefined, liveConfig);
  });
});
