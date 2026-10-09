import "server-only";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { cookies } from "next/headers";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getEntraConfig } from "./config";
import { getBackend } from "./backend";
import type { ThreatReview } from "@entra-explorer/backend";

/**
 * Why the workspace is showing the data it shows.
 *
 * - "connected":   live mode, valid session, and at least one tenant snapshot.
 * - "no-snapshot": live mode and a valid session, but no scan has completed yet.
 * - "signed-out":  live mode, but there is no valid session (never signed in, or it expired).
 * - "demo":        live mode is disabled; the product runs entirely on synthetic sample data.
 *
 * Only "connected" ever renders tenant data. Every other state renders the sample
 * snapshot and must say so loudly in the UI — silently substituting synthetic records
 * for tenant records is how "who is Maya Chen?" support tickets happen.
 */
export type ConnectionState = "connected" | "no-snapshot" | "signed-out" | "demo";

export interface SnapshotContext {
  snapshot: TenantSnapshot;
  history: TenantSnapshot[];
  state: ConnectionState;
  liveEnabled: boolean;
}

export async function loadSnapshotContext(limit = 10): Promise<SnapshotContext> {
  const config = getEntraConfig();
  if (!config.enabled) {
    return { snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "demo", liveEnabled: false };
  }
  const cookieStore = await cookies();
  const session = await getServerSession(cookieStore.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) {
    return { snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "signed-out", liveEnabled: true };
  }
  const snapshots = await (await getBackend(config)).recentSnapshots(session.tenantId, limit);
  if (snapshots.length === 0) {
    return { snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "no-snapshot", liveEnabled: true };
  }
  return { snapshot: snapshots[0]!, history: snapshots, state: "connected", liveEnabled: true };
}

export async function loadCurrentSnapshot(): Promise<TenantSnapshot> {
  return (await loadSnapshotContext(1)).snapshot;
}

export async function loadSnapshotHistory(limit = 10): Promise<TenantSnapshot[]> {
  return (await loadSnapshotContext(limit)).history;
}

export type ThreatReviewSummary = Pick<ThreatReview, "findingId" | "disposition" | "expiresAt">;

export async function loadThreatReviewContext(snapshot: TenantSnapshot, findingIds: string[]): Promise<{ currentReviews: ThreatReviewSummary[]; priorReviews: ThreatReview[] }> {
  const config = getEntraConfig();
  if (!config.enabled || snapshot.mode !== "tenant" || findingIds.length === 0) return { currentReviews: [], priorReviews: [] };
  const cookieStore = await cookies();
  const session = await getServerSession(cookieStore.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId || session.tenantId !== snapshot.tenant.tenantId) return { currentReviews: [], priorReviews: [] };
  const backend = await getBackend(config);
  const currentReviews: ThreatReviewSummary[] = [], priorReviews: ThreatReview[] = [];
  const ids = [...new Set(findingIds)];
  // Keep each read bounded without silently omitting findings in large tenants.
  // At most two database reads run concurrently, independent of inventory size.
  for (let start = 0; start < ids.length; start += 5_000) {
    const batch = ids.slice(start, start + 5_000);
    const [current, prior] = await Promise.all([
      backend.currentThreatReviews(session.tenantId, snapshot.id, batch),
      backend.priorThreatReviews(session.tenantId, snapshot.id, batch),
    ]);
    currentReviews.push(...current.map(({ findingId, disposition, expiresAt }) => ({ findingId, disposition, expiresAt })));
    priorReviews.push(...prior);
  }
  // Queue summaries omit notes, owners, flow drafts and edit revisions. Opening
  // a finding still loads its current record before editing or saving it.
  return { currentReviews, priorReviews };
}
