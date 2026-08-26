import "server-only";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { cookies } from "next/headers";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getEntraConfig } from "./config";
import { getBackend } from "./backend";

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
