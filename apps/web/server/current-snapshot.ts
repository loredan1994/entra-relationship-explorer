import "server-only";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { cookies } from "next/headers";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getEntraConfig } from "./config";
import { getBackend } from "./backend";

export async function loadCurrentSnapshot(): Promise<TenantSnapshot> {
  return (await loadSnapshotHistory(1))[0] ?? cleanProjectFixture;
}

export async function loadSnapshotHistory(limit = 10): Promise<TenantSnapshot[]> {
  const config = getEntraConfig();
  if (!config.enabled) return [cleanProjectFixture];
  const cookieStore = await cookies();
  const session = await getServerSession(cookieStore.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return [cleanProjectFixture];
  const snapshots = await (await getBackend(config)).recentSnapshots(session.tenantId, limit);
  return snapshots.length > 0 ? snapshots : [cleanProjectFixture];
}
