import "server-only";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import type { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getBackend } from "./backend";
import { getEntraConfig } from "./config";

export async function loadExportSnapshot(request: NextRequest, resourceType: string): Promise<TenantSnapshot | Response> {
  const history = await loadExportSnapshotHistory(request, resourceType, 1);
  return history instanceof Response ? history : history[0]!;
}

export async function loadExportSnapshotHistory(request: NextRequest, resourceType: string, limit = 20): Promise<TenantSnapshot[] | Response> {
  const config = getEntraConfig();
  if (!config.enabled) return [cleanProjectFixture];
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return new Response("Authentication required.", { status: 401 });
  const backend = await getBackend(config);
  const snapshots = await backend.recentSnapshots(session.tenantId, limit);
  const snapshot = snapshots[0];
  if (!snapshot) return new Response("No tenant snapshot is available.", { status: 404 });
  await backend.recordAccess(session.tenantId, session.id, "export", resourceType, snapshot.id);
  return snapshots;
}
