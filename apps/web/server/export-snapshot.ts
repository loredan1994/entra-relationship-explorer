import "server-only";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import type { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getBackend } from "./backend";
import { getEntraConfig } from "./config";

export async function loadExportSnapshot(request: NextRequest, resourceType: string): Promise<TenantSnapshot | Response> {
  const config = getEntraConfig();
  if (!config.enabled) return cleanProjectFixture;
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return new Response("Authentication required.", { status: 401 });
  const backend = await getBackend(config);
  const snapshot = (await backend.recentSnapshots(session.tenantId, 1))[0];
  if (!snapshot) return new Response("No tenant snapshot is available.", { status: 404 });
  await backend.recordAccess(session.tenantId, session.id, "export", resourceType, snapshot.id);
  return snapshot;
}
