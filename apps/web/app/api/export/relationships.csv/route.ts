import { NextRequest } from "next/server";
import { relationships } from "@entra-explorer/domain";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { getBackend } from "@/server/backend";
import { csvRow } from "@/server/csv";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return new Response("Live Entra access is disabled.", { status: 404 });
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return new Response("Authentication required.", { status: 401 });
  const backend = await getBackend(config);
  const snapshot = (await backend.recentSnapshots(session.tenantId, 1))[0];
  if (!snapshot) return new Response("No tenant snapshot is available.", { status: 404 });
  await backend.recordAccess(session.tenantId, session.id, "export", "snapshot", snapshot.id);
  const header = ["sourceName", "sourceObjectId", "relationshipType", "targetName", "targetObjectId", "permissions", "directoryScopeId", "scopeObjectId", "sourceEndpoint", "sourceRecordIds", "scannedAt", "completeness"];
  const rows = relationships(snapshot).map(({ edge, source, target }) => [source.label, source.id, edge.type, target.label, target.id, edge.permissions.join("; "), edge.scope?.directoryScopeId ?? "", edge.scope?.objectId ?? "", edge.evidence.sourceEndpoint, edge.evidence.sourceRecordIds.join("; "), edge.evidence.scannedAt, edge.evidence.completeness]);
  const csv = [header, ...rows].map(csvRow).join("\r\n");
  return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="entra-relationships-${snapshot.scannedAt.slice(0, 10)}.csv"`, "cache-control": "no-store" } });
}
