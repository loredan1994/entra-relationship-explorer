import { NextRequest } from "next/server";
import { relationships } from "@entra-explorer/domain";
import { loadExportSnapshot } from "@/server/export-snapshot";
import { csvRow } from "@/server/csv";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const snapshot = await loadExportSnapshot(request, "snapshot");
  if (snapshot instanceof Response) return snapshot;
  const header = ["sourceName", "sourceObjectId", "relationshipType", "targetName", "targetObjectId", "permissions", "directoryScopeId", "scopeObjectId", "sourceEndpoint", "sourceRecordIds", "scannedAt", "completeness"];
  const rows = relationships(snapshot).map(({ edge, source, target }) => [source.label, source.id, edge.type, target.label, target.id, edge.permissions.join("; "), edge.scope?.directoryScopeId ?? "", edge.scope?.objectId ?? "", edge.evidence.sourceEndpoint, edge.evidence.sourceRecordIds.join("; "), edge.evidence.scannedAt, edge.evidence.completeness]);
  const csv = [header, ...rows].map(csvRow).join("\r\n");
  return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="entra-relationships-${snapshot.scannedAt.slice(0, 10)}.csv"`, "cache-control": "no-store" } });
}
