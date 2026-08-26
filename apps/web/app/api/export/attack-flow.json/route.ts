import { analyzeTenantIntelligence, toAttackFlow } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { loadExportSnapshot } from "@/server/export-snapshot";

export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  const loaded = await loadExportSnapshot(request, "attack_flow");
  if (loaded instanceof Response) return loaded;
  const intelligence = analyzeTenantIntelligence(loaded);
  const requested = request.nextUrl.searchParams.get("path");
  const path = intelligence.paths.find((candidate) => candidate.id === requested) ?? (!requested ? intelligence.paths[0] : undefined);
  if (!path) return new Response("Attack path not found.", { status: 404 });
  return Response.json(toAttackFlow(loaded, path), { headers: { "content-disposition": `attachment; filename="entra-attack-flow-${loaded.scannedAt.slice(0, 10)}.json"`, "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
