import { analyzeTenantIntelligence, cleanProjectFixture } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";
import { csvRow } from "@/server/csv";

export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  const config = getEntraConfig(); let snapshot = cleanProjectFixture;
  if (config.enabled) { const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config); if (!session || session.tenantId !== config.tenantId) return new Response("Authentication required.", { status: 401 }); const backend = await getBackend(config); const tenantSnapshot = (await backend.recentSnapshots(session.tenantId, 1))[0]; if (!tenantSnapshot) return new Response("No tenant snapshot is available.", { status: 404 }); snapshot = tenantSnapshot; await backend.recordAccess(session.tenantId, session.id, "export", "findings", snapshot.id); }
  const requested = request.nextUrl.searchParams.get("finding"); const findings = analyzeTenantIntelligence(snapshot).findings.filter((finding) => !requested || finding.id === requested); if (requested && findings.length === 0) return new Response("Finding not found.", { status: 404 });
  const header = ["findingId", "title", "severity", "evidenceClass", "summary", "remediation", "affectedObjectIds", "edgeIds", "sourceEndpoints", "uncertainty", "snapshotId", "scannedAt"];
  const rows = findings.map((finding) => [finding.id, finding.title, finding.severity, finding.evidenceClass, finding.summary, finding.remediation.join("; "), finding.affectedObjectIds.join("; "), finding.edgeIds.join("; "), finding.sourceEndpoints.join("; "), finding.uncertainty.join("; "), snapshot.id, snapshot.scannedAt]);
  return new Response([header, ...rows].map(csvRow).join("\r\n"), { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="entra-findings-${snapshot.scannedAt.slice(0, 10)}.csv"`, "cache-control": "no-store" } });
}
