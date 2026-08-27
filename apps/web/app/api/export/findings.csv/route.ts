import { analyzeTenantIntelligenceHistory } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { csvRow } from "@/server/csv";
import { loadExportSnapshotHistory } from "@/server/export-snapshot";

export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  const history = await loadExportSnapshotHistory(request, "findings_csv"); if (history instanceof Response) return history; const snapshot = history[0]!;
  const requested = request.nextUrl.searchParams.get("finding"); const findings = analyzeTenantIntelligenceHistory(history).findings.filter((finding) => !requested || finding.id === requested); if (requested && findings.length === 0) return new Response("Finding not found.", { status: 404 });
  const header = ["findingId", "ruleId", "ruleVersion", "title", "severity", "evidenceClass", "summary", "prerequisites", "requiredCoverage", "remediation", "affectedObjectIds", "edgeIds", "sourceEndpoints", "uncertainty", "snapshotId", "scannedAt"];
  const rows = findings.map((finding) => [finding.id, finding.rule?.id ?? "", finding.rule ? String(finding.rule.version) : "", finding.title, finding.severity, finding.evidenceClass, finding.summary, finding.prerequisites?.join("; ") ?? "", finding.requiredCoverage?.join("; ") ?? "", finding.remediation.join("; "), finding.affectedObjectIds.join("; "), finding.edgeIds.join("; "), finding.sourceEndpoints.join("; "), finding.uncertainty.join("; "), snapshot.id, snapshot.scannedAt]);
  return new Response([header, ...rows].map(csvRow).join("\r\n"), { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="entra-findings-${snapshot.scannedAt.slice(0, 10)}.csv"`, "cache-control": "no-store" } });
}
