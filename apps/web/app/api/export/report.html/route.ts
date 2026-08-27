import { analyzeTenantIntelligenceHistory } from "@entra-explorer/domain";
import type { ThreatReview } from "@entra-explorer/backend";
import { NextRequest } from "next/server";
import { loadExportSnapshotHistory } from "@/server/export-snapshot";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";

export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  const history = await loadExportSnapshotHistory(request, "sanitized_report");
  if (history instanceof Response) return history;
  const snapshot = history[0]!;
  const intelligence = analyzeTenantIntelligenceHistory(history);
  const e = escapeHtml;
  const nonce = request.headers.get("x-nonce") ?? "";
  const config = getEntraConfig();
  const reviewMap = new Map<string, ThreatReview>();
  if (config.enabled) {
    const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
    if (session) {
      const backend = await getBackend(config);
      const reviews = await Promise.all(intelligence.findings.map((finding) => backend.getThreatReview(session.tenantId, snapshot.id, finding.id)));
      reviews.forEach((review) => { if (review) reviewMap.set(review.findingId, review); });
    }
  }
  const findings = intelligence.findings.map((finding) => {
    const review = reviewMap.get(finding.id);
    const scopedEvidence = finding.edgeIds.flatMap((id) => { const edge = snapshot.edges.find((item) => item.id === id); return edge?.scope ? [`${id}: ${edge.scope.directoryScopeId} (${edge.scope.objectId ?? "unresolved"})`] : []; });
    const decision = review ? `<section class="decision"><h3>Decision record</h3><p><strong>Status:</strong> ${e(review.disposition)} · <strong>Owner:</strong> ${e(review.owner || "Unassigned")} · <strong>Expiry:</strong> ${e(review.expiresAt ?? "None")}</p>${review.assumption ? `<p>${e(review.assumption)}</p>` : ""}${review.flowDraft?.length ? `<h4>Analyst-edited flow</h4><ol>${review.flowDraft.map((item) => `<li>${e(item.title)}${item.evidenceEdgeId ? ` <code>${e(item.evidenceEdgeId)}</code>` : " (analyst-authored)"}</li>`).join("")}</ol>` : ""}</section>` : "";
    const rule = finding.rule ? `<p><strong>Rule:</strong> ${e(finding.rule.id)} v${finding.rule.version} · ${e(finding.rule.title)}</p>` : "";
    const prerequisites = finding.prerequisites?.length ? `<h3>Prerequisites</h3><ul>${finding.prerequisites.map((item) => `<li>${e(item)}</li>`).join("")}</ul>` : "";
    const requiredCoverage = finding.requiredCoverage?.length ? `<p><strong>Required coverage:</strong> ${e(finding.requiredCoverage.join("; "))}</p>` : "";
    return `<article><div class="meta"><b class="${e(finding.severity)}">${e(finding.severity.toUpperCase())}</b><span>${e(finding.evidenceClass)} evidence</span><span>${e(finding.category.replaceAll("-", " "))}</span></div><h2>${e(finding.title)}</h2>${rule}<p>${e(finding.summary)}</p><h3>Why it matters</h3><p>${e(finding.whyItMatters)}</p>${prerequisites}<h3>Recommended action</h3><ol>${finding.remediation.map((item) => `<li>${e(item)}</li>`).join("")}</ol>${decision}<details><summary>Evidence references</summary>${requiredCoverage}<p><strong>Objects:</strong> ${e(finding.affectedObjectIds.join(", ") || "None")}</p><p><strong>Edges:</strong> ${e(finding.edgeIds.join(", ") || "None")}</p><p><strong>Directory scopes:</strong> ${e(scopedEvidence.join(", ") || "None")}</p><p><strong>Endpoints:</strong> ${e(finding.sourceEndpoints.join(", ") || "None")}</p>${finding.uncertainty.map((item) => `<p>${e(item)}</p>`).join("")}</details></article>`;
  }).join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>Entra IAM intelligence report</title><style nonce="${e(nonce)}">body{font:15px/1.55 system-ui,sans-serif;color:#17202b;background:#f3f5f7;margin:0}main{max-width:920px;margin:auto;padding:48px 24px}header,article{background:white;border:1px solid #d9dee5;border-radius:12px;padding:24px;margin-bottom:18px}h1{font-size:30px;margin:0 0 8px}h2{font-size:20px}.summary{display:flex;gap:20px;flex-wrap:wrap}.summary div{min-width:100px}.summary strong{display:block;font-size:28px}.meta{display:flex;gap:10px;align-items:center;color:#52606d;font-size:12px;text-transform:uppercase}.meta b{padding:3px 8px;border-radius:999px;background:#e7ebef}.meta .critical,.meta .high{background:#ffe1dc;color:#8b1d13}code{font-size:12px;overflow-wrap:anywhere}details{margin-top:16px;border-top:1px solid #e4e8ed;padding-top:12px}@media print{body{background:white}main{max-width:none;padding:0}article{break-inside:avoid}}</style></head><body><main><header><p>Read-only Microsoft Entra assessment</p><h1>${e(snapshot.tenant.tenantLabel)} IAM intelligence</h1><p>Generated from snapshot <code>${e(snapshot.id)}</code> collected ${e(snapshot.scannedAt)}. Configured access, observed activity, inferred possibilities, and missing evidence are intentionally distinguished.</p><div class="summary"><div><strong>${intelligence.counts.critical}</strong>Critical</div><div><strong>${intelligence.counts.high}</strong>High</div><div><strong>${intelligence.counts.medium}</strong>Review</div><div><strong>${intelligence.evidence.missing}</strong>Evidence gaps</div></div><p><strong>Coverage:</strong> ${e(snapshot.completion.status)} · ${snapshot.completion.collectedEndpoints.length} endpoints collected · ${snapshot.completion.skippedEndpoints.length} skipped.</p></header>${findings || "<article><h2>No findings</h2><p>No findings were generated for this snapshot.</p></article>"}</main></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "content-disposition": `attachment; filename="entra-iam-report-${snapshot.scannedAt.slice(0, 10)}.html"`, "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:", "x-content-type-options": "nosniff" } });
}

function escapeHtml(value: string): string { return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!); }
