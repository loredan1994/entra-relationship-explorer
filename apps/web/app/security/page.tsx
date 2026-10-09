import { analyzeFindingLifecycle, analyzeTenantIntelligenceHistory, coverageMatrix } from "@entra-explorer/domain";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { ThreatWorkspace } from "@/components/threat-workspace";
import { loadThreatReviewContext, loadSnapshotContext } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function SecurityPage({ searchParams }: { searchParams: Promise<{ finding?: string; category?: string }> }) {
  const params = await searchParams;
  const context = await loadSnapshotContext(20);
  const { snapshot, history } = context;
  const intelligence = analyzeTenantIntelligenceHistory(history);
  const lifecycle = analyzeFindingLifecycle(history);
  const initialSelectedId = intelligence.findings.some(finding => finding.id === params.finding) ? params.finding : undefined;
  const initialCategory = !initialSelectedId && params.category === "ownership" ? "ownership" : undefined;
  const unavailableSelection = Boolean(params.finding && !initialSelectedId) || Boolean(params.category && params.category !== "ownership");
  const { currentReviews, priorReviews } = await loadThreatReviewContext(snapshot, intelligence.findings.map((finding) => finding.id));
  return <AppShell context={context}><div className="page-container threat-page"><PageHeading
    eyebrow={snapshot.mode === "fixture" ? "Sample IAM intelligence" : "Your tenant's IAM intelligence"}
    title="Attack paths and threat workspace"
    description="Prioritize ways an identity could reach powerful access, inspect every configured step, and record the decision. Possibilities are inferred from configuration; activity is never invented."
  />{unavailableSelection ? <p role="status" className="notice-banner">The requested finding or category is unavailable in this snapshot. The current finding queue is shown below.</p> : null}<ThreatWorkspace key={`${snapshot.id}:${initialSelectedId ?? ""}:${initialCategory ?? ""}`} initialSelectedId={initialSelectedId} initialCategory={initialCategory} coverage={coverageMatrix(snapshot)} intelligence={intelligence} lifecycle={lifecycle} currentReviews={currentReviews} priorReviews={priorReviews} today={new Date().toISOString().slice(0, 10)} tenantLabel={snapshot.tenant.tenantLabel} snapshotId={snapshot.id} completion={snapshot.completion.status} persistence={snapshot.mode === "tenant" ? "server" : "browser"} /></div></AppShell>;
}
