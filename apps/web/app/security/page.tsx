import { analyzeFindingLifecycle, analyzeTenantIntelligenceHistory } from "@entra-explorer/domain";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { ThreatWorkspace } from "@/components/threat-workspace";
import { loadPriorThreatReviews, loadSnapshotContext } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function SecurityPage() {
  const { snapshot, history } = await loadSnapshotContext(20);
  const intelligence = analyzeTenantIntelligenceHistory(history);
  const lifecycle = analyzeFindingLifecycle(history);
  const priorReviews = await loadPriorThreatReviews(snapshot, intelligence.findings.map((finding) => finding.id));
  return <AppShell><div className="page-container threat-page"><PageHeading
    eyebrow={snapshot.mode === "fixture" ? "Sample IAM intelligence" : "Your tenant's IAM intelligence"}
    title="Attack paths and threat workspace"
    description="Prioritize ways an identity could reach powerful access, inspect every configured step, and record the decision. Possibilities are inferred from configuration; activity is never invented."
  /><ThreatWorkspace intelligence={intelligence} lifecycle={lifecycle} priorReviews={priorReviews} today={new Date().toISOString().slice(0, 10)} tenantLabel={snapshot.tenant.tenantLabel} snapshotId={snapshot.id} completion={snapshot.completion.status} persistence={snapshot.mode === "tenant" ? "server" : "browser"} /></div></AppShell>;
}
