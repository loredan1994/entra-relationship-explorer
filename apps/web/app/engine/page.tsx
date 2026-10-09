import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { EngineWorkspace } from "@/components/engine/workspace";
import { loadSnapshotContext } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";
export default async function EnginePage({ searchParams }: { searchParams: Promise<{ view?: string }> }) {
  const { view } = await searchParams;
  const { snapshot, history } = await loadSnapshotContext(view === "time" ? 10 : view === "contracts" ? 2 : 1);
  return <AppShell><div className="page-container investigations engine-workspace">
    <PageHeading eyebrow="Custom evidence engine" title="Reason about access" description="Reproduce a conclusion, test your intent, and compare a proposed change. Every workflow runs locally over the recorded evidence." actions={<Link className="button button-secondary" href="/guide">Guide</Link>} />
    <p className="trust-note">{snapshot.mode === "fixture" ? "Synthetic sample" : "Tenant evidence"} · snapshot <code>{snapshot.id}</code> · {snapshot.scannedAt}. Configuration and modeled paths do not establish observed use or effective access.</p>
    <EngineWorkspace key={`${snapshot.tenant.tenantId}/${snapshot.id}`} snapshot={snapshot} history={history} view={view} />
  </div></AppShell>;
}
