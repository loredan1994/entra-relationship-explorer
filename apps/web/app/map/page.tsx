import { Suspense } from "react";
import { AppShell } from "@/components/app-shell";
import { RelationshipExplorer } from "@/components/relationship-explorer";
import { loadSnapshotContext } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function MapPage() {
  const context = await loadSnapshotContext(1);
  const { snapshot } = context;
  return (
    <AppShell context={context}>
      <Suspense fallback={<div className="page-loading">Loading relationships…</div>}>
        <RelationshipExplorer snapshot={snapshot} />
      </Suspense>
    </AppShell>
  );
}
