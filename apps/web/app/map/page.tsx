import { Suspense } from "react";
import { AppShell } from "@/components/app-shell";
import { RelationshipExplorer } from "@/components/relationship-explorer";
import { loadCurrentSnapshot } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function MapPage() {
  const snapshot = await loadCurrentSnapshot();
  return (
    <AppShell>
      <Suspense fallback={<div className="page-loading">Loading relationships…</div>}>
        <RelationshipExplorer snapshot={snapshot} />
      </Suspense>
    </AppShell>
  );
}
