import { relationships } from "@entra-explorer/domain";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { PermissionsTable } from "@/components/permissions-table";
import { loadCurrentSnapshot } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function PermissionsPage() {
  const snapshot = await loadCurrentSnapshot();
  const views = relationships(snapshot).filter(({ edge }) =>
    edge.type === "CAN_CALL_AS_APP" || edge.type === "CAN_CALL_DELEGATED",
  );

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow="Configured access inventory"
          title="Permissions"
          description={`Who can call which resource, with exact permission values and source evidence. ${snapshot.mode === "fixture" ? "Synthetic fixture data." : "Read-only tenant snapshot."}`}
        />
        <div className="notice-banner"><strong>Configured is not observed.</strong> These records describe consent and assignments. Activity data is not collected.</div>
        <PermissionsTable views={views} />
      </div>
    </AppShell>
  );
}
