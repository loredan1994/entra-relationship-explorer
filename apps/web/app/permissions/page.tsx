import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { PermissionsTable } from "@/components/permissions-table";
import { ExportLink } from "@/components/export-link";
import { loadSnapshotContext } from "@/server/current-snapshot";
import { analyzeTenantSecurity } from "@/server/tenant-security";

export const dynamic = "force-dynamic";

export default async function PermissionsPage() {
  const context = await loadSnapshotContext(1);
  const { snapshot, state } = context;
  const security = analyzeTenantSecurity(snapshot);
  const { summary } = security;

  return (
    <AppShell context={context}>
      <div className="page-container">
        <PageHeading
          eyebrow="Configured access inventory"
          title="Permissions"
          description={`Every configured grant in the ${snapshot.mode === "fixture" ? "sample" : "latest tenant"} snapshot: who can call which resource, with the exact permission values, an exposure assessment, and a link to the source evidence.`}
          actions={state === "demo" || state === "connected" ? <ExportLink className="button button-secondary" href={`/api/export/relationships.csv?snapshot=${encodeURIComponent(snapshot.id)}`}>Export CSV</ExportLink> : <a className="button button-secondary" href="/settings">{state === "signed-out" ? "Sign in to export tenant data" : "Scan tenant to enable exports"}</a>}
        />

        <section className="summary-strip" aria-label="Permission grant summary">
          <article>
            <strong>{summary.applicationGrants}</strong>
            <span>Application grants</span>
            <small>The app calls as itself — no signed-in person required, so a stolen credential is enough</small>
          </article>
          <article>
            <strong>{summary.delegatedGrants}</strong>
            <span>Delegated grants</span>
            <small>The app acts for a signed-in person and is bounded by what that person may do</small>
          </article>
          <article>
            <strong>{summary.writeCapableGrants}</strong>
            <span>Write-capable</span>
            <small>At least one permission can change data, not just read it</small>
          </article>
          <article>
            <strong>{summary.escalationGrants}</strong>
            <span>Directory escalation</span>
            <small>Permissions that can change the directory itself — an app could widen its own access</small>
          </article>
        </section>

        <div className="notice-banner"><strong>Configured is not observed.</strong> These records describe consent and assignments — what is allowed to happen. Optional sign-in evidence is separate and does not prove that a configured permission was used.</div>
        <p><a className="button button-secondary" href="/investigations?view=ledger">Reconcile requested and granted permissions</a></p>
        <PermissionsTable grants={security.grants} />
      </div>
    </AppShell>
  );
}
