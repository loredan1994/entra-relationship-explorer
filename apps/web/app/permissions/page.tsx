import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { PermissionsTable } from "@/components/permissions-table";
import { loadCurrentSnapshot } from "@/server/current-snapshot";
import { analyzeTenantSecurity } from "@/server/tenant-security";

export const dynamic = "force-dynamic";

export default async function PermissionsPage() {
  const snapshot = await loadCurrentSnapshot();
  const security = analyzeTenantSecurity(snapshot);
  const { summary } = security;

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow="Configured access inventory"
          title="Permissions"
          description={`Every configured grant in the ${snapshot.mode === "fixture" ? "sample" : "latest tenant"} snapshot: who can call which resource, with the exact permission values, an exposure assessment, and a link to the source evidence.`}
          actions={<a className="button button-secondary" href="/api/export/relationships.csv">Export CSV</a>}
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

        <div className="notice-banner"><strong>Configured is not observed.</strong> These records describe consent and assignments — what is allowed to happen. The product does not collect activity, so nothing here proves a call occurred.</div>
        <PermissionsTable grants={security.grants} />
      </div>
    </AppShell>
  );
}
