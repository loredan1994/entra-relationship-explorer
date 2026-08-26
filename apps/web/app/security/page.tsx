import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { loadCurrentSnapshot } from "@/server/current-snapshot";
import { analyzeTenantSecurity, type Exposure } from "@/server/tenant-security";

export const dynamic = "force-dynamic";

const exposureLabel: Record<Exposure, string> = { high: "High exposure", review: "Review", low: "Least privilege" };

function formatMoment(value: string | null): string {
  if (!value) return "no expiry recorded";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "unknown";
  return new Intl.DateTimeFormat("en", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" }).format(new Date(parsed));
}

export default async function SecurityPage() {
  const snapshot = await loadCurrentSnapshot();
  const view = analyzeTenantSecurity(snapshot);
  const needsAttention = view.grants.filter((grant) => grant.exposure !== "low");
  const leastPrivilege = view.grants.filter((grant) => grant.exposure === "low");

  return (
    <AppShell>
      <div className="page-container settings-page">
        <PageHeading
          eyebrow={view.mode === "fixture" ? "Synthetic tenant exposure" : "Tenant exposure"}
          title="Where this tenant is exposed."
          description="Which applications hold powerful permissions, which identities have nobody accountable for them, and which credentials are running out. Every finding is configured access, not observed use."
          actions={<Link className="button button-secondary" href="/permissions">Full permission inventory</Link>}
        />

        <section className="summary-strip" aria-label="Exposure summary">
          <article>
            <strong>{view.summary.applicationGrants}</strong>
            <span>Application permissions</span>
            <small>Run as the app, no person involved</small>
          </article>
          <article>
            <strong>{view.summary.writeCapableGrants}</strong>
            <span>Can write</span>
            <small>Not read-only access</small>
          </article>
          <article>
            <strong>{view.summary.unowned}</strong>
            <span>Unowned identities</span>
            <small>Nobody accountable</small>
          </article>
          <article>
            <strong>{view.summary.credentialIssues}</strong>
            <span>Credential problems</span>
            <small>Expired or expiring</small>
          </article>
        </section>

        {view.completion === "partial" ? (
          <div className="notice-banner">
            <strong>This snapshot is partial.</strong> Some endpoints were skipped or failed, so absence of a finding here is not proof that it does not exist.
          </div>
        ) : null}

        <section className="settings-section">
          <div>
            <h2>Powerful permissions</h2>
            <p>
              {needsAttention.length === 0
                ? "Nothing above read-only on a single resource."
                : `${needsAttention.length} of ${view.grants.length} grants give more than read access to one resource.`}
            </p>
          </div>
          <div className="settings-card">
            {view.grants.length === 0 ? (
              <p className="change-empty">This snapshot records no application or delegated permission grants.</p>
            ) : null}
            {needsAttention.map((grant) => (
              <article key={grant.edgeId} className="grant-row">
                <div className="grant-row-head">
                  <div>
                    <span className="grant-path">
                      <strong>{grant.caller.label}</strong>
                      <i aria-hidden="true">→</i>
                      <strong>{grant.resource.label}</strong>
                    </span>
                    <small>
                      {grant.accessType === "application"
                        ? "Application permission · runs as itself"
                        : "Delegated permission · runs as a signed-in person"}
                    </small>
                  </div>
                  <span className={`severity-pill exposure-${grant.exposure}`}>{exposureLabel[grant.exposure]}</span>
                </div>
                <p>{grant.reason}</p>
                <div className="permission-pills">
                  {grant.permissions.map((permission) => (
                    <span key={permission} className={grant.writeCapable.includes(permission) ? "is-write" : ""}>
                      {permission}
                      {grant.escalation.includes(permission) ? " · can change the directory" : grant.writeCapable.includes(permission) ? " · write" : ""}
                    </span>
                  ))}
                </div>
                <div className="grant-row-foot">
                  <code>{grant.sourceEndpoint}</code>
                  <Link className="text-link" href={`/map?edge=${grant.edgeId}`}>Inspect evidence <span aria-hidden="true">→</span></Link>
                </div>
              </article>
            ))}
            {leastPrivilege.length > 0 ? (
              <details className="coverage-all">
                <summary>{leastPrivilege.length} read-only {leastPrivilege.length === 1 ? "grant" : "grants"}</summary>
                <div className="data-table-wrap flush" tabIndex={0} role="group" aria-label="Read-only grants, scrollable table">
                  <table className="data-table">
                    <thead><tr><th>Caller</th><th>Resource</th><th>Access</th><th>Permissions</th></tr></thead>
                    <tbody>
                      {leastPrivilege.map((grant) => (
                        <tr key={grant.edgeId}>
                          <td><strong>{grant.caller.label}</strong></td>
                          <td><strong>{grant.resource.label}</strong></td>
                          <td className="capitalized">{grant.accessType}</td>
                          <td className="mono">{grant.permissions.join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            ) : null}
          </div>
        </section>

        <section className="settings-section">
          <div>
            <h2>Nobody accountable</h2>
            <p>An application with no recorded owner cannot be confirmed as still needed, and no one is asked before it changes.</p>
          </div>
          <div className="settings-card">
            {view.ownership.length === 0 ? (
              <p className="change-empty">Every application and tenant identity has a recorded owner.</p>
            ) : (
              <div className="data-table-wrap flush" tabIndex={0} role="group" aria-label="Unowned identities, scrollable table">
                <table className="data-table">
                  <thead><tr><th>Object</th><th>Type</th><th>Permissions held</th><th></th></tr></thead>
                  <tbody>
                    {view.ownership.map((gap) => (
                      <tr key={gap.id}>
                        <td><strong>{gap.label}</strong>{gap.appId ? <small>appId {gap.appId}</small> : null}</td>
                        <td>{gap.kind === "application" ? "Blueprint" : "Tenant identity"}<small>{gap.kind === "application" ? "App registration" : "Enterprise application"}</small></td>
                        <td>{gap.grantCount > 0 ? <span className="severity-pill severity-medium">{gap.grantCount} grant{gap.grantCount === 1 ? "" : "s"}</span> : <span className="scanner-empty">none</span>}</td>
                        <td><Link className="text-link" href={`/applications/${gap.id}`}>Open</Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <section className="settings-section">
          <div>
            <h2>Credentials running out</h2>
            <p>An expired secret breaks the application. An expiring one is a deadline.</p>
          </div>
          <div className="settings-card">
            {view.credentials.length === 0 ? (
              <p className="change-empty">No expired or expiring credentials in this snapshot.</p>
            ) : (
              <ul className="finding-list">
                {view.credentials.map((credential) => (
                  <li key={credential.id}>
                    <strong>{credential.label}</strong>
                    <p>
                      {credential.status === "expired"
                        ? `Expired ${formatMoment(credential.expiresAt)}.`
                        : `Expires ${formatMoment(credential.expiresAt)}${credential.daysRemaining !== null ? ` · ${credential.daysRemaining} days left` : ""}.`}
                    </p>
                    <Link className="text-link" href={`/applications/${credential.id}`}>Open application detail</Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section className="settings-section">
          <div>
            <h2>Flagged for review</h2>
            <p>Reasons, not scores. Each line states the rule that produced it.</p>
          </div>
          <div className="settings-card">
            {view.review.length === 0 ? (
              <p className="change-empty">No object is currently flagged.</p>
            ) : (
              view.review.map((item) => (
                <article key={item.id} className="risk-row">
                  <div className="risk-row-head">
                    <div>
                      <strong>{item.label}</strong>
                      <small>{item.kind === "application" ? "Blueprint" : item.kind === "servicePrincipal" ? "Tenant identity" : item.kind === "user" ? "Person" : "Group"}</small>
                    </div>
                    <span className={`severity-pill exposure-${item.level === "high" ? "high" : "review"}`}>{item.level === "high" ? "High" : "Review"}</span>
                  </div>
                  <p>{item.reason}</p>
                </article>
              ))
            )}
          </div>
        </section>

        <p className="trust-note page-footnote">
          <strong>Configured, not observed.</strong> These findings describe permissions and assignments that exist in {view.tenantLabel}. The product does not
          request activity permissions, so it never claims a permission was used.
        </p>
      </div>
    </AppShell>
  );
}
