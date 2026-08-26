import { relationships } from "@entra-explorer/domain";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge } from "@/components/risk-badge";
import { loadCurrentSnapshot } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const snapshot = await loadCurrentSnapshot();
  const apps = snapshot.nodes.filter((node) => node.kind === "application").length;
  const identities = snapshot.nodes.filter((node) => node.kind === "servicePrincipal").length;
  const unowned = snapshot.nodes.filter(
    (node) => (node.kind === "application" || node.kind === "servicePrincipal") && node.ownerIds.length === 0,
  );
  const appPermissions = relationships(snapshot).filter(({ edge }) => edge.type === "CAN_CALL_AS_APP");
  const spotlight = appPermissions[0];

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow={snapshot.mode === "fixture" ? "Synthetic tenant overview" : "Read-only tenant overview"}
          title="See the identities behind every permission."
          description={`A view of configured Entra relationships from ${snapshot.mode === "fixture" ? "synthetic fixtures" : "an encrypted tenant snapshot"}. Activity data is not collected.`}
          actions={
            <Link className="button button-primary" href="/map">
              Open relationship map
            </Link>
          }
        />

        <section className="summary-strip" aria-label="Inventory summary">
          <article>
            <strong>{apps}</strong>
            <span>App blueprints</span>
            <small>Application registrations</small>
          </article>
          <article>
            <strong>{identities}</strong>
            <span>Tenant identities</span>
            <small>Enterprise applications</small>
          </article>
          <article>
            <strong>{appPermissions.length}</strong>
            <span>App-to-app connections</span>
            <small>Configured, not observed</small>
          </article>
          <article>
            <strong>{unowned.length}</strong>
            <span>Unowned identities</span>
            <small>Transparent review rule</small>
          </article>
        </section>

        <div className="overview-grid">
          {spotlight ? <section className="panel relationship-spotlight">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Relationship to review</p>
                <h2>{spotlight.source.label} can call {spotlight.target.label}</h2>
              </div>
              <RiskBadge level={spotlight.source.risk.level} reason={spotlight.source.risk.reason} />
            </div>
            <div className="mini-relationship" aria-label={`${spotlight.source.label} can call ${spotlight.target.label}`}>
              <div className="mini-node">
                <span>Tenant identity</span>
                <strong>{spotlight.source.label}</strong>
              </div>
              <div className="mini-edge">
                {spotlight.edge.permissions.map((permission) => <span key={permission}>{permission}</span>)}
                <i aria-hidden="true">→</i>
              </div>
              <div className="mini-node">
                <span>Resource identity</span>
                <strong>{spotlight.target.label}</strong>
              </div>
            </div>
            <p className="trust-note">
              <strong>Configured access.</strong> This assignment says the orchestrator can call the API. It does not prove that a call occurred.
            </p>
            <Link className="text-link" href={`/map?edge=${spotlight.edge.id}`}>
              Inspect source evidence <span aria-hidden="true">→</span>
            </Link>
          </section> : <section className="panel relationship-spotlight"><div className="map-empty compact"><h2>No app-to-app permissions found</h2><p>The current snapshot contains no application-role assignments to display.</p></div></section>}

          <section className="panel review-list">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Review queue</p>
                <h2>Reasons, not scores</h2>
              </div>
            </div>
            {snapshot.nodes
              .filter((node) => node.risk.level !== "low")
              .map((node) => (
                <article key={node.id}>
                  <RiskBadge level={node.risk.level} reason={node.risk.reason} />
                  <div>
                    <strong>{node.label}</strong>
                    <p>{node.risk.reason}</p>
                  </div>
                </article>
              ))}
          </section>
        </div>

        <section className="panel scan-coverage">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Collection coverage</p>
              <h2>{snapshot.completion.status === "complete" ? "Complete for the requested scope" : "Partial snapshot"}</h2>
            </div>
            <span className="completion-badge">{snapshot.completion.status}</span>
          </div>
          <p>
            {snapshot.completion.collectedEndpoints.length} source endpoint patterns collected · {snapshot.completion.errors.length} errors · activity endpoints intentionally skipped
          </p>
        </section>
      </div>
    </AppShell>
  );
}
