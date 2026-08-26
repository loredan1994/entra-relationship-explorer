import { analyzeTenantIntelligence, relationships } from "@entra-explorer/domain";
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
    (node) => (node.kind === "application" || (node.kind === "servicePrincipal" && node.metadata?.ownershipExpected === true)) && node.ownerIds.length === 0,
  );
  const appPermissions = relationships(snapshot).filter(({ edge }) => edge.type === "CAN_CALL_AS_APP");
  const spotlight = appPermissions[0];
  const intelligence = analyzeTenantIntelligence(snapshot);
  const priorityPath = intelligence.paths[0];
  const activityCollected = snapshot.completion.collectedEndpoints.some((endpoint) => endpoint.startsWith("/auditLogs/signIns"));
  const collectedEndpointPatterns = new Set(snapshot.completion.collectedEndpoints.map((endpoint) =>
    endpoint.replace(/\/(applications|servicePrincipals|groups)\/[0-9a-f-]{36}(?=\/)/gi, "/$1/{id}"),
  ));
  const reviewQueue = intelligence.findings.slice(0, 10);

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow={snapshot.mode === "fixture" ? "Synthetic tenant overview" : "Read-only tenant overview"}
          title="See the identities behind every permission."
          description={`A view of configured Entra relationships from ${snapshot.mode === "fixture" ? "synthetic fixtures" : "an encrypted tenant snapshot"}. ${activityCollected ? "Observed sign-ins are shown separately from configured access." : "Activity data is not collected."}`}
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
            <strong>{intelligence.paths.length}</strong>
            <span>Reachable attack paths</span>
            <small>Inferred from configured access</small>
          </article>
          <article>
            <strong>{unowned.length}</strong>
            <span>Unowned identities</span>
            <small>Transparent review rule</small>
          </article>
        </section>

        {priorityPath ? <section className="panel priority-path-card">
          <div>
            <p className="eyebrow">Address first · {priorityPath.severity}</p>
            <h2>{priorityPath.title}</h2>
            <p>{priorityPath.steps.length} configured steps can connect the starting identity to powerful access. This is an inferred possibility, not evidence of exploitation.</p>
          </div>
          <div className="priority-path-steps" aria-label={`${priorityPath.steps.length} attack path steps`}>
            {priorityPath.steps.map((item, index) => <span key={item.edgeId}><i>{index + 1}</i>{item.source.label}<b aria-hidden="true">→</b>{item.target.label}</span>)}
          </div>
          <Link className="button button-primary" href="/security">Review attack path</Link>
        </section> : null}

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
            {reviewQueue.map((finding) => (
                <article key={finding.id}>
                  <RiskBadge level={finding.severity === "low" ? "low" : finding.severity === "medium" ? "review" : "high"} reason={finding.summary} />
                  <div>
                    <strong>{finding.title}</strong>
                    <p>{finding.summary}</p>
                  </div>
                </article>
              ))}
            {intelligence.findings.length > reviewQueue.length ? <Link className="text-link" href="/security">Review all {intelligence.findings.length} findings <span aria-hidden="true">→</span></Link> : null}
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
            {collectedEndpointPatterns.size} source endpoint patterns collected · {snapshot.completion.errors.length} errors · {activityCollected ? "30-day activity overlay collected" : "activity endpoints intentionally skipped"}
          </p>
        </section>
      </div>
    </AppShell>
  );
}
