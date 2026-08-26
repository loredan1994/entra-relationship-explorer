import { analyzeTenantIntelligence } from "@entra-explorer/domain";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { rankPermissions } from "@/components/permission-utils";
import { RiskBadge } from "@/components/risk-badge";
import { loadCurrentSnapshot } from "@/server/current-snapshot";
import { analyzeTenantSecurity } from "@/server/tenant-security";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const snapshot = await loadCurrentSnapshot();
  const sample = snapshot.mode === "fixture";
  const apps = snapshot.nodes.filter((node) => node.kind === "application").length;
  const identities = snapshot.nodes.filter((node) => node.kind === "servicePrincipal").length;
  const unowned = snapshot.nodes.filter(
    (node) => (node.kind === "application" || (node.kind === "servicePrincipal" && node.metadata?.ownershipExpected === true)) && node.ownerIds.length === 0,
  );
  // The spotlight is the single grant a reviewer should look at first: grants are
  // already sorted most-exposed first, and app-only access outranks delegated.
  const security = analyzeTenantSecurity(snapshot);
  const spotlight = security.grants.find((grant) => grant.accessType === "application") ?? security.grants[0];
  const spotlightPermissions = spotlight ? rankPermissions(spotlight.permissions) : [];
  const intelligence = analyzeTenantIntelligence(snapshot);
  const priorityPath = intelligence.paths[0];
  const activityCollected = snapshot.completion.collectedEndpoints.some((endpoint) => endpoint.startsWith("/auditLogs/signIns"));
  const collectedEndpointPatterns = new Set(snapshot.completion.collectedEndpoints.map((endpoint) =>
    endpoint.replace(/\/(applications|servicePrincipals|groups)\/[0-9a-f-]{36}(?=\/)/gi, "/$1/{id}"),
  ));
  const reviewQueue = intelligence.findings.slice(0, 10);
  const scannedLabel = new Intl.DateTimeFormat("en", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }).format(new Date(snapshot.scannedAt));

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow={sample ? "Sample tenant overview" : "Your tenant, read-only"}
          title="See the identities behind every permission."
          description={`${sample ? "Everything on this page is synthetic sample data, shown so the workspace is explorable before a tenant is connected." : "Everything on this page comes from an encrypted, read-only snapshot of your tenant."} ${activityCollected ? "Observed sign-ins are shown separately from configured access." : "Only configuration is collected — no sign-in activity, so nothing here claims a permission was actually used."}`}
          actions={
            <Link className="button button-primary" href="/map">
              Open relationship map
            </Link>
          }
        />

        <section className="summary-strip summary-links" aria-label="Inventory summary">
          <Link href="/map?kind=application">
            <strong>{apps}</strong>
            <span>App blueprints</span>
            <small>Application registrations — what each app is and which APIs it wants</small>
          </Link>
          <Link href="/map?kind=servicePrincipal">
            <strong>{identities}</strong>
            <span>Tenant identities</span>
            <small>Enterprise applications — the local identity an app uses in this tenant</small>
          </Link>
          <Link href="/security">
            <strong>{intelligence.paths.length}</strong>
            <span>Reachable attack paths</span>
            <small>Chains of configured access an attacker could follow — inferred, not observed</small>
          </Link>
          <Link href="/security">
            <strong>{unowned.length}</strong>
            <span>Unowned identities</span>
            <small>Apps with no accountable owner recorded — nobody to ask “is this still needed?”</small>
          </Link>
        </section>

        {priorityPath ? <section className="panel priority-path-card">
          <div>
            <p className="eyebrow">Address first · {priorityPath.severity}</p>
            <h2>{priorityPath.title}</h2>
            <p>{priorityPath.steps.length === 1 ? "One configured step connects" : `${priorityPath.steps.length} configured steps can connect`} the starting identity to powerful access. This is an inferred possibility, not evidence of exploitation.</p>
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
                <p className="eyebrow">Relationship to review first</p>
                <h2>{spotlight.caller.label} can call {spotlight.resource.label}</h2>
              </div>
              <RiskBadge level={spotlight.exposure === "high" ? "high" : spotlight.exposure === "review" ? "review" : "low"} reason={spotlight.reason} />
            </div>
            <p className="spotlight-reason">{spotlight.reason}</p>
            <div className="mini-relationship" aria-label={`${spotlight.caller.label} can call ${spotlight.resource.label}`}>
              <div className="mini-node">
                <span>Tenant identity</span>
                <strong>{spotlight.caller.label}</strong>
              </div>
              <div className="mini-edge">
                {spotlightPermissions.slice(0, 3).map((permission) => <span key={permission} className={spotlight.writeCapable.includes(permission) ? "is-write" : undefined}>{permission}</span>)}
                {spotlightPermissions.length > 3 ? <span className="pill-count">+{spotlightPermissions.length - 3} more</span> : null}
                <i aria-hidden="true">→</i>
              </div>
              <div className="mini-node">
                <span>Resource identity</span>
                <strong>{spotlight.resource.label}</strong>
              </div>
            </div>
            <p className="trust-note">
              <strong>Configured access.</strong> {spotlight.permissions.length} permission{spotlight.permissions.length === 1 ? " is" : "s are"} granted, {spotlight.writeCapable.length} write-capable. This says the caller is allowed to call the API — it does not prove a call ever happened.
            </p>
            <Link className="text-link" href={`/map?edge=${spotlight.edgeId}`}>
              Inspect all {spotlight.permissions.length} permissions and source evidence <span aria-hidden="true">→</span>
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
            Scanned {scannedLabel} · {collectedEndpointPatterns.size} source endpoint patterns collected · {snapshot.completion.errors.length} errors · {activityCollected ? "30-day activity overlay collected" : "activity endpoints intentionally skipped"} · <Link className="text-link" href="/settings">Full scope in Settings</Link>
          </p>
        </section>
      </div>
    </AppShell>
  );
}
