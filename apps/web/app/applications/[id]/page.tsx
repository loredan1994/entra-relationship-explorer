import { cleanProjectFixture, nodeById, relationships } from "@entra-explorer/domain";
import Link from "next/link";
import { notFound } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge } from "@/components/risk-badge";
import { loadCurrentSnapshot } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export function generateStaticParams() {
  return cleanProjectFixture.nodes
    .filter((node) => node.kind === "application" || node.kind === "servicePrincipal")
    .map((node) => ({ id: node.id }));
}

export default async function ApplicationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const snapshot = await loadCurrentSnapshot();
  const selected = nodeById(snapshot, id);
  if (!selected || (selected.kind !== "application" && selected.kind !== "servicePrincipal")) notFound();

  const sameApplication = snapshot.nodes.filter(
    (node) => node.appId === selected.appId && (node.kind === "application" || node.kind === "servicePrincipal"),
  );
  const blueprint = sameApplication.find((node) => node.kind === "application");
  const tenantIdentity = sameApplication.find((node) => node.kind === "servicePrincipal");
  const connections = relationships(snapshot).filter(
    ({ source, target }) => sameApplication.some((node) => node.id === source.id || node.id === target.id),
  );
  const federatedCredentials = snapshot.nodes.filter((node) => node.kind === "federatedCredential" && sameApplication.some((application) => application.id === node.metadata?.parentId));

  return (
    <AppShell>
      <div className="page-container">
        <PageHeading
          eyebrow={`Application detail · ${snapshot.mode === "fixture" ? "sample record" : "your tenant snapshot"}`}
          title={selected.label}
          description="The reusable blueprint and its tenant-local identity are separate Entra objects joined by application ID."
          actions={<Link className="button button-secondary" href="/map">Back to map</Link>}
        />

        <div className="identity-pair-grid">
          <EntityCard title="Blueprint" microsoftTerm="App registration" node={blueprint} />
          <div className="pair-join" aria-label="The blueprint creates the tenant identity"><span>Same application ID</span><i aria-hidden="true">→</i></div>
          <EntityCard title="Tenant identity" microsoftTerm="Enterprise application (service principal)" node={tenantIdentity} />
        </div>

        {federatedCredentials.length > 0 ? (
          <section className="panel detail-connections">
            <div className="section-heading"><div><p className="eyebrow">Configured workload trust</p><h2>{federatedCredentials.length} federated identity credential{federatedCredentials.length === 1 ? "" : "s"}</h2></div></div>
            <div className="connection-list">
              {federatedCredentials.map((credential) => <article key={credential.id}><div><strong>{credential.label}</strong></div><p><strong>Issuer:</strong> <code>{String(credential.metadata?.issuer ?? "Unavailable")}</code></p><p><strong>Subject:</strong> <code>{String(credential.metadata?.subject ?? "Unavailable")}</code></p><p><strong>Audience:</strong> <code>{String(credential.metadata?.audiences ?? "Unavailable")}</code></p><p className="trust-note">Configured trust does not prove a matching external token was issued or used.</p></article>)}
            </div>
          </section>
        ) : null}

        <section className="panel detail-connections">
          <div className="section-heading"><div><p className="eyebrow">Connected facts</p><h2>{connections.length} explainable relationships</h2></div></div>
          <div className="connection-list">
            {connections.map(({ edge, source, target }) => (
              <article key={edge.id}>
                <div><strong>{source.label}</strong><span>{edge.plainLabel}</span><strong>{target.label}</strong></div>
                <p>{edge.permissions.join(" · ") || edge.type}</p>
                <Link className="text-link" href={`/map?edge=${edge.id}`}>Inspect evidence</Link>
              </article>
            ))}
          </div>
        </section>
      </div>
    </AppShell>
  );
}

function describeCredential(credential: { status: "healthy" | "expiring" | "expired" | "none"; expiresAt: string | null } | undefined): string {
  if (!credential || credential.status === "none") return "No credential metadata recorded";
  const expiry = credential.expiresAt
    ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(credential.expiresAt))
    : null;
  if (credential.status === "healthy") return expiry ? `Healthy — next expiry ${expiry}` : "Healthy";
  if (credential.status === "expiring") return expiry ? `Expiring soon — ${expiry}` : "Expiring soon";
  return expiry ? `Expired on ${expiry}` : "Expired";
}

function EntityCard({
  title,
  microsoftTerm,
  node,
}: {
  title: string;
  microsoftTerm: string;
  node: ReturnType<typeof nodeById>;
}) {
  if (!node) {
    return <section className="entity-detail-card missing"><p>No matching {title.toLocaleLowerCase()} exists in this snapshot.</p></section>;
  }
  return (
    <section className={`entity-detail-card detail-${node.kind}`}>
      <div className="entity-card-header"><div><p className="eyebrow">{title}</p><h2>{node.label}</h2><span>{microsoftTerm}</span></div><RiskBadge level={node.risk.level} reason={node.risk.reason} /></div>
      <p>{node.description}</p>
      <dl>
        <div><dt>Object ID</dt><dd><code>{node.id}</code></dd></div>
        <div><dt>Application ID</dt><dd><code>{node.appId}</code></dd></div>
        <div><dt>Publisher</dt><dd>{node.publisher}</dd></div>
        <div><dt>Owners</dt><dd>{node.ownerIds.length || "None recorded"}</dd></div>
        <div><dt>Credentials</dt><dd>{describeCredential(node.credential)}</dd></div>
      </dl>
      <p className="rule-reason"><strong>Review reason:</strong> {node.risk.reason}</p>
    </section>
  );
}
