import { credentialHistory, type TenantSnapshot } from "@entra-explorer/domain";

export function CredentialHistory({ before, after }: { before: TenantSnapshot; after: TenantSnapshot }) {
  const changes = credentialHistory(before, after);
  return <section className="panel investigation-card" aria-label="Credential and trust history">
    <h2>Credential and trust history</h2>
    <p>Individual password, certificate and federation changes in the selected pair. Validity changes caused by time passing are shown separately from configuration edits. Missing inventory remains unconfirmed.</p>
    {!changes.length ? <p>No individual credential or trust differences are visible in the collected inventories.</p> : <div className="change-list">{changes.map(change => <article key={`${change.identityId}:${change.kind}:${change.credentialId}`}>
      <span className={`change-kind change-${change.change}`}>{change.change.replaceAll("-", " ")}</span>
      <div><h3>{change.identityLabel} · {change.kind}</h3><p>{change.reason}</p><code>{change.identityId}</code> · <code>{change.credentialId}</code>
        <dl>{(["before", "after"] as const).map(side => <div key={side}><dt>{side === "before" ? "Earlier snapshot" : "Later snapshot"}</dt><dd>{change[side] ? <>{change[side].state ? <strong>{change[side].state.replaceAll("-", " ")}</strong> : null}{Object.entries(change[side].details).map(([key, value]) => <p key={key}>{key}: <code>{value ?? "Unknown"}</code></p>)}</> : "Not recorded"}</dd></div>)}</dl>
        <details><summary>Source endpoints</summary>{change.sourceEndpoints.map(endpoint => <code key={endpoint}>{endpoint}</code>)}</details>
      </div>
    </article>)}</div>}
  </section>;
}
