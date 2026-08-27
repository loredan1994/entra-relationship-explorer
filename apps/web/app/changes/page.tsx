import { analyzeFindingLifecycle, compareSnapshots } from "@entra-explorer/domain";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { loadSnapshotHistory } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function ChangesPage() {
  const snapshots = await loadSnapshotHistory(20);
  const current = snapshots[0]!;
  const previous = snapshots[1];
  const diff = previous ? compareSnapshots(previous, current) : null;
  const lifecycle = analyzeFindingLifecycle(snapshots);
  return (
    <AppShell>
      <div className="page-container">
        <PageHeading eyebrow="Snapshot comparison" title="Changes" description="Compare read-only snapshots without changing the tenant." />
        {!diff ? <section className="panel empty-state-large">
          <span className="empty-icon" aria-hidden="true">↔</span>
          <h2>One {current.mode === "fixture" ? "sample" : "tenant"} snapshot is available</h2>
          <p>Change tracking compares two scans of the same tenant. Run another read-only scan later and this page will show exactly which objects and permissions were added, removed, or changed in between.</p>
          <div className="empty-state-facts"><span><strong>1</strong> snapshot</span><span><strong>0</strong> inferred changes</span><span><strong>30 days</strong> proposed default retention</span></div>
        </section> : <>
          <section className="summary-strip change-summary" aria-label="Snapshot change summary">
            <article><strong>{diff.counts.added}</strong><span>Added</span><small>Objects and relationships</small></article>
            <article><strong>{diff.counts.removed}</strong><span>Removed</span><small>Absent from the latest scan</small></article>
            <article><strong>{diff.counts.changed}</strong><span>Changed</span><small>Material metadata differences</small></article>
            <article><strong>{snapshots.length}</strong><span>Snapshots</span><small>Same tenant only</small></article>
          </section>
          <section className="summary-strip lifecycle-summary" aria-label="Finding lifecycle summary">
            <article><strong>{lifecycle.counts.new}</strong><span>New findings</span><small>First detected in retained history</small></article>
            <article><strong>{lifecycle.counts.returned}</strong><span>Returned</span><small>Detected again after an absence</small></article>
            <article><strong>{lifecycle.counts.ongoing}</strong><span>Ongoing</span><small>Present in consecutive scans</small></article>
            <article><strong>{lifecycle.counts["no-longer-detected"]}</strong><span>No longer detected</span><small>Not an automatic resolution</small></article>
            <article><strong>{lifecycle.counts.unconfirmed}</strong><span>Unconfirmed</span><small>Coverage cannot prove absence</small></article>
          </section>
          <section className="panel change-feed">
            <div className="section-heading"><div><p className="eyebrow">Latest comparison</p><h2>{new Date(diff.beforeScannedAt).toLocaleString("en")} → {new Date(diff.afterScannedAt).toLocaleString("en")}</h2></div></div>
            {diff.changes.length === 0 ? <div className="change-empty"><strong>No material changes</strong><p>Scan timestamps and collection evidence alone do not create change events.</p></div> : <div className="change-list">{diff.changes.map((change) => <article key={`${change.subject}:${change.kind}:${change.id}`}><span className={`change-kind change-${change.kind}`}>{change.kind}</span><div><strong>{change.label}</strong><p>{change.subject} · {change.detail}</p><code>{change.id}</code></div></article>)}</div>}
          </section>
          <section className="panel change-feed lifecycle-feed">
            <div className="section-heading"><div><p className="eyebrow">Recurring investigation</p><h2>Finding lifecycle</h2><p>Scan evidence only. A finding disappearing never changes its analyst decision automatically.</p></div></div>
            <div className="change-list">{lifecycle.records.map((record) => <article key={`${record.status}:${record.finding.id}`}><span className={`change-kind lifecycle-${record.status}`}>{record.status.replaceAll("-", " ")}</span><div><strong>{record.finding.title}</strong><p>{record.status === "no-longer-detected" ? "No longer detected in the latest analysis; verify the configured evidence before marking it resolved." : record.status === "unconfirmed" ? "The latest scan did not detect this finding, but partial or reduced endpoint coverage prevents assurance." : `${record.finding.severity} · ${record.finding.evidenceClass} evidence · first detected ${new Date(record.firstDetectedAt).toLocaleString("en")}`}</p><code>{record.finding.id}</code></div></article>)}</div>
          </section>
        </>}
      </div>
    </AppShell>
  );
}
