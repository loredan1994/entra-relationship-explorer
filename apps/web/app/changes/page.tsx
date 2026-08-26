import { compareSnapshots } from "@entra-explorer/domain";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { loadSnapshotHistory } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function ChangesPage() {
  const snapshots = await loadSnapshotHistory(20);
  const current = snapshots[0]!;
  const previous = snapshots[1];
  const diff = previous ? compareSnapshots(previous, current) : null;
  return (
    <AppShell>
      <div className="page-container">
        <PageHeading eyebrow="Snapshot comparison" title="Changes" description="Compare read-only snapshots without changing the tenant." />
        {!diff ? <section className="panel empty-state-large">
          <span className="empty-icon" aria-hidden="true">↔</span>
          <h2>One {current.mode === "fixture" ? "fixture" : "tenant"} snapshot is available</h2>
          <p>Changes need two snapshots from the same tenant. With only the current snapshot, no difference is inferred.</p>
          <div className="empty-state-facts"><span><strong>1</strong> snapshot</span><span><strong>0</strong> inferred changes</span><span><strong>30 days</strong> proposed default retention</span></div>
        </section> : <>
          <section className="summary-strip change-summary" aria-label="Snapshot change summary">
            <article><strong>{diff.counts.added}</strong><span>Added</span><small>Objects and relationships</small></article>
            <article><strong>{diff.counts.removed}</strong><span>Removed</span><small>Absent from the latest scan</small></article>
            <article><strong>{diff.counts.changed}</strong><span>Changed</span><small>Material metadata differences</small></article>
            <article><strong>{snapshots.length}</strong><span>Snapshots</span><small>Same tenant only</small></article>
          </section>
          <section className="panel change-feed">
            <div className="section-heading"><div><p className="eyebrow">Latest comparison</p><h2>{new Date(diff.beforeScannedAt).toLocaleString("en")} → {new Date(diff.afterScannedAt).toLocaleString("en")}</h2></div></div>
            {diff.changes.length === 0 ? <div className="change-empty"><strong>No material changes</strong><p>Scan timestamps and collection evidence alone do not create change events.</p></div> : <div className="change-list">{diff.changes.map((change) => <article key={`${change.subject}:${change.kind}:${change.id}`}><span className={`change-kind change-${change.kind}`}>{change.kind}</span><div><strong>{change.label}</strong><p>{change.subject} · {change.detail}</p><code>{change.id}</code></div></article>)}</div>}
          </section>
        </>}
      </div>
    </AppShell>
  );
}
