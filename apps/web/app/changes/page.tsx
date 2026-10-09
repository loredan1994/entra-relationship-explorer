import { analyzeFindingLifecycle, snapshotTimeline, cleanProjectPreviousFixture } from "@entra-explorer/domain";
import Link from "next/link";
import { CredentialHistory } from "@/components/credential-history";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { loadSnapshotContext } from "@/server/current-snapshot";

export const dynamic = "force-dynamic";

export default async function ChangesPage({ searchParams }: { searchParams: Promise<{ before?: string; after?: string }> }) {
  const selection = await searchParams;
  const context = await loadSnapshotContext(20);
  const retained = context.history;
  const snapshots = retained[0]?.mode === "fixture" ? [retained[0], cleanProjectPreviousFixture] : retained;
  const current = snapshots.find(s => s.id === selection.after) ?? snapshots[0]!;
  const candidate = snapshots.find(s => s.id === selection.before);
  const previous = candidate && candidate.id !== current.id && Date.parse(candidate.scannedAt) <= Date.parse(current.scannedAt) ? candidate : snapshots.find(s => s.id !== current.id && Date.parse(s.scannedAt) < Date.parse(current.scannedAt));
  const diff = previous ? snapshotTimeline(previous, current) : null;
  // Lifecycle must describe the selected later scan, never scans from its future.
  const lifecycle = analyzeFindingLifecycle(snapshots.slice(snapshots.indexOf(current)));
  return (
    <AppShell context={{ ...context, snapshot: current }}>
      <div className="page-container">
        <PageHeading eyebrow="Snapshot comparison" title="Changes" description="Compare read-only snapshots without changing the tenant." />
        <form key={`${current.id}:${previous?.id ?? "none"}`} className="investigation-search"><label>Earlier snapshot<select name="before" defaultValue={previous?.id ?? ""}><option value="">Select an earlier scan</option>{snapshots.map(s => <option key={s.id} value={s.id}>{s.scannedAt} · {s.id} · {s.completion.status}</option>)}</select></label><label>Later snapshot<select name="after" defaultValue={current.id}>{snapshots.map(s => <option key={s.id} value={s.id}>{s.scannedAt} · {s.id} · {s.completion.status}</option>)}</select></label><button className="button button-secondary" type="submit">Compare snapshots</button></form>
        {selection.after && !snapshots.some(s => s.id === selection.after) ? <p role="status">The selected later snapshot is unavailable. Showing the latest retained snapshot.</p> : null}
        {selection.before && (!candidate || candidate.id === current.id || Date.parse(candidate.scannedAt) > Date.parse(current.scannedAt)) ? <p role="status">The selected pair is unavailable or out of order. {previous ? "Showing the nearest available earlier snapshot." : "No earlier snapshot is available for the selected later scan."}</p> : null}
        {!diff ? <section className="panel empty-state-large">
          <span className="empty-icon" aria-hidden="true">↔</span>
          <h2>{snapshots.length === 1 ? `One ${current.mode === "fixture" ? "sample" : "tenant"} snapshot is available` : "No earlier snapshot for this selection"}</h2>
          <p>{snapshots.length === 1 ? "Change tracking needs two scans of the same tenant. Run another read-only scan later to compare objects and permissions." : "You selected the earliest retained scan as the later snapshot. Choose a more recent later snapshot to compare it with earlier evidence."}</p>
          <p><Link className="button button-secondary" href={snapshots.length === 1 ? "/settings" : "/changes"}>{snapshots.length === 1 ? "Open scan settings" : "Compare latest snapshots"}</Link></p>
          <div className="empty-state-facts"><span><strong>{snapshots.length}</strong> retained {snapshots.length === 1 ? "snapshot" : "snapshots"}</span><span><strong>0</strong> inferred changes</span><span><strong>30 days</strong> retention</span></div>
        </section> : <>
          <section className="summary-strip change-summary" aria-label="Snapshot change summary">
            <article><strong>{diff.counts.added}</strong><span>Added</span><small>Objects and relationships</small></article>
            <article><strong>{diff.counts.removed}</strong><span>Removed</span><small>Absent from the selected later scan</small></article>
            <article><strong>{diff.counts.changed}</strong><span>Changed</span><small>Material metadata differences</small></article>
            <article><strong>{diff.counts.unconfirmed}</strong><span>Unconfirmed changes</span><small>Incomplete or reduced coverage</small></article>
          </section>
          <section className="summary-strip lifecycle-summary" aria-label="Finding lifecycle summary">
            <article><strong>{lifecycle.counts.new}</strong><span>New findings</span><small>First detected in retained history</small></article>
            <article><strong>{lifecycle.counts.returned}</strong><span>Returned</span><small>Detected again after an absence</small></article>
            <article><strong>{lifecycle.counts.ongoing}</strong><span>Ongoing</span><small>Present in consecutive scans</small></article>
            <article><strong>{lifecycle.counts["no-longer-detected"]}</strong><span>No longer detected</span><small>Not an automatic resolution</small></article>
            <article><strong>{lifecycle.counts.unconfirmed}</strong><span>Unconfirmed</span><small>Coverage cannot prove absence</small></article>
          </section>
          <section className="panel change-feed">
            <div className="section-heading"><div><p className="eyebrow">Selected comparison</p><h2>{new Date(diff.beforeScannedAt).toLocaleString("en")} → {new Date(diff.afterScannedAt).toLocaleString("en")}</h2></div></div>
            {diff.changes.length === 0 ? <div className="change-empty"><strong>No material changes</strong><p>Scan timestamps and collection evidence alone do not create change events.</p></div> : <div className="change-list">{diff.changes.map((change) => <article key={`${change.subject}:${change.kind}:${change.id}`}><span className={`change-kind change-${change.kind}`}>{change.kind}</span><div><strong>{change.label}</strong><p>{change.subject} · {change.detail}</p><code>{change.id}</code>{change.fields?.length ? <details><summary>Field-level changes</summary><dl>{change.fields.map(field => <div key={field.field}><dt>{field.field}{field.state === "unconfirmed" ? " · Unconfirmed" : ""}</dt><dd>{field.reason ? <p>{field.reason}</p> : null}<strong>Before:</strong> <code>{field.before}</code><br /><strong>After:</strong> <code>{field.after}</code></dd></div>)}</dl></details> : null}<p>{change.attribution}</p>{change.auditCandidates.map(event => <p key={event.id}>{event.activity} · {event.occurredAt} · actor {event.actor.id ?? "unknown"} ({event.actor.kind})<br /><code>{event.sourceEndpoint}</code> · event <code>{event.id}</code></p>)}</div></article>)}</div>}
          </section>
          <CredentialHistory before={previous!} after={current} />
          <section className="panel change-feed lifecycle-feed">
            <div className="section-heading"><div><p className="eyebrow">Recurring investigation</p><h2>Finding lifecycle</h2><p>History through the selected later snapshot only. A finding disappearing never changes its analyst decision automatically.</p></div></div>
            <div className="change-list">{lifecycle.records.map((record) => <article key={`${record.status}:${record.finding.id}`}><span className={`change-kind lifecycle-${record.status}`}>{record.status.replaceAll("-", " ")}</span><div><strong>{record.finding.title}</strong><p>{record.status === "no-longer-detected" ? "No longer detected in the selected later analysis; verify the configured evidence before marking it resolved." : record.status === "unconfirmed" ? "The selected later scan did not detect this finding, but partial coverage or a path-analysis limit prevents assurance." : `${record.finding.severity} · ${record.finding.evidenceClass} evidence · first detected ${new Date(record.firstDetectedAt).toLocaleString("en")}`}</p>{record.finding.rule ? <small className="rule-feed-label">{record.finding.rule.id} · rule v{record.finding.rule.version}</small> : null}<code>{record.finding.id}</code></div></article>)}</div>
          </section>
        </>}
      </div>
    </AppShell>
  );
}
