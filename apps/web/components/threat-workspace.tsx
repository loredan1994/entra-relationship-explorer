"use client";

import type { ThreatReview } from "@entra-explorer/backend";
import type { FindingLifecycle, FindingLifecycleStatus, IamFinding, TenantIntelligence } from "@entra-explorer/domain";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

type Disposition = "open" | "mitigating" | "accepted" | "resolved";
interface FlowDraftStep { id: string; title: string; evidenceEdgeId: string | null; }
interface ReviewRecord { disposition: Disposition; owner: string; expiresAt: string; assumption: string; flowDraft: FlowDraftStep[]; }
interface SaveState { status: "idle" | "saving" | "saved" | "error"; message?: string; }
type FindingFilter = "all" | "critical" | "high" | "medium" | "missing" | "new" | "ongoing" | "returned" | "acceptance-due";
const EMPTY: ReviewRecord = { disposition: "open", owner: "", expiresAt: "", assumption: "", flowDraft: [] };
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;
const evidenceLabel = { configured: "Configured access", observed: "Observed activity", inferred: "Inferred possibility", missing: "Missing evidence" } as const;

const toReviewRecord = (review: ThreatReview): ReviewRecord => ({ disposition: review.disposition, owner: review.owner, expiresAt: review.expiresAt ?? "", assumption: review.assumption, flowDraft: review.flowDraft ?? [] });

export function ThreatWorkspace({ intelligence, lifecycle, priorReviews, today, tenantLabel, snapshotId, completion, persistence }: { intelligence: TenantIntelligence; lifecycle: FindingLifecycle; priorReviews: ThreatReview[]; today: string; tenantLabel: string; snapshotId: string; completion: "complete" | "partial"; persistence: "server" | "browser" }) {
  const storageKey = `entra-threat-workspace:${snapshotId}`;
  const [selectedId, setSelectedId] = useState(intelligence.findings[0]?.id ?? "");
  const [records, setRecords] = useState<Record<string, ReviewRecord>>({});
  const [pendingReview, setPendingReview] = useState<{ id: string; record: ReviewRecord } | null>(null);
  const [saveState, setSaveState] = useState<SaveState>({ status: "idle" });
  const [priorRecords, setPriorRecords] = useState<Record<string, ThreatReview>>(() => Object.fromEntries(priorReviews.map((review) => [review.findingId, review])));
  const [filter, setFilter] = useState<FindingFilter>("all");
  useEffect(() => {
    if (persistence !== "browser") {
      for (const key of Object.keys(window.localStorage)) {
        if (key.startsWith("entra-threat-workspace:")) window.localStorage.removeItem(key);
      }
      setRecords({});
      return;
    }
    try { setRecords(JSON.parse(window.localStorage.getItem(storageKey) ?? "{}") as Record<string, ReviewRecord>); } catch { setRecords({}); }
    const restored = window.localStorage.getItem(`${storageKey}:selected`);
    if (restored && intelligence.findings.some((finding) => finding.id === restored)) setSelectedId(restored);
  }, [intelligence.findings, persistence, storageKey]);
  useEffect(() => {
    if (persistence !== "server" || !selectedId) return;
    void fetch(`/api/v1/threat-reviews/${encodeURIComponent(selectedId)}`, { cache: "no-store" }).then(async (response) => {
      if (!response.ok) return;
      const payload = await response.json() as { review?: ThreatReview | null; priorReview?: ThreatReview | null };
      if (payload.review) setRecords((current) => ({ ...current, [selectedId]: toReviewRecord(payload.review!) }));
      if (payload.priorReview) setPriorRecords((current) => ({ ...current, [selectedId]: payload.priorReview! }));
    });
  }, [persistence, selectedId]);
  // The panel has no save button: every edit is written to the tenant record
  // after a short debounce. A rejected write (a disposition the server refuses,
  // an expired session, an unreachable backend) must never look like a saved
  // decision, so the outcome of that request is always reported here.
  useEffect(() => {
    if (persistence !== "server" || !pendingReview) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void fetch(`/api/v1/threat-reviews/${encodeURIComponent(pendingReview.id)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(pendingReview.record) }).then(async (response) => {
        if (cancelled) return;
        if (response.ok) { setSaveState({ status: "saved" }); return; }
        const payload = await response.json().catch(() => null) as { error?: string } | null;
        setSaveState({ status: "error", message: payload?.error ?? `The tenant record rejected this change (HTTP ${response.status}). It remains only in this open page until you retry.` });
      }).catch(() => { if (!cancelled) setSaveState({ status: "error", message: "The tenant record is unreachable. This decision remains only in this open page until you retry." }); });
    }, 350);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [pendingReview, persistence]);
  const lifecycleById = useMemo(() => new Map(lifecycle.records.map((record) => [record.finding.id, record.status])), [lifecycle.records]);
  const acceptanceDue = (review: ThreatReview | undefined) => review?.disposition === "accepted" && Boolean(review.expiresAt) && review.expiresAt! <= addDays(today, 30);
  const visible = useMemo(() => intelligence.findings.filter((finding) => {
    if (filter === "all") return true;
    if (filter === "missing") return finding.evidenceClass === "missing";
    if (filter === "new" || filter === "ongoing" || filter === "returned") return lifecycleById.get(finding.id) === filter;
    if (filter === "acceptance-due") return acceptanceDue(priorRecords[finding.id]);
    return finding.severity === filter;
  }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.title.localeCompare(b.title)), [filter, intelligence.findings, lifecycleById, priorRecords]);
  const selected = intelligence.findings.find((finding) => finding.id === selectedId) ?? visible[0] ?? intelligence.findings[0];
  const selectedPath = selected?.attackPathId ? intelligence.paths.find((path) => path.id === selected.attackPathId) : null;
  const record = selected ? { ...EMPTY, ...(records[selected.id] ?? {}) } : EMPTY;
  const selectedLifecycle = selected ? lifecycleById.get(selected.id) ?? "new" : "new";
  const selectedPrior = selected ? priorRecords[selected.id] : undefined;
  function updateRecord(patch: Partial<ReviewRecord>) {
    if (!selected) return;
    setRecords((current) => {
      const next = { ...current, [selected.id]: { ...(current[selected.id] ?? EMPTY), ...patch } };
      if (persistence === "browser") window.localStorage.setItem(storageKey, JSON.stringify(next));
      if (persistence === "server") setPendingReview({ id: selected.id, record: next[selected.id]! });
      return next;
    });
    setSaveState(persistence === "server" ? { status: "saving" } : { status: "saved" });
  }
  function selectFinding(id: string) { setSelectedId(id); setSaveState({ status: "idle" }); if (persistence === "browser") window.localStorage.setItem(`${storageKey}:selected`, id); }
  function beginFlowDraft() { if (!selectedPath) return; updateRecord({ flowDraft: selectedPath.steps.map((item) => ({ id: item.edgeId, title: item.explanation, evidenceEdgeId: item.edgeId })) }); }
  function updateFlowStep(index: number, patch: Partial<FlowDraftStep>) { updateRecord({ flowDraft: record.flowDraft.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item) }); }
  function moveFlowStep(index: number, offset: -1 | 1) { const target = index + offset; if (target < 0 || target >= record.flowDraft.length) return; const next = [...record.flowDraft]; const item = next[index]!; next[index] = next[target]!; next[target] = item; updateRecord({ flowDraft: next }); }
  async function revalidatePrior() {
    if (!selected || !selectedPrior) return;
    setSaveState({ status: "saving" });
    try {
      const response = await fetch(`/api/v1/threat-reviews/${encodeURIComponent(selected.id)}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sourceSnapshotId: selectedPrior.snapshotId }) });
      const payload = await response.json().catch(() => null) as { review?: ThreatReview; error?: string } | null;
      if (!response.ok || !payload?.review) { setSaveState({ status: "error", message: payload?.error ?? `Revalidation failed (HTTP ${response.status}).` }); return; }
      setRecords((current) => ({ ...current, [selected.id]: toReviewRecord(payload.review!) }));
      setSaveState({ status: "saved" });
    } catch { setSaveState({ status: "error", message: "The tenant record is unreachable. The prior decision was not revalidated." }); }
  }

  return <>
    <section className="summary-strip intelligence-summary" aria-label="IAM intelligence summary">
      <button type="button" onClick={() => setFilter("critical")} aria-pressed={filter === "critical"}><strong>{intelligence.counts.critical}</strong><span>Critical</span><small>Directory escalation</small></button>
      <button type="button" onClick={() => setFilter("high")} aria-pressed={filter === "high"}><strong>{intelligence.counts.high}</strong><span>High</span><small>Powerful reachable access</small></button>
      <button type="button" onClick={() => setFilter("medium")} aria-pressed={filter === "medium"}><strong>{intelligence.counts.medium}</strong><span>Review</span><small>Consent and ownership</small></button>
      <button type="button" onClick={() => setFilter("missing")} aria-pressed={filter === "missing"}><strong>{intelligence.evidence.missing}</strong><span>Evidence gaps</span><small>Prevent false reassurance</small></button>
    </section>
    <div className="lifecycle-filters" aria-label="Finding lifecycle filters">
      <strong>Since retained scans</strong>
      {(["new", "ongoing", "returned"] as const).map((status) => <button key={status} type="button" onClick={() => setFilter(status)} aria-pressed={filter === status}><span>{lifecycle.counts[status]}</span>{status}</button>)}
      <button type="button" onClick={() => setFilter("acceptance-due")} aria-pressed={filter === "acceptance-due"}><span>{Object.values(priorRecords).filter(acceptanceDue).length}</span>acceptance due</button>
    </div>
    <div className="evidence-separation" role="note"><span className="evidence-configured"><i />{intelligence.evidence.configured} configured</span><span className="evidence-observed"><i />{intelligence.evidence.observed} observed</span><span className="evidence-inferred"><i />{intelligence.evidence.inferred} inferred</span><span className="evidence-missing"><i />{intelligence.evidence.missing} missing</span><p>{intelligence.pathAnalysis.truncated ? "Attack-path analysis reached its safety limit; review the displayed highest-priority paths as a partial result." : completion === "partial" ? "Partial snapshot: missing data may hide additional paths." : "Complete for the granted core scope; optional activity remains unavailable."}</p></div>
    <div className="threat-workspace">
      <aside className="finding-queue" aria-label="Prioritized findings"><div className="queue-heading"><div><p className="eyebrow">Prioritized queue</p><h2>{visible.length} findings</h2></div>{filter !== "all" ? <button type="button" className="text-button" onClick={() => setFilter("all")}>Show all</button> : null}</div>{visible.map((finding) => <FindingButton key={finding.id} finding={finding} lifecycle={lifecycleById.get(finding.id) ?? "new"} prior={priorRecords[finding.id]} acceptanceDue={acceptanceDue(priorRecords[finding.id])} active={selected?.id === finding.id} disposition={(records[finding.id] ?? EMPTY).disposition} onClick={() => selectFinding(finding.id)} />)}</aside>
      <section className="finding-detail" aria-live="polite">{selected ? <>
        <header className="finding-detail-header"><div><span className={`severity-pill severity-${selected.severity}`}>{selected.severity}</span><span className={`evidence-chip evidence-${selected.evidenceClass}`}>{evidenceLabel[selected.evidenceClass]}</span><span className={`lifecycle-chip lifecycle-${selectedLifecycle}`}>{selectedLifecycle}</span><h2>{selected.title}</h2><p>{selected.summary}</p></div><div className="detail-actions"><Link className="button button-secondary" href={`/api/export/findings.csv?finding=${encodeURIComponent(selected.id)}`}>Export CSV</Link><Link className="button button-secondary" href="/api/export/report.html">Client report</Link>{selectedPath ? <Link className="button button-secondary" href={`/api/export/attack-flow.json?path=${encodeURIComponent(selectedPath.id)}`}>Attack Flow</Link> : null}{selected.edgeIds[0] ? <Link className="button button-primary" href={`/map?edge=${encodeURIComponent(selected.edgeIds[0])}`}>Inspect evidence</Link> : null}</div></header>
        <div className="finding-columns"><div><section className="detail-section"><h3>Why this matters</h3><p>{selected.whyItMatters}</p></section>
          {selectedPath ? <section className="detail-section"><div className="section-heading compact"><div><h3>Multi-stage attack flow</h3><p>{selectedPath.confidence} confidence · {record.flowDraft.length || selectedPath.steps.length} {record.flowDraft.length ? "review" : "configured"} steps</p></div>{record.flowDraft.length === 0 ? <button type="button" className="text-button" onClick={beginFlowDraft}>Edit a review copy</button> : <button type="button" className="text-button" onClick={() => updateRecord({ flowDraft: [] })}>Reset to evidence</button>}</div>{record.flowDraft.length > 0 ? <ol className="attack-flow flow-editor">{record.flowDraft.map((item, index) => <li key={item.id}><span>{index + 1}</span><div><label>Step narrative<input value={item.title} onChange={(event) => updateFlowStep(index, { title: event.target.value })} /></label><small>{item.evidenceEdgeId ? `Evidence edge: ${item.evidenceEdgeId}` : "Analyst-authored step; no evidence edge"}</small><div className="flow-controls"><button type="button" onClick={() => moveFlowStep(index, -1)} disabled={index === 0}>Move up</button><button type="button" onClick={() => moveFlowStep(index, 1)} disabled={index === record.flowDraft.length - 1}>Move down</button><button type="button" onClick={() => updateRecord({ flowDraft: record.flowDraft.filter((_, itemIndex) => itemIndex !== index) })}>Remove</button></div></div></li>)}</ol> : <ol className="attack-flow">{selectedPath.steps.map((item) => <li key={item.edgeId}><span>{item.index + 1}</span><div><strong>{item.explanation}</strong>{item.permissions.length ? <p className="mono">{item.permissions.join(" · ")}</p> : null}<small>{item.source.id} → {item.target.id}</small><code>{item.sourceEndpoint}</code></div></li>)}</ol>}{record.flowDraft.length > 0 ? <button type="button" className="button button-secondary" onClick={() => updateRecord({ flowDraft: [...record.flowDraft, { id: `analyst-${Date.now()}`, title: "Describe the analyst-authored step", evidenceEdgeId: null }] })}>Add analyst step</button> : null}<div className="attack-tags">{selectedPath.attackMappings.map((mapping) => <span key={mapping.id}>{mapping.id} · {mapping.name}</span>)}</div></section> : null}
          <section className="detail-section"><h3>Recommended action</h3><ol className="remediation-list">{selected.remediation.map((item) => <li key={item}>{item}</li>)}</ol></section><section className="detail-section uncertainty"><h3>Residual uncertainty</h3>{selected.uncertainty.map((item) => <p key={item}>{item}</p>)}</section></div>
          <aside className="review-panel" aria-label="Finding decision"><p className="eyebrow">Decision record</p><h3>Review this risk</h3>{selectedPrior && !records[selected.id] ? <div className={`prior-review-note ${selectedPrior.disposition === "resolved" || acceptanceDue(selectedPrior) ? "warning" : ""}`}><strong>{selectedPrior.disposition === "resolved" ? `Previously resolved, but ${selectedLifecycle === "ongoing" ? "still" : "again"} detected.` : acceptanceDue(selectedPrior) ? `Prior acceptance ${selectedPrior.expiresAt! < today ? "expired" : "expires soon"}.` : "A prior decision is available."}</strong><p>{selectedPrior.owner ? `Owner: ${selectedPrior.owner}. ` : ""}It belongs to snapshot <code>{selectedPrior.snapshotId}</code> and is context only until you revalidate it.</p><button type="button" className="button button-secondary" onClick={revalidatePrior}>{selectedPrior.disposition === "resolved" || (selectedPrior.disposition === "accepted" && selectedPrior.expiresAt! < today) ? "Reopen from prior context" : "Revalidate for this scan"}</button></div> : null}<label>Status<select value={record.disposition} onChange={(event) => updateRecord({ disposition: event.target.value as Disposition })}><option value="open">Open</option><option value="mitigating">Mitigating</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option></select></label><label>Owner<input value={record.owner} onChange={(event) => updateRecord({ owner: event.target.value })} placeholder="Team or person" /></label><label>Review / acceptance expiry<input type="date" value={record.expiresAt} onChange={(event) => updateRecord({ expiresAt: event.target.value })} /></label><label>Assumptions and notes<textarea rows={6} value={record.assumption} onChange={(event) => updateRecord({ assumption: event.target.value })} placeholder="What must remain true? Why is this accepted or mitigated?" /></label><p className={`record-save-state ${saveState.status}`} role="status" aria-live="polite">{saveState.status === "saving" ? "Saving the decision…" : saveState.status === "saved" ? (persistence === "server" ? "Decision registered in the tenant record." : "Decision saved in this browser.") : saveState.status === "error" ? saveState.message : "There is no save button: every change is registered as you make it. Accepting a risk requires an owner, an expiry date, and a rationale."}</p><p className="local-record-note"><strong>{persistence === "server" ? "Encrypted and tenant-scoped." : "Saved in this browser only."}</strong> Review decisions never modify Microsoft Entra.{persistence === "server" ? " Authenticated team members in this tenant share the PostgreSQL record." : " Connect a tenant to share decision records with your team."}</p><dl><div><dt>Tenant</dt><dd>{tenantLabel}</dd></div><div><dt>Snapshot</dt><dd><code>{snapshotId}</code></dd></div><div><dt>Finding ID</dt><dd><code>{selected.id}</code></dd></div></dl></aside>
        </div>
      </> : <div className="map-empty compact"><h2>No findings match</h2><p>Clear the current filter to return to the prioritized queue.</p></div>}</section>
    </div>
  </>;
}

function FindingButton({ finding, lifecycle, prior, acceptanceDue, active, disposition, onClick }: { finding: IamFinding; lifecycle: FindingLifecycleStatus; prior?: ThreatReview; acceptanceDue: boolean; active: boolean; disposition: Disposition; onClick: () => void }) {
  const priorWarning = prior?.disposition === "resolved" ? "resolved before" : acceptanceDue ? "acceptance due" : null;
  return <button type="button" className={`finding-button ${active ? "active" : ""}`} onClick={onClick} aria-pressed={active}><span className={`severity-mark severity-${finding.severity}`} aria-hidden="true" /><span><strong>{finding.title}</strong><small>{finding.category.replaceAll("-", " ")} · {evidenceLabel[finding.evidenceClass]} · {lifecycle}{priorWarning ? ` · ${priorWarning}` : ""}</small></span><em>{disposition}</em></button>;
}

function addDays(date: string, days: number): string {
  const value = new Date(`${date}T00:00:00.000Z`);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}
