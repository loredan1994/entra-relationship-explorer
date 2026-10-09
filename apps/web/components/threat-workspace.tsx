"use client";

import type { ThreatReview } from "@entra-explorer/backend";
import { COLLECTORS, type coverageMatrix } from "@entra-explorer/domain";
import type { FindingLifecycle, FindingLifecycleStatus, IamFinding, TenantIntelligence } from "@entra-explorer/domain";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ThreatReviewSummary } from "@/server/current-snapshot";

type Disposition = "open" | "mitigating" | "accepted" | "resolved";
interface FlowDraftStep { id: string; title: string; evidenceEdgeId: string | null; }
interface ReviewRecord { disposition: Disposition; owner: string; expiresAt: string; assumption: string; flowDraft: FlowDraftStep[]; }
interface SaveState { status: "idle" | "saving" | "saved" | "error"; message?: string; }
type FindingFilter = "all" | "critical" | "high" | "medium" | "missing" | "new" | "ongoing" | "returned" | "acceptance-due";
const EMPTY: ReviewRecord = { disposition: "open", owner: "", expiresAt: "", assumption: "", flowDraft: [] };
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;
const evidenceLabel = { configured: "Configured access", observed: "Observed activity", inferred: "Inferred possibility", missing: "Missing evidence" } as const;

const toReviewRecord = (review: ThreatReview): ReviewRecord => ({ disposition: review.disposition, owner: review.owner, expiresAt: review.expiresAt ?? "", assumption: review.assumption, flowDraft: review.flowDraft ?? [] });

export function ThreatWorkspace({ coverage, intelligence, lifecycle, currentReviews, priorReviews, today, tenantLabel, snapshotId, completion, persistence }: { coverage: ReturnType<typeof coverageMatrix>; intelligence: TenantIntelligence; lifecycle: FindingLifecycle; currentReviews: ThreatReviewSummary[]; priorReviews: ThreatReview[]; today: string; tenantLabel: string; snapshotId: string; completion: "complete" | "partial"; persistence: "server" | "browser" }) {
  const storageKey = `entra-threat-workspace:${snapshotId}`;
  const [selectedId, setSelectedId] = useState(intelligence.findings[0]?.id ?? "");
  const [records, setRecords] = useState<Record<string, ReviewRecord>>({});
  const currentSummaries = useMemo(() => Object.fromEntries(currentReviews.map(review => [review.findingId, review])), [currentReviews]);
  const [revisions, setRevisions] = useState<Record<string, string | null>>({});
  const [loaded, setLoaded] = useState<Record<string, boolean>>({});
  const dirty = useRef(new Set<string>());
  const [saveStates, setSaveStates] = useState<Record<string, SaveState>>({});
  const pending = useRef(new Set<string>());
  function setFindingSaveState(id: string, state: SaveState) {
    setSaveStates(current => ({ ...current, [id]: state }));
  }
  const [priorRecords, setPriorRecords] = useState<Record<string, ThreatReview>>(() => Object.fromEntries(priorReviews.map((review) => [review.findingId, review])));
  const [filter, setFilter] = useState<FindingFilter>("all");
  useEffect(() => {
    if (persistence !== "browser") {
      for (const key of Object.keys(window.localStorage)) {
        if (key.startsWith("entra-threat-workspace:")) window.localStorage.removeItem(key);
      }
      return;
    }
    try { setRecords(JSON.parse(window.localStorage.getItem(storageKey) ?? "{}") as Record<string, ReviewRecord>); } catch { setRecords({}); }
    const restored = window.localStorage.getItem(`${storageKey}:selected`);
    if (restored && intelligence.findings.some((finding) => finding.id === restored)) setSelectedId(restored);
  }, [intelligence.findings, persistence, storageKey]);
  useEffect(() => {
    if (persistence !== "server" || !selectedId || loaded[selectedId] || pending.current.has(selectedId)) return;
    const controller = new AbortController();
    void fetch(`/api/v1/threat-reviews/${encodeURIComponent(selectedId)}?snapshot=${encodeURIComponent(snapshotId)}`, { cache: "no-store", signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Review load failed");
      const payload = await response.json() as { review?: ThreatReview | null; priorReview?: ThreatReview | null };
      if (controller.signal.aborted || dirty.current.has(selectedId) || pending.current.has(selectedId)) return;
      setLoaded(current => ({ ...current, [selectedId]: true }));
      setRevisions(current => ({ ...current, [selectedId]: payload.review ? payload.review.revision ?? "" : null }));
      if (payload.review) setRecords((current) => ({ ...current, [selectedId]: toReviewRecord(payload.review!) }));
      if (payload.priorReview) setPriorRecords((current) => ({ ...current, [selectedId]: payload.priorReview! }));
    }).catch(() => {
      if (!controller.signal.aborted) setFindingSaveState(selectedId, { status: "error", message: "The review could not be loaded. Reload the page before saving." });
    });
    return () => controller.abort();
  }, [persistence, selectedId, snapshotId, loaded]);
  const lifecycleById = useMemo(() => new Map(lifecycle.records.map((record) => [record.finding.id, record.status])), [lifecycle.records]);
  const acceptanceDue = (review: ReviewRecord | ThreatReview | ThreatReviewSummary | undefined) => review?.disposition === "accepted" && Boolean(review.expiresAt) && review.expiresAt! <= addDays(today, 30);
  const visible = useMemo(() => intelligence.findings.filter((finding) => {
    if (filter === "all") return true;
    if (filter === "missing") return finding.evidenceClass === "missing";
    if (filter === "new" || filter === "ongoing" || filter === "returned") return lifecycleById.get(finding.id) === filter;
    if (filter === "acceptance-due") return acceptanceDue(records[finding.id] ?? currentSummaries[finding.id] ?? priorRecords[finding.id]);
    return finding.severity === filter;
  }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.title.localeCompare(b.title)), [filter, intelligence.findings, lifecycleById, priorRecords, records, currentSummaries, today]);
  const selected = visible.find((finding) => finding.id === selectedId) ?? visible[0];
  const activeId = selected?.id ?? "";
  const saveState = saveStates[activeId] ?? { status: "idle" };
  useEffect(() => { if (selectedId !== activeId) setSelectedId(activeId); }, [activeId, selectedId]);
  const selectedPath = selected?.attackPathId ? intelligence.paths.find((path) => path.id === selected.attackPathId) : null;
  const record = selected ? { ...EMPTY, ...(records[selected.id] ?? {}) } : EMPTY;
  const selectedLifecycle = selected ? lifecycleById.get(selected.id) ?? "new" : "new";
  const selectedPrior = selected ? priorRecords[selected.id] : undefined;
  function updateRecord(patch: Partial<ReviewRecord>) {
    if (!selected || (persistence === "server" && (!loaded[selected.id] || pending.current.has(selected.id)))) return;
    setRecords((current) => {
      const next = { ...current, [selected.id]: { ...(current[selected.id] ?? EMPTY), ...patch } };
      if (persistence === "browser") window.localStorage.setItem(storageKey, JSON.stringify(next));
      if (persistence === "server") dirty.current.add(selected.id);
      return next;
    });
    setFindingSaveState(selected.id, persistence === "server" ? { status: "idle", message: "Unsaved decision. Choose Save decision to register it." } : { status: "saved" });
  }
  async function saveDecision() {
    if (!selected || !loaded[selected.id] || pending.current.has(selected.id)) return;
    const findingId = selected.id;
    const savedRecord = records[findingId] ?? EMPTY;
    pending.current.add(selected.id);
    setFindingSaveState(selected.id, { status: "saving" });
    try {
      const response = await fetch(`/api/v1/threat-reviews/${encodeURIComponent(findingId)}?snapshot=${encodeURIComponent(snapshotId)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...savedRecord, expectedRevision: revisions[findingId] ?? null }) });
      const payload = await response.json() as { review?: ThreatReview; error?: string };
      if (!response.ok || !payload.review) { setFindingSaveState(selected.id, { status: "error", message: payload.error ?? "The decision was not saved. Reload before retrying." }); return; }
      setRevisions(current => ({ ...current, [findingId]: payload.review!.revision ?? "" }));
      setRecords(current => ({ ...current, [findingId]: toReviewRecord(payload.review!) }));
      dirty.current.delete(findingId);
      setFindingSaveState(selected.id, { status: "saved" });
    } catch { setFindingSaveState(selected.id, { status: "error", message: "The decision was not saved. Your edits remain in this page." }); }
    finally { pending.current.delete(findingId); }
  }
  function selectFinding(id: string) { setSelectedId(id); if (persistence === "browser") window.localStorage.setItem(`${storageKey}:selected`, id); }
  function beginFlowDraft() { if (!selectedPath) return; updateRecord({ flowDraft: selectedPath.steps.map((item) => ({ id: item.edgeId, title: item.explanation, evidenceEdgeId: item.edgeId })) }); }
  function updateFlowStep(index: number, patch: Partial<FlowDraftStep>) { updateRecord({ flowDraft: record.flowDraft.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item) }); }
  function moveFlowStep(index: number, offset: -1 | 1) { const target = index + offset; if (target < 0 || target >= record.flowDraft.length) return; const next = [...record.flowDraft]; const item = next[index]!; next[index] = next[target]!; next[target] = item; updateRecord({ flowDraft: next }); }
  async function revalidatePrior() {
    if (!selected || !selectedPrior) return;
    if (!loaded[selected.id] || pending.current.has(selected.id)) return;
    pending.current.add(selected.id);
    setFindingSaveState(selected.id, { status: "saving" });
    try {
      const response = await fetch(`/api/v1/threat-reviews/${encodeURIComponent(selected.id)}?snapshot=${encodeURIComponent(snapshotId)}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sourceSnapshotId: selectedPrior.snapshotId, expectedRevision: revisions[selected.id] ?? null }) });
      const payload = await response.json().catch(() => null) as { review?: ThreatReview; error?: string } | null;
      if (!response.ok || !payload?.review) { setFindingSaveState(selected.id, { status: "error", message: payload?.error ?? `Revalidation failed (HTTP ${response.status}).` }); return; }
      dirty.current.delete(selected.id);
      setRecords((current) => ({ ...current, [selected.id]: toReviewRecord(payload.review!) }));
      setRevisions(current => ({ ...current, [selected.id]: payload.review!.revision ?? "" }));
      setFindingSaveState(selected.id, { status: "saved" });
    } catch { setFindingSaveState(selected.id, { status: "error", message: "The tenant record is unreachable. The prior decision was not revalidated." }); }
    finally { pending.current.delete(selected.id); }
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
      <button type="button" onClick={() => setFilter("acceptance-due")} aria-pressed={filter === "acceptance-due"}><span>{intelligence.findings.filter(f => acceptanceDue(records[f.id] ?? currentSummaries[f.id] ?? priorRecords[f.id])).length}</span>acceptance due</button>
    </div>
    <div className="evidence-separation" role="note"><span className="evidence-configured"><i />{intelligence.evidence.configured} configured</span><span className="evidence-observed"><i />{intelligence.evidence.observed} observed</span><span className="evidence-inferred"><i />{intelligence.evidence.inferred} inferred</span><span className="evidence-missing"><i />{intelligence.evidence.missing} missing</span><p>{intelligence.pathAnalysis.truncated ? "Attack-path analysis reached its safety limit; displayed paths are a partial result and other higher-priority paths may be missing." : completion === "partial" ? "Partial snapshot: missing data may hide additional paths." : "Collection completed for its recorded scope. See Evidence coverage for optional activity and analysis limits."}</p></div>
    <div className="threat-workspace">
      <aside className="finding-queue" aria-label="Prioritized findings"><div className="queue-heading"><div><p className="eyebrow">Prioritized queue</p><h2>{visible.length} findings</h2></div>{filter !== "all" ? <button type="button" className="text-button" onClick={() => setFilter("all")}>Show all</button> : null}</div>{visible.map((finding) => <FindingButton key={finding.id} finding={finding} lifecycle={lifecycleById.get(finding.id) ?? "new"} prior={priorRecords[finding.id]} acceptanceDue={acceptanceDue(records[finding.id] ?? currentSummaries[finding.id] ?? priorRecords[finding.id])} active={selected?.id === finding.id} disposition={(records[finding.id] ?? currentSummaries[finding.id] ?? EMPTY).disposition} onClick={() => selectFinding(finding.id)} />)}</aside>
      <section className="finding-detail" aria-live="polite">{selected ? <>
        <header className="finding-detail-header"><div><span className={`severity-pill severity-${selected.severity}`}>{selected.severity}</span><span className={`evidence-chip evidence-${selected.evidenceClass}`}>{evidenceLabel[selected.evidenceClass]}</span><span className={`lifecycle-chip lifecycle-${selectedLifecycle}`}>{selectedLifecycle}</span>{selected.rule ? <span className="rule-chip" title={`${selected.rule.title}, version ${selected.rule.version}`}>{selected.rule.id} · v{selected.rule.version}</span> : null}<h2>{selected.title}</h2><p>{selected.summary}</p></div><div className="detail-actions"><Link className="button button-secondary" href={`/api/export/evidence-packet.md?kind=finding&id=${encodeURIComponent(selected.id)}`}>Finding packet · Markdown</Link><Link className="button button-secondary" href={`/api/export/evidence-packet.json?kind=finding&id=${encodeURIComponent(selected.id)}`}>Finding packet · JSON</Link>{selectedPath ? <Link className="button button-secondary" href={`/api/export/attack-flow.json?path=${encodeURIComponent(selectedPath.id)}`}>Attack Flow</Link> : null}{selected.edgeIds[0] ? <Link className="button button-primary" href={`/map?edge=${encodeURIComponent(selected.edgeIds[0])}`}>Inspect evidence</Link> : null}</div></header>
        <div className="finding-columns"><div><section className="detail-section"><h3>Recorded source coverage</h3><ul>{coverage.filter(c => selected.sourceEndpoints.some(endpoint => COLLECTORS.find(d => d.id === c.id)?.prefixes.some(prefix => endpoint.includes(prefix.replace(/\?$/, ""))))).map(c => <li key={c.id}><strong>{c.label}: {c.state.replaceAll("-", " ")}</strong> · {c.reason}</li>)}</ul><Link href="/investigations?view=coverage">Inspect all collector limits and prerequisites</Link></section><section className="detail-section"><h3>Why this matters</h3><p>{selected.whyItMatters}</p></section>
          {selected.rule ? <section className="detail-section rule-detail"><div className="section-heading compact"><div><p className="eyebrow">Control-path rule</p><h3>{selected.rule.id} · {selected.rule.title}</h3></div><span>Version {selected.rule.version}</span></div>{selected.prerequisites?.length ? <><h4>Prerequisites</h4><ul>{selected.prerequisites.map((item) => <li key={item}>{item}</li>)}</ul></> : null}{selected.requiredCoverage?.length ? <><h4>Evidence required to evaluate this rule</h4><ul>{selected.requiredCoverage.map((item) => <li key={item}>{item}</li>)}</ul></> : null}<p className="rule-references"><strong>Public references:</strong> {selected.rule.references.map((reference, index) => <span key={reference}>{index > 0 ? " · " : ""}<a href={reference} target="_blank" rel="noreferrer">Source {index + 1}</a></span>)}</p></section> : null}
          {selectedPath ? <section className="detail-section"><div className="section-heading compact"><div><h3>Multi-stage attack flow</h3><p>{selectedPath.confidence} confidence · {record.flowDraft.length || selectedPath.steps.length} {record.flowDraft.length ? "review" : "configured"} steps</p></div>{record.flowDraft.length === 0 ? <button type="button" className="text-button" onClick={beginFlowDraft}>Edit a review copy</button> : <button type="button" className="text-button" onClick={() => updateRecord({ flowDraft: [] })}>Reset to evidence</button>}</div>{record.flowDraft.length > 0 ? <ol className="attack-flow flow-editor">{record.flowDraft.map((item, index) => <li key={item.id}><span>{index + 1}</span><div><label>Step narrative<input value={item.title} onChange={(event) => updateFlowStep(index, { title: event.target.value })} /></label><small>{item.evidenceEdgeId ? `Evidence edge: ${item.evidenceEdgeId}` : "Analyst-authored step; no evidence edge"}</small><div className="flow-controls"><button type="button" onClick={() => moveFlowStep(index, -1)} disabled={index === 0}>Move up</button><button type="button" onClick={() => moveFlowStep(index, 1)} disabled={index === record.flowDraft.length - 1}>Move down</button><button type="button" onClick={() => updateRecord({ flowDraft: record.flowDraft.filter((_, itemIndex) => itemIndex !== index) })}>Remove</button></div></div></li>)}</ol> : <ol className="attack-flow">{selectedPath.steps.map((item) => <li key={item.edgeId}><span>{item.index + 1}</span><div><strong>{item.explanation}</strong>{item.permissions.length ? <p className="mono">{item.permissions.join(" · ")}</p> : null}<small>{item.source.id} → {item.target.id}</small><code>{item.sourceEndpoint}</code></div></li>)}</ol>}{record.flowDraft.length > 0 ? <button type="button" className="button button-secondary" onClick={() => updateRecord({ flowDraft: [...record.flowDraft, { id: `analyst-${Date.now()}`, title: "Describe the analyst-authored step", evidenceEdgeId: null }] })}>Add analyst step</button> : null}<div className="attack-tags">{selectedPath.attackMappings.map((mapping) => <span key={mapping.id}>{mapping.id} · {mapping.name}</span>)}</div><div className="packet-actions" aria-label="Focused attack path exports"><span>Share only this evidence-backed path:</span><Link href={`/api/export/evidence-packet.md?kind=path&id=${encodeURIComponent(selectedPath.id)}`}>Markdown packet</Link><Link href={`/api/export/evidence-packet.json?kind=path&id=${encodeURIComponent(selectedPath.id)}`}>Versioned JSON</Link></div></section> : null}
          <section className="detail-section"><h3>Recommended action</h3><ol className="remediation-list">{selected.remediation.map((item) => <li key={item}>{item}</li>)}</ol></section><section className="detail-section uncertainty"><h3>Residual uncertainty</h3>{selected.uncertainty.map((item) => <p key={item}>{item}</p>)}</section></div>
          <aside className="review-panel" aria-label="Finding decision"><p className="eyebrow">Decision record</p><h3>Review this risk</h3>{selectedPrior && !records[selected.id] && !currentSummaries[selected.id] ? <div className={`prior-review-note ${selectedPrior.disposition === "resolved" || acceptanceDue(selectedPrior) ? "warning" : ""}`}><strong>{selectedPrior.disposition === "resolved" ? `Previously resolved, but ${selectedLifecycle === "ongoing" ? "still" : "again"} detected.` : acceptanceDue(selectedPrior) ? `Prior acceptance ${selectedPrior.expiresAt! < today ? "expired" : "expires soon"}.` : "A prior decision is available."}</strong><p>{selectedPrior.owner ? `Owner: ${selectedPrior.owner}. ` : ""}It belongs to snapshot <code>{selectedPrior.snapshotId}</code> and is context only until you revalidate it.</p><button type="button" className="button button-secondary" disabled={!loaded[selected.id] || saveState.status === "saving"} onClick={revalidatePrior}>{selectedPrior.disposition === "resolved" || (selectedPrior.disposition === "accepted" && selectedPrior.expiresAt! < today) ? "Reopen from prior context" : "Revalidate for this scan"}</button></div> : null}<fieldset disabled={saveState.status === "saving" || (persistence === "server" && !loaded[selected.id])}><label>Status<select value={record.disposition} onChange={(event) => updateRecord({ disposition: event.target.value as Disposition })}><option value="open">Open</option><option value="mitigating">Mitigating</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option></select></label><label>Owner<input value={record.owner} onChange={(event) => updateRecord({ owner: event.target.value })} placeholder="Team or person" /></label><label>Review / acceptance expiry<input type="date" value={record.expiresAt} onChange={(event) => updateRecord({ expiresAt: event.target.value })} /></label><label>Assumptions and notes<textarea rows={6} value={record.assumption} onChange={(event) => updateRecord({ assumption: event.target.value })} placeholder="What must remain true? Why is this accepted or mitigated?" /></label></fieldset>{persistence === "server" ? <button type="button" className="button button-primary" disabled={!loaded[selected.id] || saveState.status === "saving"} onClick={saveDecision}>Save decision</button> : null}<p className={`record-save-state ${saveState.status}`} role="status" aria-live="polite">{saveState.status === "saving" ? "Saving the decision…" : saveState.status === "saved" ? (persistence === "server" ? "Decision registered in the tenant record." : "Decision saved in this browser.") : saveState.status === "error" ? saveState.message : saveState.message ?? (persistence === "server" ? "Save explicitly after reviewing this snapshot. Accepted risk requires an owner, expiry and rationale." : "Changes are saved in this browser. Accepted risk requires an owner, expiry and rationale.")}</p><p className="local-record-note"><strong>{persistence === "server" ? "Encrypted and tenant-scoped." : "Saved in this browser only."}</strong> Review decisions never modify Microsoft Entra.{persistence === "server" ? " Authenticated team members in this tenant share the PostgreSQL record." : " Connect a tenant to share decision records with your team."}</p><dl><div><dt>Tenant</dt><dd>{tenantLabel}</dd></div><div><dt>Snapshot</dt><dd><code>{snapshotId}</code></dd></div><div><dt>Finding ID</dt><dd><code>{selected.id}</code></dd></div></dl></aside>
        </div>
      </> : <div className="map-empty compact"><h2>No findings match</h2><p>Clear the current filter to return to the prioritized queue.</p></div>}</section>
    </div>
  </>;
}

function FindingButton({ finding, lifecycle, prior, acceptanceDue, active, disposition, onClick }: { finding: IamFinding; lifecycle: FindingLifecycleStatus; prior?: ThreatReview; acceptanceDue: boolean; active: boolean; disposition: Disposition; onClick: () => void }) {
  const priorWarning = prior?.disposition === "resolved" ? "resolved before" : acceptanceDue ? "acceptance due" : null;
  return <button type="button" className={`finding-button ${active ? "active" : ""}`} onClick={onClick} aria-pressed={active}><span className={`severity-mark severity-${finding.severity}`} aria-hidden="true" /><span><strong>{finding.title}</strong><small>{finding.rule ? `${finding.rule.id} · ` : ""}{finding.category.replaceAll("-", " ")} · {evidenceLabel[finding.evidenceClass]} · {lifecycle}{priorWarning ? ` · ${priorWarning}` : ""}</small></span><em>{disposition}</em></button>;
}

function addDays(date: string, days: number): string {
  const value = new Date(`${date}T00:00:00.000Z`);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}
