"use client";

import type { ThreatReview } from "@entra-explorer/backend";
import { COLLECTORS, type coverageMatrix } from "@entra-explorer/domain";
import type { FindingLifecycle, FindingLifecycleStatus, IamFinding, TenantIntelligence } from "@entra-explorer/domain";
import Link from "next/link";
import { ExportLink } from "./export-link";
import { useEffect, useMemo, useRef, useState } from "react";
import { createThreatFlowDraft } from "@/lib/threat-review-flow";
import { THREAT_REVIEW_LIMITS } from "@/lib/threat-review-limits";
import type { ThreatReviewSummary } from "@/server/current-snapshot";
import { EMPTY_REVIEW as EMPTY, mergeBrowserReviewDrafts, restoreBrowserReviews, type BrowserReviewDraft, type Disposition, type FlowDraftStep, type ReviewRecord } from "./threat-review-storage";

interface SaveState { status: "idle" | "saving" | "saved" | "error"; message?: string; }
type FindingFilter = "all" | "critical" | "high" | "medium" | "missing" | "new" | "ongoing" | "returned" | "acceptance-due" | "ownership";
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;
const evidenceLabel = { configured: "Configured access", observed: "Observed activity", inferred: "Inferred possibility", missing: "Missing evidence" } as const;

const toReviewRecord = (review: ThreatReview): ReviewRecord => ({ disposition: review.disposition, owner: review.owner, expiresAt: review.expiresAt ?? "", assumption: review.assumption, flowDraft: review.flowDraft ?? [] });

export function ThreatWorkspace({ coverage, intelligence, lifecycle, currentReviews, priorReviews, today, tenantLabel, snapshotId, completion, persistence, initialSelectedId, initialCategory }: { initialSelectedId?: string; initialCategory?: "ownership"; coverage: ReturnType<typeof coverageMatrix>; intelligence: TenantIntelligence; lifecycle: FindingLifecycle; currentReviews: ThreatReviewSummary[]; priorReviews: ThreatReview[]; today: string; tenantLabel: string; snapshotId: string; completion: "complete" | "partial"; persistence: "server" | "browser" }) {
  const storageKey = `entra-threat-workspace:${snapshotId}`;
  const [selectedId, setSelectedId] = useState(initialSelectedId ?? intelligence.findings[0]?.id ?? "");
  const [records, setRecords] = useState<Record<string, ReviewRecord>>({});
  const [storageWarning, setStorageWarning] = useState("");
  const browserDrafts = useRef<Record<string, BrowserReviewDraft>>({});
  const [browserConflicts, setBrowserConflicts] = useState<string[]>([]);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  function withBrowserDrafts(saved: Record<string, ReviewRecord>) {
    return { ...saved, ...Object.fromEntries(Object.entries(browserDrafts.current).map(([id, draft]) => [id, { ...(saved[id] ?? EMPTY), ...draft.changes }])) };
  }
  const currentSummaries = useMemo(() => Object.fromEntries(currentReviews.map(review => [review.findingId, review])), [currentReviews]);
  const [revisions, setRevisions] = useState<Record<string, string | null>>({});
  const [loaded, setLoaded] = useState<Record<string, boolean>>({});
  const [loadAttempt, setLoadAttempt] = useState(0);
  const dirty = useRef(new Set<string>());
  const [saveStates, setSaveStates] = useState<Record<string, SaveState>>({});
  const pending = useRef(new Set<string>());
  const detailRef = useRef<HTMLElement>(null);
  const queueRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!initialSelectedId) return;
    detailRef.current?.focus({ preventScroll: true });
    detailRef.current?.scrollIntoView({ block: "start" });
  }, [initialSelectedId]);
  function setFindingSaveState(id: string, state: SaveState) {
    setSaveStates(current => ({ ...current, [id]: state }));
  }
  const [priorRecords, setPriorRecords] = useState<Record<string, ThreatReview>>(() => Object.fromEntries(priorReviews.map((review) => [review.findingId, review])));
  const [filter, setFilter] = useState<FindingFilter>(initialCategory ?? "all");
  useEffect(() => {
    if (persistence !== "browser") {
      try {
        for (const key of Object.keys(window.localStorage)) {
          if (key.startsWith("entra-threat-workspace:")) window.localStorage.removeItem(key);
        }
      } catch { /* Tenant reviews never depend on browser storage access. */ }
      return;
    }
    const refresh = () => {
      try {
        const restoredRecords = restoreBrowserReviews(window.localStorage.getItem(storageKey), intelligence.findings.map(finding => finding.id));
        setRecords(withBrowserDrafts(restoredRecords.records));
        setStorageWarning(restoredRecords.discarded ? "Some saved review data was invalid and could not be restored. Valid decisions remain available; review the affected findings again." : "");
      } catch { setStorageWarning("Browser storage is unavailable. You can continue reviewing in this page, but changes will not survive a reload or navigation."); }
    };
    const onStorage = (event: StorageEvent) => { if (event.key === storageKey || event.key === null) refresh(); };
    const onLocalSave = (event: Event) => { if ((event as CustomEvent<string>).detail === storageKey) refresh(); };
    // Subscribe even when initial access fails; a later successful retry must restore synchronization.
    window.addEventListener("storage", onStorage);
    window.addEventListener("entra-review-saved", onLocalSave);
    refresh();
    try {
      const restored = window.localStorage.getItem(`${storageKey}:selected`);
      if (!initialSelectedId && !initialCategory && restored && intelligence.findings.some(finding => finding.id === restored)) setSelectedId(restored);
    } catch { setStorageWarning(current => current || "Browser storage is unavailable. The selected finding cannot be remembered after a reload."); }
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener("entra-review-saved", onLocalSave); };
  }, [initialSelectedId, initialCategory, intelligence.findings, persistence, storageKey]);
  useEffect(() => {
    if (persistence !== "server" || !selectedId || loaded[selectedId] || pending.current.has(selectedId)) return;
    const controller = new AbortController();
    setFindingSaveState(selectedId, { status: "idle" });
    void fetch(`/api/v1/threat-reviews/${encodeURIComponent(selectedId)}?snapshot=${encodeURIComponent(snapshotId)}`, { cache: "no-store", signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Review load failed");
      const payload = await response.json() as { review?: ThreatReview | null; priorReview?: ThreatReview | null };
      if (controller.signal.aborted || dirty.current.has(selectedId) || pending.current.has(selectedId)) return;
      setLoaded(current => ({ ...current, [selectedId]: true }));
      setRevisions(current => ({ ...current, [selectedId]: payload.review ? payload.review.revision ?? "" : null }));
      if (payload.review) setRecords((current) => ({ ...current, [selectedId]: toReviewRecord(payload.review!) }));
      if (payload.priorReview) setPriorRecords((current) => ({ ...current, [selectedId]: payload.priorReview! }));
    }).catch(() => {
      if (!controller.signal.aborted) setFindingSaveState(selectedId, { status: "error", message: "The review could not be loaded. Retry without leaving this page; your other unsaved decisions will remain." });
    });
    return () => controller.abort();
  }, [persistence, selectedId, snapshotId, loaded, loadAttempt]);
  const lifecycleById = useMemo(() => new Map(lifecycle.records.map((record) => [record.finding.id, record.status])), [lifecycle.records]);
  const acceptanceDue = (review: ReviewRecord | ThreatReview | ThreatReviewSummary | undefined) => review?.disposition === "accepted" && Boolean(review.expiresAt) && review.expiresAt! <= addDays(today, 30);
  const visible = useMemo(() => intelligence.findings.filter((finding) => {
    if (filter === "all") return true;
    if (filter === "ownership") return finding.category === "ownership";
    if (filter === "missing") return finding.evidenceClass === "missing";
    if (filter === "new" || filter === "ongoing" || filter === "returned") return lifecycleById.get(finding.id) === filter;
    if (filter === "acceptance-due") return acceptanceDue(records[finding.id] ?? currentSummaries[finding.id] ?? priorRecords[finding.id]);
    return finding.severity === filter;
  }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.title.localeCompare(b.title)), [filter, intelligence.findings, lifecycleById, priorRecords, records, currentSummaries, today]);
  const selected = visible.find((finding) => finding.id === selectedId) ?? visible[0];
  const activeId = selected?.id ?? "";
  const saveState = saveStates[activeId] ?? { status: "idle" };
  useEffect(() => { if (selectedId !== activeId) setSelectedId(activeId); }, [activeId, selectedId]);
  const reviewLoading = persistence === "server" && Boolean(activeId) && !loaded[activeId];
  const editingDisabled = reviewLoading || (persistence === "server" && saveState.status === "saving");
  const selectedPath = selected?.attackPathId ? intelligence.paths.find((path) => path.id === selected.attackPathId) : null;
  const record = selected ? { ...EMPTY, ...(records[selected.id] ?? {}) } : EMPTY;
  const selectedLifecycle = selected ? lifecycleById.get(selected.id) ?? "new" : "new";
  const selectedPrior = selected ? priorRecords[selected.id] : undefined;
  function updateRecord(patch: Partial<ReviewRecord>) {
    if (!selected || (persistence === "server" && (!loaded[selected.id] || pending.current.has(selected.id)))) return;
    if (persistence === "server") {
      setRecords(current => ({ ...current, [selected.id]: { ...(current[selected.id] ?? EMPTY), ...patch } }));
      dirty.current.add(selected.id);
      setFindingSaveState(selected.id, { status: "idle", message: "Unsaved decision. Choose Save decision to register it." });
      return;
    }
    const draft = browserDrafts.current[selected.id];
    const currentRecord = records[selected.id] ?? EMPTY;
    const original = { ...(draft?.original ?? currentRecord) };
    for (const field of Object.keys(patch) as Array<keyof ReviewRecord>) {
      if (!Object.hasOwn(draft?.changes ?? {}, field)) Object.assign(original, { [field]: currentRecord[field] });
    }
    browserDrafts.current[selected.id] = { original, changes: { ...draft?.changes, ...patch } };
    setRecords(current => ({ ...current, [selected.id]: { ...(current[selected.id] ?? EMPTY), ...patch } }));
    setFindingSaveState(selected.id, { status: "saving" });
    void persistBrowserRecords();
  }
  async function persistBrowserRecords() {
    try {
      if (!navigator.locks) throw new Error("Browser review locking is unavailable");
      // One origin-wide lock covers the read/merge/write so simultaneous tabs cannot erase each other.
      await navigator.locks.request(storageKey, () => {
        const ids = Object.keys(browserDrafts.current);
        if (!ids.length) return;
        const saved = restoreBrowserReviews(window.localStorage.getItem(storageKey), intelligence.findings.map(finding => finding.id));
        const merged = mergeBrowserReviewDrafts(saved.records, browserDrafts.current);
        window.localStorage.setItem(storageKey, JSON.stringify(merged.records));
        for (const id of ids) if (!merged.conflicts.includes(id)) delete browserDrafts.current[id];
        // Native storage events skip this window, including a remounted workspace in the same tab.
        window.dispatchEvent(new CustomEvent("entra-review-saved", { detail: storageKey }));
        // A requested save survives client navigation; only updates to the departed UI are skipped.
        if (!mounted.current) return;
        setRecords(withBrowserDrafts(merged.records));
        setBrowserConflicts(merged.conflicts);
        setStorageWarning(current => current.startsWith("Browser storage is unavailable.") ? "" : current);
        setSaveStates(current => ({ ...current, ...Object.fromEntries(ids.map(id => [id, merged.conflicts.includes(id)
          ? { status: "error", message: "Another tab changed this decision. Your unsaved edits remain here. Reload the saved decision to use its latest values before editing again." }
          : { status: "saved" }])) }));
      });
    } catch {
      if (!mounted.current) return;
      const message = navigator.locks
        ? "Your edits are not saved in this browser. They remain in this page; allow browser storage or free space, then retry before leaving."
        : "This browser cannot coordinate review saves across tabs. Your edits remain in this page and are not saved. Use a current browser on localhost or HTTPS before relying on browser persistence.";
      setSaveStates(current => ({ ...current, ...Object.fromEntries(Object.keys(browserDrafts.current).map(id => [id, { status: "error", message }])) }));
    }
  }
  function reloadBrowserDecision() {
    if (!selected) return;
    try {
      const saved = restoreBrowserReviews(window.localStorage.getItem(storageKey), intelligence.findings.map(finding => finding.id));
      delete browserDrafts.current[selected.id];
      setBrowserConflicts(current => current.filter(id => id !== selected.id));
      setRecords(withBrowserDrafts(saved.records));
      setFindingSaveState(selected.id, { status: "idle", message: "Loaded the saved decision. Review its values before making further changes." });
    } catch { setFindingSaveState(selected.id, { status: "error", message: "The saved decision could not be loaded. Your unsaved edits remain in this page." }); }
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
  function selectFinding(id: string) {
    setSelectedId(id);
    if (persistence === "browser") {
      try { window.localStorage.setItem(`${storageKey}:selected`, id); }
      catch { setStorageWarning("Browser storage is unavailable. The selected finding cannot be remembered after a reload."); }
    }
    requestAnimationFrame(() => {
      detailRef.current?.focus({ preventScroll: true });
      detailRef.current?.scrollIntoView({ block: "start" });
    });
  }
  function returnToQueue() {
    queueRef.current?.focus({ preventScroll: true });
    queueRef.current?.scrollIntoView({ block: "start" });
  }
  function beginFlowDraft() { if (!selectedPath) return; updateRecord({ flowDraft: createThreatFlowDraft(selectedPath.steps) }); }
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
    {storageWarning ? <p role="alert" className="notice-banner">{storageWarning}</p> : null}
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
      <aside ref={queueRef} className="finding-queue" aria-label="Prioritized findings" tabIndex={-1}><div className="queue-heading"><div><p className="eyebrow">Prioritized queue</p><h2>{visible.length} {filter === "ownership" ? "ownership " : ""}findings</h2></div>{filter !== "all" ? <button type="button" className="text-button" onClick={() => setFilter("all")}>Show all</button> : null}</div>{visible.map((finding) => <FindingButton key={finding.id} finding={finding} lifecycle={lifecycleById.get(finding.id) ?? "new"} prior={priorRecords[finding.id]} acceptanceDue={acceptanceDue(records[finding.id] ?? currentSummaries[finding.id] ?? priorRecords[finding.id])} active={selected?.id === finding.id} disposition={(records[finding.id] ?? currentSummaries[finding.id] ?? EMPTY).disposition} onClick={() => selectFinding(finding.id)} />)}</aside>
      <section ref={detailRef} className="finding-detail" aria-label="Selected finding" tabIndex={-1} aria-live="polite">{selected ? <>
        <button type="button" className="text-button finding-back-link" onClick={returnToQueue}>Back to findings</button><header className="finding-detail-header"><div><span className={`severity-pill severity-${selected.severity}`}>{selected.severity}</span><span className={`evidence-chip evidence-${selected.evidenceClass}`}>{evidenceLabel[selected.evidenceClass]}</span><span className={`lifecycle-chip lifecycle-${selectedLifecycle}`}>{selectedLifecycle}</span>{selected.rule ? <span className="rule-chip" title={`${selected.rule.title}, version ${selected.rule.version}`}>{selected.rule.id} · v{selected.rule.version}</span> : null}<h2>{selected.title}</h2><p>{selected.summary}</p></div><div className="detail-actions"><ExportLink className="button button-secondary" href={`/api/export/evidence-packet.md?snapshot=${encodeURIComponent(snapshotId)}&kind=finding&id=${encodeURIComponent(selected.id)}`}>Finding packet · Markdown</ExportLink><ExportLink className="button button-secondary" href={`/api/export/evidence-packet.json?snapshot=${encodeURIComponent(snapshotId)}&kind=finding&id=${encodeURIComponent(selected.id)}`}>Finding packet · JSON</ExportLink>{selectedPath ? <ExportLink className="button button-secondary" href={`/api/export/attack-flow.json?snapshot=${encodeURIComponent(snapshotId)}&path=${encodeURIComponent(selectedPath.id)}`}>Attack Flow</ExportLink> : null}{selected.edgeIds[0] ? <Link className="button button-primary" href={`/map?edge=${encodeURIComponent(selected.edgeIds[0])}`}>Inspect evidence</Link> : null}</div></header>
        <div className="finding-columns"><div><section className="detail-section"><h3>Recorded source coverage</h3><ul>{coverage.filter(c => selected.sourceEndpoints.some(endpoint => COLLECTORS.find(d => d.id === c.id)?.prefixes.some(prefix => endpoint.includes(prefix.replace(/\?$/, ""))))).map(c => <li key={c.id}><strong>{c.label}: {c.state.replaceAll("-", " ")}</strong> · {c.reason}</li>)}</ul><Link href="/investigations?view=coverage">Inspect all collector limits and prerequisites</Link></section><section className="detail-section"><h3>Why this matters</h3><p>{selected.whyItMatters}</p></section>
          {selected.rule ? <section className="detail-section rule-detail"><div className="section-heading compact"><div><p className="eyebrow">Control-path rule</p><h3>{selected.rule.id} · {selected.rule.title}</h3></div><span>Version {selected.rule.version}</span></div>{selected.prerequisites?.length ? <><h4>Prerequisites</h4><ul>{selected.prerequisites.map((item) => <li key={item}>{item}</li>)}</ul></> : null}{selected.requiredCoverage?.length ? <><h4>Evidence required to evaluate this rule</h4><ul>{selected.requiredCoverage.map((item) => <li key={item}>{item}</li>)}</ul></> : null}<p className="rule-references"><strong>Public references:</strong> {selected.rule.references.map((reference, index) => <span key={reference}>{index > 0 ? " · " : ""}<a href={reference} target="_blank" rel="noreferrer">Source {index + 1}</a></span>)}</p></section> : null}
          {selectedPath ? <section className="detail-section"><div className="section-heading compact"><div><h3>Multi-stage attack flow</h3><p>{selectedPath.confidence} confidence · {record.flowDraft.length || selectedPath.steps.length} {record.flowDraft.length ? "review" : "configured"} steps</p></div>{record.flowDraft.length === 0 ? <button type="button" className="text-button" disabled={editingDisabled} onClick={beginFlowDraft}>Edit a review copy</button> : <button type="button" className="text-button" disabled={editingDisabled} onClick={() => updateRecord({ flowDraft: [] })}>Reset to evidence</button>}</div>{editingDisabled ? <p className="review-edit-hint">{reviewLoading ? "Review controls are unavailable while the saved decision loads." : "Review controls are unavailable while the decision is saving."}</p> : null}{record.flowDraft.length > 0 && selectedPath.steps.some(step => step.explanation.length > THREAT_REVIEW_LIMITS.title) ? <p className="review-edit-hint">Long source explanations start as shortened review summaries (up to {THREAT_REVIEW_LIMITS.title} characters). Open Full source explanation beside a step to read the complete evidence. Your own edits are never shortened on save.</p> : null}{record.flowDraft.length > 0 ? <ol className="attack-flow flow-editor">{record.flowDraft.map((item, index) => <li key={item.id}><span>{index + 1}</span><div><label>Step narrative<input disabled={editingDisabled} maxLength={THREAT_REVIEW_LIMITS.title} value={item.title} onChange={(event) => updateFlowStep(index, { title: event.target.value })} /></label><small>{item.evidenceEdgeId ? `Evidence edge: ${item.evidenceEdgeId}` : "Analyst-authored step; no evidence edge"}</small>{item.evidenceEdgeId ? selectedPath.steps.filter(step => step.edgeId === item.evidenceEdgeId && step.explanation.length > THREAT_REVIEW_LIMITS.title).map(step => <details key={step.edgeId}><summary>Full source explanation</summary><p>{step.explanation}</p><code>{step.source.id} → {step.target.id}</code><code>{step.sourceEndpoint}</code></details>) : null}<div className="flow-controls"><button type="button" onClick={() => moveFlowStep(index, -1)} disabled={editingDisabled || index === 0}>Move up</button><button type="button" onClick={() => moveFlowStep(index, 1)} disabled={editingDisabled || index === record.flowDraft.length - 1}>Move down</button><button type="button" disabled={editingDisabled} onClick={() => updateRecord({ flowDraft: record.flowDraft.filter((_, itemIndex) => itemIndex !== index) })}>Remove</button></div></div></li>)}</ol> : <ol className="attack-flow">{selectedPath.steps.map((item) => <li key={item.edgeId}><span>{item.index + 1}</span><div><strong>{item.explanation}</strong>{item.permissions.length ? <p className="mono">{item.permissions.join(" · ")}</p> : null}<small>{item.source.id} → {item.target.id}</small><code>{item.sourceEndpoint}</code></div></li>)}</ol>}{record.flowDraft.length > 0 ? <button type="button" className="button button-secondary" disabled={editingDisabled || record.flowDraft.length >= THREAT_REVIEW_LIMITS.flowDraft} onClick={() => updateRecord({ flowDraft: [...record.flowDraft, { id: `analyst-${crypto.randomUUID()}`, title: "Describe the analyst-authored step", evidenceEdgeId: null }] })}>Add analyst step</button> : null}{record.flowDraft.length > 0 ? <p>{record.flowDraft.length} of {THREAT_REVIEW_LIMITS.flowDraft} review steps. Each narrative allows up to {THREAT_REVIEW_LIMITS.title} characters.{record.flowDraft.length >= THREAT_REVIEW_LIMITS.flowDraft ? " Remove a step before adding another." : ""}</p> : null}<div className="attack-tags">{selectedPath.attackMappings.map((mapping) => <span key={mapping.id}>{mapping.id} · {mapping.name}</span>)}</div><div className="packet-actions" aria-label="Focused attack path exports"><span>Share only this evidence-backed path:</span><ExportLink href={`/api/export/evidence-packet.md?snapshot=${encodeURIComponent(snapshotId)}&kind=path&id=${encodeURIComponent(selectedPath.id)}`}>Markdown packet</ExportLink><ExportLink href={`/api/export/evidence-packet.json?snapshot=${encodeURIComponent(snapshotId)}&kind=path&id=${encodeURIComponent(selectedPath.id)}`}>Versioned JSON</ExportLink></div></section> : null}
          <section className="detail-section"><h3>Recommended action</h3><ol className="remediation-list">{selected.remediation.map((item) => <li key={item}>{item}</li>)}</ol></section><section className="detail-section uncertainty"><h3>Residual uncertainty</h3>{selected.uncertainty.map((item) => <p key={item}>{item}</p>)}</section></div>
          <aside className="review-panel" aria-label="Finding decision"><p className="eyebrow">Decision record</p><h3>Review this risk</h3>{selectedPrior && !records[selected.id] && !currentSummaries[selected.id] ? <div className={`prior-review-note ${selectedPrior.disposition === "resolved" || acceptanceDue(selectedPrior) ? "warning" : ""}`}><strong>{selectedPrior.disposition === "resolved" ? `Previously resolved, but ${selectedLifecycle === "ongoing" ? "still" : "again"} detected.` : acceptanceDue(selectedPrior) ? `Prior acceptance ${selectedPrior.expiresAt! < today ? "expired" : "expires soon"}.` : "A prior decision is available."}</strong><p>{selectedPrior.owner ? `Owner: ${selectedPrior.owner}. ` : ""}It belongs to snapshot <code>{selectedPrior.snapshotId}</code> and is context only until you revalidate it.</p><button type="button" className="button button-secondary" disabled={!loaded[selected.id] || saveState.status === "saving"} onClick={revalidatePrior}>{selectedPrior.disposition === "resolved" || (selectedPrior.disposition === "accepted" && selectedPrior.expiresAt! < today) ? "Reopen from prior context" : "Revalidate for this scan"}</button></div> : null}<fieldset disabled={editingDisabled}><label>Status<select value={record.disposition} onChange={(event) => updateRecord({ disposition: event.target.value as Disposition })}><option value="open">Open</option><option value="mitigating">Mitigating</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option></select></label><label>Owner<input maxLength={THREAT_REVIEW_LIMITS.owner} value={record.owner} onChange={(event) => updateRecord({ owner: event.target.value })} placeholder="Team or person" /></label><label>Review / acceptance expiry<input type="date" value={record.expiresAt} onChange={(event) => updateRecord({ expiresAt: event.target.value })} /></label><label>Assumptions and notes<textarea rows={6} maxLength={THREAT_REVIEW_LIMITS.assumption} value={record.assumption} onChange={(event) => updateRecord({ assumption: event.target.value })} placeholder="What must remain true? Why is this accepted or mitigated?" /></label></fieldset>{persistence === "server" ? <button type="button" className="button button-primary" disabled={!loaded[selected.id] || saveState.status === "saving"} onClick={saveDecision}>Save decision</button> : null}<p className={`record-save-state ${saveState.status}`} role="status" aria-live="polite">{saveState.status === "saving" ? "Saving the decision…" : saveState.status === "saved" ? (persistence === "server" ? "Decision registered in the tenant record." : "Decision saved in this browser.") : saveState.status === "error" ? saveState.message : saveState.message ?? (reviewLoading ? "Loading the saved review…" : persistence === "server" ? "Save explicitly after reviewing this snapshot. Accepted risk requires an owner, expiry and rationale." : "Changes are saved in this browser. Accepted risk requires an owner, expiry and rationale.")}</p>{persistence === "server" && reviewLoading && saveState.status === "error" ? <button type="button" className="button button-secondary" onClick={() => setLoadAttempt(attempt => attempt + 1)}>Retry review load</button> : null}{persistence === "browser" && saveState.status === "error" && selected ? <button type="button" className="button button-secondary" onClick={() => { if (browserConflicts.includes(selected.id)) reloadBrowserDecision(); else void persistBrowserRecords(); }}>{browserConflicts.includes(selected.id) ? "Reload saved decision" : "Retry browser save"}</button> : null}<p className="local-record-note"><strong>{persistence === "server" ? "Encrypted and tenant-scoped." : "Saved in this browser only."}</strong> Review decisions never modify Microsoft Entra.{persistence === "server" ? " Authenticated team members in this tenant share the PostgreSQL record." : " Connect a tenant to share decision records with your team."}</p><dl><div><dt>Tenant</dt><dd>{tenantLabel}</dd></div><div><dt>Snapshot</dt><dd><code>{snapshotId}</code></dd></div><div><dt>Finding ID</dt><dd><code>{selected.id}</code></dd></div></dl></aside>
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
