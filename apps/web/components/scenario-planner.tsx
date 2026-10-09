"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { createScenarioPlan, importScenarioPlan, SCENARIO_PLAN_MAX_BYTES, rankScenarioCuts, SCENARIO_EDGE_TYPES, simulateRemoval, type TenantSnapshot } from "@entra-explorer/domain";

export function ScenarioPlanner({ snapshot }: { snapshot: TenantSnapshot }) {
  const [excluded, setExcluded] = useState<string[]>([]);
  const [importStatus, setImportStatus] = useState("");
  const [importPending, setImportPending] = useState(false);
  const importOperation = useRef(0);
  useEffect(() => () => { importOperation.current++; }, []);
  const [query, setQuery] = useState("");
  const [ranked, setRanked] = useState<ReturnType<typeof rankScenarioCuts> | null>(null);
  const result = useMemo(() => simulateRemoval(snapshot, excluded), [snapshot, excluded]);
  const names = new Map(snapshot.nodes.map(n => [n.id, n.label]));
  const eligible = snapshot.edges.filter(e => e.evidence.configured && (SCENARIO_EDGE_TYPES as readonly string[]).includes(e.type));
  const visible = eligible.filter(e => `${names.get(e.sourceId)} ${names.get(e.targetId)} ${e.type} ${e.permissions.join(" ")}`.toLowerCase().includes(query.toLowerCase()));
  function updateScenario(ids: string[]) {
    importOperation.current++;
    setImportPending(false); setImportStatus(""); setExcluded(ids);
  }
  function exportPlan() {
    const report = createScenarioPlan(snapshot, excluded);
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = "entra-scenario.json"; a.click(); URL.revokeObjectURL(url);
  }
  async function importPlan(file: File | undefined) {
    if (!file) return;
    const operation = ++importOperation.current;
    setImportPending(true); setImportStatus(`Reading ${file.name} locally…`);
    try {
      if (file.size > SCENARIO_PLAN_MAX_BYTES) throw new Error("Scenario plans must be at most 100 KB.");
      const source = await file.text();
      if (operation !== importOperation.current) return;
      const ids = importScenarioPlan(source, snapshot);
      setExcluded(ids);
      setImportStatus(`Imported ${ids.length} exclusions. Results were recomputed from this snapshot.`);
    } catch (error) {
      if (operation === importOperation.current) setImportStatus(error instanceof Error ? error.message : "The plan could not be imported.");
    } finally {
      if (operation === importOperation.current) setImportPending(false);
    }
  }
  return <section className="panel investigation-card"><h2>What-if access planner</h2><p>Exclude configured relationships in a local copy of snapshot <code>{snapshot.id}</code>. This performs no network request and makes no Entra change. Removing an ownership relationship models loss of that control path, not operational revocation or a full risk assessment.</p><div className="notice-banner">{result.complete ? "Analysis finished within the collected evidence and traversal bounds." : "Partial evidence or analysis: path counts are lower bounds. Missing paths cannot be declared eliminated."} Credential possession, sessions, group expansion gaps and future changes remain outside this model.</div>
    <div className="summary-strip" aria-label="Scenario results"><article><strong>{result.baseline.paths.length}</strong><span>Baseline paths</span></article><article><strong>{result.removedPaths.length}</strong><span>Paths absent in scenario</span></article><article><strong>{result.remainingPaths.length}</strong><span>Remaining paths</span></article><article><strong>{result.scenarioTargets.length}</strong><span>Reachable targets in scenario</span></article></div>
    <p>Exported plans contain tenant object IDs. Handle them as sensitive tenant data.</p><div className="detail-actions"><button type="button" className="button button-secondary" onClick={() => updateScenario([])}>Reset scenario</button><button type="button" className="button button-secondary" onClick={exportPlan}>Export review plan</button><button type="button" className="button button-secondary" onClick={() => setRanked(rankScenarioCuts(snapshot))}>Rank candidate changes</button></div>
    <label className="investigation-search">Import review plan<input type="file" accept=".json,application/json" aria-busy={importPending} onChange={event => { void importPlan(event.target.files?.[0]); event.target.value = ""; }} /></label><p>Plans must match this tenant and snapshot. Imports stay in this browser and never trust exported path counts. Selecting another file, resetting, or editing exclusions cancels a pending import.</p>{importStatus ? <p role="status">{importStatus}</p> : null}
    {ranked ? <div><h3>Candidate changes</h3><p>Compared {ranked.candidatesConsidered} relationships from at most the first 20 candidates. Counts reflect modeled paths, not business impact or an optimal remediation plan.</p><ol>{ranked.cuts.map(c => { const e = snapshot.edges.find(e => e.id === c.edgeId)!; return <li key={c.edgeId}><button className="text-button" type="button" onClick={() => updateScenario([c.edgeId])}>{names.get(e.sourceId)} → {names.get(e.targetId)} · {e.plainLabel}</button>: {c.removedPaths} paths absent, {c.remainingPaths} remaining{c.complete ? "" : " (incomplete evidence)"}</li>; })}</ol></div> : null}
    <label className="investigation-search">Find a relationship<input value={query} onChange={e => setQuery(e.target.value)} /></label><p>{excluded.length} excluded / {eligible.length} eligible. Select up to 100.</p>
    <div className="scenario-choices">{visible.map(edge => <label key={edge.id}><input type="checkbox" checked={excluded.includes(edge.id)} disabled={!excluded.includes(edge.id) && excluded.length >= 100} onChange={e => updateScenario(e.target.checked ? [...excluded, edge.id] : excluded.filter(id => id !== edge.id))} /><span><strong>{names.get(edge.sourceId)} → {names.get(edge.targetId)}</strong><br />{edge.plainLabel} · {edge.permissions.join(", ")}<br /><code>{edge.id}</code></span></label>)}</div>
    <h3>Remaining paths and alternatives</h3>{result.remainingPaths.length ? <ul>{result.remainingPaths.slice(0, 100).map(path => <li key={path.id}>{path.source.label} → {path.target.label} · {path.steps.length} steps · <Link href={`/map?edge=${encodeURIComponent(path.steps[0]!.edgeId)}`}>Inspect baseline evidence</Link></li>)}</ul> : <p>No paths found within the modeled evidence. This is not assurance that access is impossible.</p>}{result.remainingPaths.length > 100 ? <p>Showing the first 100 paths; the export contains every returned path ID.</p> : null}
  </section>;
}
