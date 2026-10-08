"use client";
import Link from "next/link";
import type { ReactNode } from "react";
import type { EvidenceProof, WorkflowResult } from "@entra-explorer/engine";

export function download(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}
export function JsonDetails({ value, label = "Inspect reproducible result" }: { value: unknown; label?: string }) {
  return <details className="engine-json"><summary>{label}</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>;
}
export function ResultSummary({ result, children }: { result: EvidenceProof | WorkflowResult; children?: ReactNode }) {
  return <section className="engine-result" aria-live="polite"><div className="section-heading"><h3>Result: {result.verdict}</h3><span className="completion-badge neutral">{result.limits.exhausted ? "Search limit reached" : "Finished within bounds"}</span></div>{children}
    <p>{result.limits.steps.toLocaleString("en")} steps · limit {result.limits.maxSteps.toLocaleString("en")} · engine {result.engineVersion} · rules {result.ruleVersion}</p>
    {result.missing.length ? <><h4>Unresolved prerequisites</h4><ul>{result.missing.map(m => <li key={m}><code>{m}</code></li>)}</ul></> : null}
    <details><summary>Assumptions and interpretation</summary><ul>{result.assumptions.map(a => <li key={a}>{a}</li>)}</ul></details>
  </section>;
}
export function ProofView({ proof, names }: { proof: EvidenceProof; names: Map<string, string> }) {
  return <><ResultSummary result={proof}><p><strong>{proof.evidenceClass}</strong> evidence · {proof.paths.length} recorded derivations. “Supported” applies to the stated query and assumptions.</p></ResultSummary>
    <h3>Derivations and exact sources</h3>{proof.paths.length ? <ol className="engine-paths">{proof.paths.map((path, index) => <li key={JSON.stringify(path)}><strong>Path {index + 1}</strong><ol>{path.map(id => { const fact = proof.facts.find(f => f.id === `relationship:${id}`)!; return <li key={id}><Link href={`/map?edge=${encodeURIComponent(id)}`}>{names.get(fact.sourceObjectId) ?? fact.sourceObjectId} → {names.get(fact.targetObjectId) ?? fact.targetObjectId}</Link><br /><code>{id}</code> · {fact.relationshipType} · {fact.completeness}<br /><code>{fact.sourceEndpoint}</code><br /><small>Source records: {fact.sourceRecordIds.join(", ")}</small></li>; })}</ol></li>)}</ol> : <p>No supported path recorded. Check the verdict and missing prerequisites before interpreting absence.</p>}
    {proof.conflicts.length ? <div className="notice-banner">Contradictory source facts remain visible in the proof. Resolve them before relying on this conclusion.</div> : null}
    <JsonDetails value={proof} />
  </>;
}
