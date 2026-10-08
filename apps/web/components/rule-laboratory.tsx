"use client";
import { useState } from "react";
import { cleanProjectFixture, replayRuleLabCase, type RuleLabCase } from "@entra-explorer/domain";

function example(negative: boolean): RuleLabCase {
  return { schemaVersion: 1, name: negative ? "Owner control negative case" : "Owner control positive case", fixture: "clean-project-v1",
    removeEdgeIds: negative ? cleanProjectFixture.edges.filter(e => ["OWNS", "FEDERATES_AS"].includes(e.type)).map(e => e.id) : [],
    expectations: [{ ruleId: "ERE-IAM-001", version: 1, minimum: negative ? 0 : 1, maximum: negative ? 0 : 100 }] };
}
export function RuleLaboratory() {
  const [source, setSource] = useState(JSON.stringify(example(false), null, 2));
  const [result, setResult] = useState<ReturnType<typeof replayRuleLabCase> | null>(null);
  const [error, setError] = useState("");
  function edit(value: string) { setSource(value); setResult(null); setError(""); }
  function replay() {
    setResult(null); setError("");
    try {
      if (new TextEncoder().encode(source).length > 100_000) throw new Error("Scenario exceeds 100 KB.");
      setResult(replayRuleLabCase(JSON.parse(source)));
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Invalid scenario."); }
  }
  return <div className="rule-laboratory">
    <h3>Try a synthetic regression</h3>
    <p>Edit expected counts or exclude fixture relationships, then replay the compiled rules locally. Changing the case clears previous results. Real tenant data and executable rules are rejected.</p>
    <div className="detail-actions"><button className="button button-secondary" type="button" onClick={() => edit(JSON.stringify(example(false), null, 2))}>Load positive case</button><button className="button button-secondary" type="button" onClick={() => edit(JSON.stringify(example(true), null, 2))}>Load negative case</button></div>
    <label className="investigation-search">Synthetic scenario JSON<textarea rows={16} value={source} maxLength={100_000} spellCheck={false} onChange={event => edit(event.target.value)} /></label>
    <button className="button button-primary" type="button" onClick={replay}>Replay synthetic case</button>
    {error ? <p role="alert">{error}</p> : null}
    {result ? <section aria-label="Rule replay results"><p role="status"><strong>{result.passed ? "Passed" : "Failed"}</strong> · {result.name} · synthetic fixture only</p>
      <div className="table-scroll"><table><thead><tr><th>Rule</th><th>Expected findings</th><th>Actual findings</th><th>Result</th></tr></thead><tbody>{result.results.map((row, index) => <tr key={`${row.ruleId}:${index}`}><td>{row.ruleId} · v{row.version}</td><td>{row.minimum}–{row.maximum}</td><td>{row.actual}</td><td>{row.passed ? "Passed" : "Failed"}</td></tr>)}</tbody></table></div>
      {result.results.flatMap(row => row.findings).map((finding, index) => <details key={`${finding.id}:${index}`}><summary>Finding evidence · {finding.id}</summary><p>Relationship IDs: {finding.edgeIds.join(", ") || "None"}</p>{finding.sourceEndpoints.map(endpoint => <p key={endpoint}><code>{endpoint}</code></p>)}</details>)}
    </section> : null}
  </div>;
}
