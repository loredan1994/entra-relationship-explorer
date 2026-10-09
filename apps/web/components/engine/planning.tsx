"use client";
import { useMemo, useState } from "react";
import { canonical, compareContract, evaluateContract, parseContract, solveChanges, unique, type AuthorizationQuery, type EvidenceModel, type EvidenceProof } from "@entra-explorer/engine";
import { download, JsonDetails, ResultSummary } from "./common";

export function ChangePlanner({ model, proof, names }: { model: EvidenceModel; proof: EvidenceProof; names: Map<string, string> }) {
  const ids = unique(proof.paths.flat());
  const [costs, setCosts] = useState<Record<string, number>>({}), [protectedIds, setProtected] = useState<string[]>([]);
  const [result, setResult] = useState<ReturnType<typeof solveChanges> | null>(null), [error, setError] = useState("");
  const protectionChoices = model.edges.filter(e => e.type === "CAN_CALL_AS_APP" && e.evidence.configured);
  function run() {
    try {
      setResult(solveChanges({ context: model, paths: proof.paths.map((dependencies, i) => ({ id: `path-${i + 1}`, dependencies })),
        candidates: ids.map(id => ({ id, cost: costs[id] ?? 1, removes: [id], description: "Proposed relationship exclusion" })),
        protectedIntegrations: protectedIds.map(id => ({ id, alternatives: [{ id, dependencies: [id] }] })),
        evidenceComplete: proof.verdict !== "unknown" && proof.verdict !== "conflicting" && !proof.missing.length, maxSteps: 25_000 }));
      setError("");
    } catch (e) { setError(e instanceof Error ? e.message : "Plan could not be evaluated."); }
  }
  return <><p>Find low-cost sets of proposed relationship exclusions that break all {proof.paths.length} recorded paths. Costs are your operational estimates. Nothing is applied to Entra.</p>
    <h3>Candidate changes and declared cost</h3><div className="engine-costs">{ids.map(id => { const e = model.edges.find(e => e.id === id)!; return <label key={id}><span>{names.get(e.sourceId)} → {names.get(e.targetId)} · {e.type}<br /><code>{id}</code></span><input aria-label={`Cost for ${id}`} type="number" min="0" max="1000000" value={costs[id] ?? 1} onChange={event => { setCosts(c => ({ ...c, [id]: Number(event.target.value) })); setResult(null); }} /></label>; })}</div>
    <details><summary>Protect required application integrations</summary><p>A protected recorded grant cannot be excluded. Advanced protected alternatives are supported by the engine’s declarative planning interface.</p><div className="scenario-choices">{protectionChoices.map(e => <label key={e.id}><input type="checkbox" checked={protectedIds.includes(e.id)} onChange={event => { setProtected(values => event.target.checked ? [...values, e.id] : values.filter(id => id !== e.id)); setResult(null); }} /><span>{names.get(e.sourceId)} → {names.get(e.targetId)} · {e.permissions.join(", ")}<br /><code>{e.id}</code></span></label>)}</div></details>
    <button className="button button-primary" onClick={run} type="button" disabled={!proof.paths.length}>Compare proposed changes</button>{!proof.paths.length ? <p>Evaluate a query with a recorded path first.</p> : null}{error ? <p role="alert">{error}</p> : null}
    {result ? <><ResultSummary result={result}><p>Search: <strong>{result.status}</strong> · lower bound {result.lowerBound} · best cost {result.upperBound ?? "No feasible plan found"}. Bounds concern supplied paths only.</p><p>Analysis work: {result.limits.work.toLocaleString()} / {result.limits.maxWork.toLocaleString()} units. {result.status === "bounded" ? "A limit was reached. Reduce the candidate set or use a larger offline budget; no result here establishes that a plan is impossible." : "All supplied planning work completed."}</p></ResultSummary>{result.plans.map((p, i) => <article className="engine-result" key={i}><h3>Plan {i + 1} · cost {p.cost}</h3><ul>{p.changes.map(id => <li key={id}>Propose excluding <code>{id}</code></li>)}</ul><p>{p.brokenPaths.length} modeled paths broken · {p.residualPaths.length} residual paths · {p.preservedIntegrations.length} protected integrations preserved.</p></article>)}<button className="button button-secondary" type="button" onClick={() => download(result, "entra-local-change-plans.json")}>Export sensitive review plans</button><JsonDetails value={result} /></> : null}
  </>;
}

export function ContractWorkbench({ model, previous, query }: { model: EvidenceModel; previous?: EvidenceModel; query: AuthorizationQuery }) {
  const initial = { version: 1, tenantId: model.tenantId, id: "application-access-intent", kind: "only-principals", resourceId: query.resourceId, permissionId: query.permissionId ?? "", allowedPrincipalIds: [query.principalId] };
  const [source, setSource] = useState(JSON.stringify(initial, null, 2));
  const [result, setResult] = useState<ReturnType<typeof evaluateContract> | null>(null), [comparison, setComparison] = useState<ReturnType<typeof compareContract> | null>(null), [error, setError] = useState("");
  const templates = useMemo(() => ({
    "only-principals": initial,
    "require-grant": { version: 1, tenantId: model.tenantId, id: "required-integration", kind: "require-grant", principalId: query.principalId, resourceId: query.resourceId, permissionId: query.permissionId ?? "" },
    "no-control-path": { version: 1, tenantId: model.tenantId, id: "protected-resource", kind: "no-control-path", sourceIds: [query.principalId], resourceIds: [query.resourceId] },
  }), [model.tenantId, query.principalId, query.resourceId, query.permissionId]);
  function run() { try { const contract = parseContract(source); setResult(evaluateContract(model, contract)); setComparison(previous ? compareContract(previous, model, contract) : null); setError(""); } catch (e) { setError(e instanceof Error ? e.message : "Contract is invalid."); } }
  return <><p>Declare who may hold an application permission, require an integration, or forbid a modeled control path. Contracts are tenant-bound JSON; imported code cannot run.</p>
    <label className="engine-field">Choose a contract template<select defaultValue="only-principals" onChange={e => { setSource(JSON.stringify(templates[e.target.value as keyof typeof templates], null, 2)); setResult(null); setComparison(null); }}><option value="only-principals">Only these principals may hold a permission</option><option value="require-grant">This integration must have a recorded grant</option><option value="no-control-path">No supported control path to these resources</option></select></label>
    <label className="engine-field"><span id="engine-contract-label">Access contract</span><textarea aria-labelledby="engine-contract-label" rows={14} maxLength={100000} value={source} onChange={e => { setSource(e.target.value); setResult(null); setComparison(null); }} spellCheck={false} /></label>
    <button type="button" className="button button-primary" onClick={run}>Evaluate contract and semantic changes</button>{error ? <p role="alert">{error}</p> : null}
    {result ? <><ResultSummary result={result}><p>Contract <code>{result.contractId}</code>: <strong>{result.status}</strong>. {result.witnesses.length} violating witnesses.</p></ResultSummary>{comparison ? <p>Compared with {previous!.snapshotIds[0]}: {comparison.addedPaths.length} added / {comparison.removedPaths.length} absent semantic paths · {comparison.complete ? "Complete relevant evidence" : "Incomplete — removals are unconfirmed"}.</p> : <p>No prior retained snapshot is available for comparison.</p>}
      <button className="button button-secondary" type="button" onClick={() => download(parseContract(source), "entra-access-contract.json")}>Export sensitive contract</button><JsonDetails value={comparison ?? result} />
      <p>Run the same contract in local CI: <code>pnpm engine contract snapshot.json contract.json</code>. Exit 0 means pass, 1 means fail, and 2 means unknown or invalid input.</p>
    </> : null}<details><summary>Contract schema</summary><pre>{canonical(templates)}</pre></details>
  </>;
}
