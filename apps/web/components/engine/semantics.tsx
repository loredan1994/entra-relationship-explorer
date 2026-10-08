"use client";
import { useMemo, useState } from "react";
import { analyzeFederation, findPolicyCounterexamples, matchesTrust, simulateContinuity, type ContinuityPlan, type EvidenceModel, type PolicyIntent } from "@entra-explorer/engine";
import { download, JsonDetails, ResultSummary } from "./common";

export function FederationWorkbench({ model, names }: { model: EvidenceModel; names: Map<string, string> }) {
  const result = useMemo(() => analyzeFederation(model), [model]);
  const [claims, setClaims] = useState({ issuer: "", subject: "", audience: "api://AzureADTokenExchange" });
  const [tested, setTested] = useState(false);
  return <><ResultSummary result={result}><p>{result.comparisons.length} trust pairs checked. Exact matches compare case-sensitive issuer, subject and a single audience. Witnesses are unsigned synthetic claims.</p></ResultSummary>
    <div className="table-scroll"><table><thead><tr><th>Trusts</th><th>Overlap</th><th>Reason / synthetic witness</th></tr></thead><tbody>{result.comparisons.map(c => <tr key={`${c.left}/${c.right}`}><td>{names.get(c.left)} ↔ {names.get(c.right)}</td><td>{c.verdict}</td><td>{c.reason}{c.witness ? <JsonDetails value={c.witness} label="Inspect synthetic claims" /> : null}</td></tr>)}</tbody></table></div>
    {!result.comparisons.length ? <p>At least two recorded trusts are needed for pairwise comparison. Historical flattened records require a fresh read-only scan for exact audience analysis.</p> : null}
    <h3>Test operator-supplied workload claims</h3><p>Enter plain claim values, never a token. These are supplied assumptions, separate from collected tenant facts.</p><form className="engine-query" onSubmit={e => { e.preventDefault(); setTested(true); }}>{(["issuer", "subject", "audience"] as const).map(field => <label key={field}>{field}<input value={claims[field]} maxLength={600} required onChange={e => { setClaims(c => ({ ...c, [field]: e.target.value })); setTested(false); }} /></label>)}<button className="button button-primary" type="submit">Compare exact claims</button></form>
    {tested ? <ul aria-live="polite">{model.nodes.filter(n => n.kind === "federatedCredential").map(n => <li key={n.id}>{names.get(n.id)}: {matchesTrust(n.federationTrust, claims)}</li>)}</ul> : null}<JsonDetails value={result} />
  </>;
}

export function PolicyWorkbench({ model }: { model: EvidenceModel }) {
  const [requirement, setRequirement] = useState<PolicyIntent["require"]>("mfa"), [users, setUsers] = useState("All"), [apps, setApps] = useState("All");
  const [result, setResult] = useState<ReturnType<typeof findPolicyCounterexamples> | null>(null), [error, setError] = useState("");
  function run() { try { setResult(findPolicyCounterexamples(model, { require: requirement, userIds: users.split(",").map(s => s.trim()).filter(Boolean), applicationIds: apps.split(",").map(s => s.trim()).filter(Boolean) })); setError(""); } catch (e) { setError(e instanceof Error ? e.message : "Intent is invalid."); } }
  return <><p>Search a finite domain of policy boundaries for scenarios that violate the intent below. Existing optional policy evidence is required. Unavailable conditions and report-only controls cannot establish enforcement.</p>
    <div className="engine-query"><label>Intent<select value={requirement} onChange={e => { setRequirement(e.target.value as PolicyIntent["require"]); setResult(null); }}><option value="mfa">Require MFA</option><option value="compliantDevice">Require a compliant device</option><option value="block">Block every modeled scenario</option></select></label><label>User object IDs, comma-separated, or All<input value={users} maxLength={10000} onChange={e => { setUsers(e.target.value); setResult(null); }} /></label><label>Resource application IDs, comma-separated, or All<input value={apps} maxLength={10000} onChange={e => { setApps(e.target.value); setResult(null); }} /></label><button className="button button-primary" type="button" onClick={run}>Find policy counterexamples</button></div>
    {error ? <p role="alert">{error}</p> : null}{result ? <><ResultSummary result={result}><p>{result.checked} scenarios checked of {result.domainSize} boundary combinations · {result.unknown} indeterminate · {result.witnesses.length} minimized counterexamples displayed.</p></ResultSummary>{result.witnesses.map((w, i) => <article className="engine-result" key={i}><h3>Counterexample {i + 1}</h3><p>User <code>{w.scenario.userId}</code> · resource <code>{w.scenario.applicationId}</code>. Policy requirements permit this scenario under the supported model.</p><JsonDetails value={w} label="Inspect minimized scenario and policy decisions" /></article>)}<button className="button button-secondary" type="button" onClick={() => download(result, "entra-policy-counterexamples.json")}>Export sensitive scenarios for comparison</button><p>Compare the exported scenarios manually with Microsoft’s What If tool. This workspace does not call its evaluation API.</p><JsonDetails value={result} /></> : null}
  </>;
}

export function RotationWorkbench({ model, names }: { model: EvidenceModel; names: Map<string, string> }) {
  const identities = model.nodes.filter(n => (n.credentials?.length ?? 0) > 0);
  const [identity, setIdentity] = useState(identities[0]?.id ?? "");
  const selected = identities.find(n => n.id === identity);
  const horizonStart = model.collectedAt[0]!;
  const horizonEnd = new Date(Date.parse(horizonStart) + 30 * 86400000).toISOString();
  const [source, setSource] = useState("");
  const [result, setResult] = useState<ReturnType<typeof simulateContinuity> | null>(null), [error, setError] = useState("");
  function scaffold() {
    const keys = selected?.credentials?.map(c => `${selected.id}/${c.id}`) ?? [];
    const plan: ContinuityPlan = { tenantId: model.tenantId, horizon: { startsAt: horizonStart, endsAt: horizonEnd }, clockSkewSeconds: 60,
      deployments: keys.map(credentialKey => ({ credentialKey, availableFrom: null })), workloads: [{ id: "declared-workload", credentialKeys: keys, requires: [] }] };
    setSource(JSON.stringify(plan, null, 2)); setResult(null); setError("");
  }
  function run() { try { if (source.length > 100000) throw new Error("Rotation plan exceeds 100 KB."); setResult(simulateContinuity(model, JSON.parse(source) as ContinuityPlan)); setError(""); } catch (e) { setError(e instanceof Error ? e.message : "Plan is invalid."); } }
  return <><p>Model credential validity together with your declared deployment stages. Start dates are intentionally unknown until you supply them. Dates alone do not prove that a credential is deployed or used.</p>
    {!identities.length ? <p>No individual credential metadata is available in this snapshot. Missing metadata cannot establish safe rotation.</p> : <><div className="engine-query"><label>Identity with credential metadata<select value={identity} onChange={e => { setIdentity(e.target.value); setSource(""); setResult(null); setError(""); }}>{identities.map(n => <option key={n.id} value={n.id}>{names.get(n.id)}</option>)}</select></label><button className="button button-secondary" type="button" onClick={scaffold}>Create a rotation-plan template</button></div>
      <p>Set <code>availableFrom</code> to a declared ISO timestamp. Omit <code>unavailableFrom</code> to declare availability through the horizon, set a retirement timestamp, or use null for unknown. Workloads can depend on other declared workloads through <code>requires</code>.</p>
      {source ? <><label className="engine-field">Declared deployment plan<textarea rows={18} value={source} maxLength={100000} spellCheck={false} onChange={e => { setSource(e.target.value); setResult(null); }} /></label><button className="button button-primary" type="button" onClick={run}>Simulate credential continuity</button></> : null}</>}
    {error ? <p role="alert">{error}</p> : null}{result ? <><ResultSummary result={result} /><div className="table-scroll"><table><thead><tr><th>Workload</th><th>Interval (end exclusive)</th><th>Continuity</th><th>Modeled rollback</th></tr></thead><tbody>{result.intervals.map((i, index) => <tr key={index}><td>{i.workloadId}</td><td>{i.startsAt} → {i.endsAt}</td><td>{i.verdict}<p>{i.credentials.join(", ")}</p></td><td>{i.rollbackAvailable ? "Overlapping declared credentials" : "No confirmed overlap"}</td></tr>)}</tbody></table></div><button className="button button-secondary" type="button" onClick={() => download({ plan: JSON.parse(source), result }, "entra-credential-continuity.json")}>Export sensitive rotation model</button><JsonDetails value={result} /></> : null}
  </>;
}
