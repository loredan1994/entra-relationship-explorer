"use client";
import { useMemo, useState, type FormEvent } from "react";
import Link from "next/link";
import type { TenantSnapshot } from "@entra-explorer/domain";
import { compileSnapshot, evaluateAuthorization, reconstructPaths, planEvidenceGaps, ENGINE_VERSION, type AuthorizationQuery, type QueryKind } from "@entra-explorer/engine";
import { ProofView, ResultSummary, JsonDetails } from "./common";
import { ChangePlanner, ContractWorkbench } from "./planning";
import { FederationWorkbench, PolicyWorkbench, RotationWorkbench } from "./semantics";
import { PortableWorkbench } from "./verifier";

export const engineTools = [
  { id: "proof", title: "Evidence proofs", question: "Can I reproduce this conclusion?" },
  { id: "authorization", title: "Access compiler", question: "What configuration supports this access?" },
  { id: "time", title: "Time-consistent paths", question: "Did the prerequisites coexist?" },
  { id: "plans", title: "Change planning", question: "Which changes break every modeled path?" },
  { id: "policy", title: "Policy counterexamples", question: "Where could our policy intent fail?" },
  { id: "federation", title: "Federation boundaries", question: "Which workload trusts overlap?" },
  { id: "rotation", title: "Credential continuity", question: "Does this declared rotation leave a gap?" },
  { id: "gaps", title: "Evidence gap planner", question: "Which reads could resolve this question?" },
  { id: "contracts", title: "Access contracts", question: "Does this snapshot satisfy our intent?" },
  { id: "verify", title: "Portable verifier", question: "Can another analyst replay this evidence?" },
] as const;
const kinds: Array<[QueryKind, string]> = [["application-permission", "Application permission"], ["delegated-permission", "Delegated consent with user context"], ["assignment", "Application assignment"], ["membership", "Group membership, including nesting"], ["ownership", "Ownership capability"], ["active-role", "Active administrative role"], ["eligible-role", "Eligible administrative role"], ["control-path", "Possible control path"]];

export function EngineWorkspace({ snapshot, history, view }: { snapshot: TenantSnapshot; history: TenantSnapshot[]; view?: string }) {
  const tab = engineTools.find(t => t.id === view) ?? engineTools[0];
  const model = useMemo(() => compileSnapshot(snapshot), [snapshot]);
  const needsHistory = tab.id === "time" || tab.id === "contracts";
  const models = useMemo(() => needsHistory ? history.map(item => item.id === snapshot.id ? model : compileSnapshot(item)) : [], [history, model, needsHistory, snapshot.id]);
  const initialGrant = snapshot.edges.find(e => e.type === "CAN_CALL_AS_APP" && e.permissionIds?.length);
  const initial: AuthorizationQuery = { tenantId: model.tenantId, kind: "application-permission", principalId: initialGrant?.sourceId ?? snapshot.nodes[0]?.id ?? "", resourceId: initialGrant?.targetId ?? snapshot.nodes[1]?.id ?? "", permissionId: initialGrant?.permissionIds?.[0] ?? "" };
  const [draft, setDraft] = useState(initial), [query, setQuery] = useState(initial), [error, setError] = useState("");
  const proof = useMemo(() => { try { return evaluateAuthorization(model, query); } catch { return null; } }, [model, query]);
  const names = useMemo(() => new Map(snapshot.nodes.map(n => [n.id, n.label])), [snapshot]);
  const usesQuery = !["policy", "federation", "rotation"].includes(tab.id);
  function run(event: FormEvent) {
    event.preventDefault();
    const submitted = { ...draft,
      permissionId: ["application-permission", "delegated-permission", "control-path", "assignment"].includes(draft.kind) ? draft.permissionId : undefined,
      userId: draft.kind === "delegated-permission" ? draft.userId : undefined,
      directoryScopeId: draft.kind.includes("role") ? draft.directoryScopeId : undefined };
    try { evaluateAuthorization(model, submitted); setQuery(submitted); setError(""); } catch (e) { setError(e instanceof Error ? e.message : "Query could not be evaluated."); }
  }
  const set = (field: keyof AuthorizationQuery, value: string) => setDraft(q => ({ ...q, [field]: value || undefined }));
  return <>
    <nav className="investigation-tabs engine-tabs" aria-label="Engine workflows">{engineTools.map(t => <Link key={t.id} href={`/engine?view=${t.id}`} aria-current={t.id === tab.id ? "page" : undefined}>{t.title}</Link>)}</nav>
    <section className="panel investigation-card"><h2>{tab.question}</h2>
      {usesQuery ? <form className="engine-query" onSubmit={run}>
        <label>Question type<select value={draft.kind} onChange={e => set("kind", e.target.value)}>{kinds.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
        <label><span id="engine-principal-label">Principal</span><select aria-labelledby="engine-principal-label" value={draft.principalId} onChange={e => set("principalId", e.target.value)}>{snapshot.nodes.map(n => <option key={n.id} value={n.id}>{n.label} · {n.kind}</option>)}</select></label>
        <label><span id="engine-resource-label">Resource or group</span><select aria-labelledby="engine-resource-label" value={draft.resourceId} onChange={e => set("resourceId", e.target.value)}>{snapshot.nodes.map(n => <option key={n.id} value={n.id}>{n.label} · {n.kind}</option>)}</select></label>
        {["application-permission", "delegated-permission", "control-path", "assignment"].includes(draft.kind) ? <label>Permission ID {draft.kind === "control-path" || draft.kind === "assignment" ? "(optional)" : "(required)"}<input value={draft.permissionId ?? ""} maxLength={500} list="engine-permissions" onChange={e => set("permissionId", e.target.value)} /><datalist id="engine-permissions">{[...new Set(snapshot.edges.filter(e => e.targetId === draft.resourceId).flatMap(e => e.permissionIds ?? []))].map(id => <option key={id} value={id} />)}</datalist></label> : null}
        {draft.kind === "delegated-permission" ? <label>User context<select value={draft.userId ?? ""} onChange={e => set("userId", e.target.value)}><option value="">Unknown / not supplied</option>{snapshot.nodes.filter(n => n.kind === "user").map(n => <option key={n.id} value={n.id}>{n.label}</option>)}</select></label> : null}
        {draft.kind.includes("role") ? <label>Exact directory scope<input value={draft.directoryScopeId ?? ""} onChange={e => set("directoryScopeId", e.target.value)} placeholder="/ or /administrativeUnits/object-id" /></label> : null}
        <button className="button button-primary" type="submit">Evaluate recorded evidence</button>
      </form> : null}
      {usesQuery && proof ? <p>Results describe the last evaluated query: <strong>{names.get(query.principalId) ?? query.principalId}</strong> → <strong>{names.get(query.resourceId) ?? query.resourceId}</strong> · {query.kind}. After editing controls, select Evaluate recorded evidence.</p> : null}
      {error ? <p role="alert">{error}</p> : null}
      {usesQuery && !proof ? <p>Select a principal, resource, and required permission ID to begin.</p> : null}
      {proof && (tab.id === "proof" || tab.id === "authorization") ? <ProofView proof={proof} names={names} /> : null}
      {proof && tab.id === "time" ? <TemporalView models={models} query={query} /> : null}
      {proof && tab.id === "plans" ? <ChangePlanner key={JSON.stringify(query)} model={model} proof={proof} names={names} /> : null}
      {proof && tab.id === "gaps" ? <GapView proof={proof} /> : null}
      {proof && tab.id === "contracts" ? <ContractWorkbench key={JSON.stringify(query)} model={model} previous={models[1]} query={query} /> : null}
      {proof && tab.id === "verify" ? <PortableWorkbench model={model} query={query} /> : null}
      {tab.id === "federation" ? <FederationWorkbench model={model} names={names} /> : null}
      {tab.id === "policy" ? <PolicyWorkbench model={model} /> : null}
      {tab.id === "rotation" ? <RotationWorkbench model={model} names={names} /> : null}
    </section>
    <details className="panel investigation-card"><summary>Supported semantics and limits</summary>
      <p>Engine {ENGINE_VERSION} evaluates recorded configuration. Query states are supported, refuted, unknown, or conflicting. They are separate from configured, observed, and inferred evidence.</p>
      <div className="table-scroll"><table><thead><tr><th>Workflow</th><th>Supported</th><th>Stays unknown or outside the model</th></tr></thead><tbody>
        <tr><td>Access compiler</td><td>Exact permission IDs, consent audiences, direct application/group assignments, nested membership, explicit role scopes and typed ownership/federation paths</td><td>Successful authentication, resource enforcement, nested application assignment, eligible-role activation</td></tr>
        <tr><td>Time and credentials</td><td>Collected-snapshot witnesses, source validity intersections, declared deployment/retirement and workload dependencies</td><td>Continuity between scans, secret possession, observed deployment</td></tr>
        <tr><td>Policy</td><td>Exact user/group/resource, platform, client and location selectors; block, MFA, compliant and hybrid-joined device controls</td><td>Uncollected policy fields, device filters, risk, workload targeting, authentication strengths, session controls and service dependencies</td></tr>
        <tr><td>Federation</td><td>Case-sensitive exact v1.0 issuer/subject with one audience</td><td>Preview expressions, flattened historical audiences, token authenticity</td></tr>
        <tr><td>Plans, contracts and replay</td><td>Bounded weighted search, protected integrations, declarative intent, SHA-256 integrity and deterministic offline replay</td><td>Global optimality after search limits, absence with incomplete evidence, Microsoft source authenticity</td></tr>
      </tbody></table></div><p>Default queries stop at 50,000 steps, 128 paths and depth 12. Each result exposes its own budget. Optional evidence uses only existing read permissions; this workspace cannot consent or execute a proposed read.</p>
    </details>
  </>;
}

function TemporalView({ models, query }: { models: ReturnType<typeof compileSnapshot>[]; query: AuthorizationQuery }) {
  const result = useMemo(() => reconstructPaths(models, query), [models, query]);
  return <><ResultSummary result={result}><p>{models.length} retained snapshots. A scan is not an atomic transaction; repeated observations do not prove continuous existence.</p></ResultSummary><div className="table-scroll"><table><thead><tr><th>Path</th><th>Collected instants</th><th>Source validity</th><th>Uncertain between scans</th></tr></thead><tbody>{result.paths.map((p, i) => <tr key={i}><td>{p.edges.join(" → ")}</td><td>{p.collectedInstants.join(", ")}</td><td>{p.validity}{p.sourceValidity ? <p>{p.sourceValidity.startsAt} → {p.sourceValidity.endsAt}</p> : null}</td><td>{p.uncertainIntervals.map(w => <p key={w.startsAt}>{w.startsAt} → {w.endsAt}</p>)}</td></tr>)}</tbody></table></div><JsonDetails value={result} /></>;
}
function GapView({ proof }: { proof: NonNullable<ReturnType<typeof evaluateAuthorization>> }) {
  const result = useMemo(() => planEvidenceGaps(proof), [proof]);
  return <><ResultSummary result={result}><p>Declared cost counts endpoint templates. Current session permissions are not inferred from historical coverage. Verify prerequisites before collecting.</p></ResultSummary>{result.plans.map((p, i) => <article className="engine-result" key={i}><h3>Read plan {i + 1} · cost {p.cost}</h3><p>May resolve: {p.mayResolve.join(", ") || "No recorded evidence gap"}</p><ul>{p.endpoints.map(e => <li key={e}><code>GET {e}</code></li>)}</ul><p>Read scopes: {p.requiredScopes.join(", ") || "None"}</p><p>Permission availability is unverified; these proposals do not change consent.</p></article>)}<JsonDetails value={result} /></>;
}
