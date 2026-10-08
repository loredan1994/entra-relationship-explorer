"use client";
import { useState } from "react";
import { exportInvestigation, verifyInvestigation, type AuthorizationQuery, type EvidenceModel } from "@entra-explorer/engine";
import { download, JsonDetails, ResultSummary } from "./common";

export function PortableWorkbench({ model, query }: { model: EvidenceModel; query: AuthorizationQuery }) {
  const [pseudonyms, setPseudonyms] = useState(true), [acknowledged, setAcknowledged] = useState(false);
  const [status, setStatus] = useState(""), [mapping, setMapping] = useState<Record<string, string> | null>(null), [verified, setVerified] = useState<Awaited<ReturnType<typeof verifyInvestigation>> | null>(null);
  async function exportPacket() {
    try { const result = await exportInvestigation(model, query, pseudonyms ? "pseudonymized" : "identified"); download(result.package, "entra-investigation.json"); setMapping(pseudonyms ? result.privateMapping : null); setStatus("Exported a minimal fact projection and replayable proof. The private identity mapping is not in the package."); }
    catch (e) { setStatus(e instanceof Error ? e.message : "Export failed."); }
  }
  async function importPacket(file?: File) {
    if (!file) return;
    setVerified(null);
    try { if (file.size > 5_000_000) throw new Error("Investigation packages must be at most 5 MB."); setVerified(await verifyInvestigation(await file.text())); setStatus("Integrity and proof replay verified locally. Imported facts remain separate from the active tenant."); }
    catch (e) { setStatus(e instanceof Error ? e.message : "Verification failed."); }
  }
  return <><p>Export the selected query with the facts required for independent offline replay. Labels and unrelated credential metadata are omitted. SHA-256 detects modification; it does not authenticate Microsoft as the source.</p>
    <label className="engine-checkbox"><input type="checkbox" checked={pseudonyms} onChange={e => setPseudonyms(e.target.checked)} />Replace identifiers with stable per-export pseudonyms</label>
    <label className="engine-checkbox"><input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)} />I understand this export contains sensitive tenant relationships, even with pseudonyms.</label>
    <div className="detail-actions"><button className="button button-primary" type="button" disabled={!acknowledged} onClick={() => { void exportPacket(); }}>Export investigation package</button>{mapping ? <button className="button button-secondary" type="button" onClick={() => download(mapping, "entra-private-identity-mapping.json")}>Save private mapping separately</button> : null}</div>
    <h3>Verify an offline package</h3><p>Choose one JSON document, maximum 5 MB. It is validated and replayed in this browser, never uploaded or merged with your tenant data.</p><label className="engine-field">Investigation package<input type="file" accept=".json,application/json" onChange={e => { void importPacket(e.target.files?.[0]); e.target.value = ""; }} /></label>
    {status ? <p role="status">{status}</p> : null}{verified ? <><ResultSummary result={verified.proof}><p>{verified.notice}</p></ResultSummary><JsonDetails value={verified.proof} /></> : null}
    <p>Offline CLI: <code>pnpm engine verify entra-investigation.json</code>.</p>
  </>;
}
