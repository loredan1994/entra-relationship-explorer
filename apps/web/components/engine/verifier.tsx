"use client";
import { useEffect, useRef, useState } from "react";
import { exportInvestigation, verifyInvestigation, type AuthorizationQuery, type EvidenceModel } from "@entra-explorer/engine";
import { download, JsonDetails, ResultSummary } from "./common";

export function PortableWorkbench({ model, query }: { model: EvidenceModel; query: AuthorizationQuery | null }) {
  return <><p>Export the selected query with the facts required for independent offline replay. Labels and unrelated credential metadata are omitted. SHA-256 detects modification; it does not authenticate Microsoft as the source.</p>
    <PortableExport key={JSON.stringify(query)} model={model} query={query} />
    <PortableImport />
    <p>Offline CLI: <code>pnpm engine verify entra-investigation.json</code>.</p>
  </>;
}

function PortableExport({ model, query }: { model: EvidenceModel; query: AuthorizationQuery | null }) {
  const [pseudonyms, setPseudonyms] = useState(true), [acknowledged, setAcknowledged] = useState(false);
  const [status, setStatus] = useState(""), [mapping, setMapping] = useState<Record<string, string> | null>(null), [pending, setPending] = useState(false);
  const operation = useRef(0), busy = useRef(false);
  useEffect(() => () => { operation.current++; }, []);
  function invalidate() {
    operation.current++; busy.current = false;
    setPending(false); setMapping(null); setStatus("");
  }
  async function exportPacket() {
    if (!query || !acknowledged || busy.current) return;
    const request = ++operation.current;
    busy.current = true; setPending(true); setMapping(null); setStatus("Preparing the investigation package locally…");
    try {
      const result = await exportInvestigation(model, query, pseudonyms ? "pseudonymized" : "identified");
      if (request !== operation.current) return;
      download(result.package, "entra-investigation.json");
      setMapping(pseudonyms ? result.privateMapping : null);
      setStatus("Exported a minimal fact projection and replayable proof. The private identity mapping is not in the package.");
    } catch (e) {
      if (request === operation.current) setStatus(e instanceof Error ? e.message : "Export failed.");
    } finally {
      if (request === operation.current) { busy.current = false; setPending(false); }
    }
  }
  return <div aria-busy={pending}>
    {!query ? <p>Evaluate a valid query above to enable package export. You can still verify an existing package below.</p> : null}
    <label className="engine-checkbox"><input type="checkbox" checked={pseudonyms} onChange={e => { invalidate(); setPseudonyms(e.target.checked); }} />Replace identifiers with stable per-export pseudonyms</label>
    <label className="engine-checkbox"><input type="checkbox" checked={acknowledged} onChange={e => { invalidate(); setAcknowledged(e.target.checked); }} />I understand this export contains sensitive tenant relationships, even with pseudonyms.</label>
    <div className="detail-actions"><button className="button button-primary" type="button" disabled={!query || !acknowledged || pending} onClick={() => { void exportPacket(); }}>{pending ? "Exporting investigation package…" : "Export investigation package"}</button>{mapping ? <button className="button button-secondary" type="button" onClick={() => download(mapping, "entra-private-identity-mapping.json")}>Save private mapping separately</button> : null}</div>
    {status ? <p role="status">{status}</p> : null}
  </div>;
}

function PortableImport() {
  const [status, setStatus] = useState(""), [pending, setPending] = useState(false);
  const [verified, setVerified] = useState<Awaited<ReturnType<typeof verifyInvestigation>> | null>(null);
  const operation = useRef(0);
  useEffect(() => () => { operation.current++; }, []);
  async function importPacket(file?: File) {
    if (!file) return;
    const request = ++operation.current;
    setVerified(null); setPending(true); setStatus(`Verifying ${file.name} locally…`);
    try {
      if (file.size > 5_000_000) throw new Error("Investigation packages must be at most 5 MB.");
      const source = await file.text();
      if (request !== operation.current) return;
      const result = await verifyInvestigation(source);
      if (request !== operation.current) return;
      setVerified(result); setStatus(`Integrity and proof replay verified locally for ${file.name}. Imported facts remain separate from the active tenant.`);
    } catch (e) {
      if (request === operation.current) setStatus(e instanceof Error ? e.message : "Verification failed.");
    } finally {
      if (request === operation.current) setPending(false);
    }
  }
  return <div aria-busy={pending}>
    <h3>Verify an offline package</h3><p>Choose one JSON document, maximum 5 MB. It is validated and replayed in this browser, never uploaded or merged with your tenant data. Selecting another file replaces the pending verification.</p>
    <label className="engine-field">Investigation package<input type="file" accept=".json,application/json" onChange={e => { void importPacket(e.target.files?.[0]); e.target.value = ""; }} /></label>
    {status ? <p role="status">{status}</p> : null}{verified ? <><ResultSummary result={verified.proof}><p>{verified.notice}</p></ResultSummary><JsonDetails value={verified.proof} /></> : null}
  </div>;
}
