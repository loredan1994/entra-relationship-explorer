"use client";

import { useEffect, useState } from "react";

interface JobView {
  id: string;
  status: "queued" | "running" | "complete" | "failed" | "cancel_requested" | "cancelled";
  stage: string;
  collected: number;
  detail: string;
  completion: "complete" | "partial" | null;
  error: string | null;
}

export function ScanControl({ enabled, connected, initialJob }: { enabled: boolean; connected: boolean; initialJob: JobView | null }) {
  const [job, setJob] = useState<JobView | null>(initialJob);
  const [busy, setBusy] = useState(false);
  const active = job?.status === "queued" || job?.status === "running" || job?.status === "cancel_requested";

  useEffect(() => {
    if (!active || !job) return;
    const timer = window.setInterval(async () => {
      const response = await fetch(`/api/v1/scans/${encodeURIComponent(job.id)}`, { cache: "no-store" });
      if (!response.ok) return;
      const payload = await response.json() as { job: JobView };
      setJob(payload.job);
      if (payload.job.status === "complete") window.location.reload();
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [active, job]);

  async function startScan() {
    setBusy(true);
    try {
      const response = await fetch("/api/v1/scans", { method: "POST", headers: { "content-type": "application/json" } });
      const payload = await response.json() as { job?: JobView; error?: string };
      if (!response.ok || !payload.job) throw new Error(payload.error || "The scan could not start.");
      setJob(payload.job);
    } catch (error) {
      setJob({ id: "local-error", status: "failed", stage: "start", collected: 0, detail: "The scan could not start", completion: null, error: error instanceof Error ? error.message : "The scan could not start." });
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await fetch("/api/auth/sign-out", { method: "POST", headers: { "content-type": "application/json" } });
    window.location.reload();
  }
  async function cancelScan() {
    if (!job || !active || job.status === "cancel_requested") return;
    const response = await fetch(`/api/v1/scans/${encodeURIComponent(job.id)}`, { method: "DELETE", headers: { "content-type": "application/json" } });
    const payload = await response.json() as { job?: JobView; error?: string };
    if (payload.job) setJob(payload.job); else if (!response.ok) setJob({ ...job, error: payload.error ?? "Cancellation failed." });
  }

  return (
    <div className="scan-control">
      {!enabled ? <p>To protect the boundary, there is no sign-in or consent action until live mode is configured locally.</p> : !connected ? <a className="button button-primary" href="/api/auth/sign-in">Sign in to configured tenant</a> : (
        <div className="scan-actions">
          <button className="button button-primary" type="button" disabled={busy || active} onClick={startScan}>{active ? "Scan in progress" : "Start read-only scan"}</button>
          {active ? <button className="button button-secondary" type="button" disabled={job?.status === "cancel_requested"} onClick={cancelScan}>{job?.status === "cancel_requested" ? "Cancelling safely" : "Cancel scan"}</button> : null}
          <a className="button button-secondary" href="/api/v1/exports/relationships.csv">Export relationship table</a>
          <button className="text-button" type="button" onClick={signOut}>Sign out</button>
        </div>
      )}
      {job ? <div className="scan-progress" role="status" aria-live="polite"><strong>{job.status === "complete" ? "Scan complete" : job.status === "failed" ? "Scan stopped" : job.status === "cancelled" ? "Scan cancelled" : job.status === "cancel_requested" ? "Cancellation requested" : job.stage}</strong><span>{job.detail} · {job.collected} records</span>{job.error ? <small>{job.error}</small> : null}</div> : null}
    </div>
  );
}
