"use client";

import { useEffect, useRef, useState } from "react";
import { ExportLink } from "./export-link";

interface JobView {
  id: string;
  status: "queued" | "running" | "complete" | "failed" | "cancel_requested" | "cancelled";
  stage: string;
  collected: number;
  detail: string;
  completion: "complete" | "partial" | null;
  error: string | null;
}

function isActive(job: JobView | null) {
  return job?.status === "queued" || job?.status === "running" || job?.status === "cancel_requested";
}

function readJob(payload: Record<string, unknown>, expectedId?: string): JobView {
  const job = payload.job as Partial<JobView> | undefined;
  if (!job || typeof job.id !== "string" || !job.id || (expectedId !== undefined && job.id !== expectedId)
    || !["queued", "running", "complete", "failed", "cancel_requested", "cancelled"].includes(job.status ?? "")
    || typeof job.stage !== "string" || typeof job.detail !== "string"
    || typeof job.collected !== "number" || !Number.isFinite(job.collected) || job.collected < 0
    || (job.completion !== null && !["complete", "partial"].includes(job.completion ?? ""))
    || (job.error !== null && typeof job.error !== "string")) {
    throw new Error("The server returned an invalid scan response. Try again.");
  }
  return job as JobView;
}

class AuthenticationRequiredError extends Error {
  constructor() { super("Your session has expired. Sign in again to refresh scan status and start or cancel scans."); }
}

async function request(url: string, method: string, signal: AbortSignal, failure: string): Promise<Record<string, unknown>> {
  const deadline = new AbortController();
  const timer = window.setTimeout(() => deadline.abort(), 15_000);
  try {
    const response = await fetch(url, {
      method, cache: "no-store", signal: AbortSignal.any([signal, deadline.signal]),
      ...(method === "GET" ? {} : { headers: { "content-type": "application/json" } }),
    });
    if (response.status === 401) throw new AuthenticationRequiredError();
    const payload: unknown = await response.json();
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error(failure);
    const body = payload as Record<string, unknown>;
    if (!response.ok) throw new Error(typeof body.error === "string" ? body.error : failure);
    return body;
  } catch (error) {
    if (deadline.signal.aborted) throw new Error(`${failure} The request timed out. Try again.`, { cause: error });
    if (error instanceof SyntaxError || error instanceof TypeError) throw new Error(`${failure} Check the connection and try again.`, { cause: error });
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

export function ScanControl({ enabled, connected, initialJob, exportAvailable = false, snapshotId }: { enabled: boolean; connected: boolean; initialJob: JobView | null; exportAvailable?: boolean; snapshotId?: string }) {
  const [job, setJob] = useState<JobView | null>(initialJob);
  const [busy, setBusy] = useState<"start" | "cancel" | "sign-out" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [pollEpoch, setPollEpoch] = useState(0);
  const [authenticationRequired, setAuthenticationRequired] = useState(false);
  const mounted = useRef(false);
  const actionRequest = useRef<AbortController | null>(null);
  const pollRequest = useRef<AbortController | null>(null);
  const active = isActive(job);
  const jobId = job?.id;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      actionRequest.current?.abort();
      pollRequest.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!enabled || !connected || authenticationRequired || !active || !jobId || busy) return;
    const controller = new AbortController();
    pollRequest.current = controller;
    let failures = 0;
    let timer: number;
    async function poll() {
      let keepPolling = true;
      try {
        const payload = await request(`/api/v1/scans/${encodeURIComponent(jobId!)}`, "GET", controller.signal, "Scan status could not be refreshed.");
        if (controller.signal.aborted) return;
        const next = readJob(payload, jobId);
        keepPolling = isActive(next);
        failures = 0;
        setJob(next);
        setPollError(null);
        if (next.status === "complete") window.location.reload();
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error instanceof AuthenticationRequiredError) {
          keepPolling = false;
          setAuthenticationRequired(true);
          setPollError(error.message);
          return;
        }
        failures += 1;
        setPollError(`${error instanceof Error ? error.message : "Scan status could not be refreshed."} Retrying automatically.`);
      } finally {
        // Wait after the response: slow or failed requests never overlap.
        if (!controller.signal.aborted && keepPolling) timer = window.setTimeout(poll, Math.min(1_000 * 2 ** Math.min(failures, 4), 10_000));
      }
    }
    timer = window.setTimeout(poll, 1_000);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
      if (pollRequest.current === controller) pollRequest.current = null;
    };
  }, [enabled, connected, authenticationRequired, active, jobId, busy, pollEpoch]);

  function beginAction(action: NonNullable<typeof busy>) {
    if (actionRequest.current) return null;
    const controller = new AbortController();
    actionRequest.current = controller;
    // Invalidate a status response immediately, before React runs effect cleanup.
    pollRequest.current?.abort();
    setPollEpoch(epoch => epoch + 1);
    setBusy(action);
    setError(null);
    setPollError(null);
    return controller;
  }

  async function runAction(action: NonNullable<typeof busy>, url: string, method: string, failure: string, apply: (payload: Record<string, unknown>) => void) {
    const controller = beginAction(action);
    if (!controller) return;
    try {
      const payload = await request(url, method, controller.signal, failure);
      if (mounted.current && !controller.signal.aborted) apply(payload);
    } catch (error) {
      if (mounted.current && !controller.signal.aborted) {
        if (error instanceof AuthenticationRequiredError) setAuthenticationRequired(true);
        setError(error instanceof Error ? error.message : failure);
      }
    } finally {
      if (actionRequest.current === controller) actionRequest.current = null;
      if (mounted.current) setBusy(null);
    }
  }

  function startScan() {
    if (active) return;
    return runAction("start", "/api/v1/scans", "POST", "The scan could not start.", payload => setJob(readJob(payload)));
  }

  function signOut() {
    return runAction("sign-out", "/api/auth/sign-out", "POST", "Sign-out failed.", payload => {
      if (payload.signedOut !== true) throw new Error("Sign-out could not be confirmed. Try again.");
      window.location.reload();
    });
  }

  function cancelScan() {
    if (!job || !active || job.status === "cancel_requested") return;
    return runAction("cancel", `/api/v1/scans/${encodeURIComponent(job.id)}`, "DELETE", "Cancellation failed.", payload => setJob(readJob(payload, job.id)));
  }

  return (
    <div className="scan-control">
      {!enabled ? <p>To protect the boundary, there is no sign-in or consent action until live mode is configured locally.</p> : !connected || authenticationRequired ? <a className="button button-primary" href="/api/auth/sign-in">{authenticationRequired ? "Sign in again" : "Sign in to configured tenant"}</a> : (
        <div className="scan-actions">
          <button className="button button-primary" type="button" disabled={Boolean(busy) || active} onClick={startScan}>{busy === "start" ? "Starting scan…" : active ? "Scan in progress" : "Start read-only scan"}</button>
          {active ? <button className="button button-secondary" type="button" disabled={Boolean(busy) || job?.status === "cancel_requested"} onClick={cancelScan}>{busy === "cancel" ? "Requesting cancellation…" : job?.status === "cancel_requested" ? "Cancelling safely" : "Cancel scan"}</button> : null}
          {exportAvailable && snapshotId ? <ExportLink className="button button-secondary" href={`/api/export/relationships.csv?snapshot=${encodeURIComponent(snapshotId)}`}>Export relationship table</ExportLink> : <span>Complete a read-only scan to export tenant relationships.</span>}
          <button className="text-button" type="button" disabled={Boolean(busy)} onClick={signOut}>{busy === "sign-out" ? "Signing out…" : "Sign out"}</button>
        </div>
      )}
      {error ? <p role="alert">{error}</p> : null}
      {pollError ? <p role="alert">{pollError}</p> : null}
      {authenticationRequired && job ? <p>Progress below is the last known status. Sign in again to check whether the scan is still running.</p> : null}
      {job ? <div className="scan-progress" role="status" aria-live="polite"><strong>{job.status === "complete" ? "Scan complete" : job.status === "failed" ? "Scan stopped" : job.status === "cancelled" ? "Scan cancelled" : job.status === "cancel_requested" ? "Cancellation requested" : job.stage}</strong><span>{job.detail} · {job.collected} records</span>{job.error ? <small>{job.error}</small> : null}</div> : null}
    </div>
  );
}
