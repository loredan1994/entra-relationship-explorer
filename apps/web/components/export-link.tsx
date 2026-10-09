"use client";

import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from "react";

type ExportState = "idle" | "pending" | "ready" | "unauthorized" | "stale" | "error" | "timeout";
interface ExportLinkProps { href: string; children: ReactNode; className?: string; }

function downloadName(disposition: string | null, href: string) {
  const encoded = disposition?.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plain = disposition?.match(/filename\s*=\s*(?:"([^"]*)"|([^;\s]+))/i);
  let name = plain?.[1] ?? plain?.[2] ?? new URL(href, window.location.href).pathname.split("/").at(-1) ?? "entra-evidence-export";
  if (encoded) {
    try { name = decodeURIComponent(encoded); } catch { /* Use the plain name when the encoded header is malformed. */ }
  }
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^\.+/, "").slice(0, 160) || "entra-evidence-export";
}

/** Keep a real download destination while protecting an in-progress review from export errors. */
export function ExportLink(props: ExportLinkProps) {
  return <ExportAction key={props.href} {...props} />;
}

function ExportAction({ href, children, className }: ExportLinkProps) {
  const [state, setState] = useState<ExportState>("idle");
  const operation = useRef(0), pending = useRef<AbortController | null>(null);
  useEffect(() => () => { operation.current++; pending.current?.abort(); }, []);

  async function startExport() {
    if (pending.current) return;
    const controller = new AbortController();
    const request = ++operation.current;
    pending.current = controller;
    setState("pending");
    let timedOut = false;
    const timeout = window.setTimeout(() => { timedOut = true; controller.abort(); }, 30_000);
    try {
      const response = await fetch(href, { cache: "no-store", credentials: "same-origin", signal: controller.signal });
      if (request !== operation.current) return;
      if (!response.ok) { setState(response.status === 401 ? "unauthorized" : response.status === 409 ? "stale" : "error"); return; }
      const payload = await response.blob();
      if (request !== operation.current) return;
      if (controller.signal.aborted) { setState(timedOut ? "timeout" : "error"); return; }
      const url = URL.createObjectURL(payload);
      try {
        const anchor = document.createElement("a");
        anchor.href = url; anchor.download = downloadName(response.headers.get("content-disposition"), href);
        document.body.append(anchor);
        try { anchor.click(); } finally { anchor.remove(); }
        setState("ready");
      } finally {
        // Let the browser consume the download URL before releasing its data.
        window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      }
    } catch {
      if (request === operation.current) setState(timedOut ? "timeout" : "error");
    } finally {
      window.clearTimeout(timeout);
      if (request === operation.current) pending.current = null;
    }
  }
  function click(event: MouseEvent<HTMLAnchorElement>) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    void startExport();
  }
  const retryable = state === "error" || state === "timeout" || state === "unauthorized";
  return <span className="export-control">
    <a href={href} className={className} aria-disabled={state === "pending" || undefined} aria-busy={state === "pending" || undefined} onClick={click}>{children}</a>
    {state !== "idle" ? <span className="export-status" role="status">
      {state === "pending" ? "Preparing the download…" : state === "ready" ? "Download prepared." : state === "unauthorized" ? <>Sign in again in Settings, then retry this export. Your edits remain in this page. <a href="/settings" target="_blank" rel="noopener noreferrer">Open Settings in another tab</a></> : state === "stale" ? "The displayed snapshot is no longer available for this export. Copy any unsaved edits before reloading, then review the current evidence before exporting." : state === "timeout" ? "The export timed out. Your edits remain in this page. Retry when the workspace is reachable." : "The export could not be downloaded. Your edits remain in this page."}
    </span> : null}
    {retryable ? <button type="button" className="text-button" onClick={() => { void startExport(); }}>Retry export</button> : null}
  </span>;
}
