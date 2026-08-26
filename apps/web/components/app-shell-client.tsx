"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import type { ConnectionState } from "@/server/current-snapshot";

const navItems = [
  { href: "/overview", label: "Overview" },
  { href: "/map", label: "Relationship map" },
  { href: "/permissions", label: "Permissions" },
  { href: "/changes", label: "Changes" },
  { href: "/security", label: "Threat workspace" },
  { href: "/settings", label: "Settings" },
];

function relativeTime(value: string): string {
  const elapsed = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(elapsed) || elapsed < 0) return "just now";
  const minutes = Math.round(elapsed / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"} ago`;
}

function ConnectionBanner({ connection }: { connection: ConnectionState }) {
  if (connection === "connected") return null;
  if (connection === "signed-out") {
    return (
      <div className="connection-banner banner-warning" role="status">
        <div>
          <strong>You are signed out, so everything below is sample data.</strong>
          <span>People like “Maya Chen” and apps like “Clean Project” are synthetic examples — none of it comes from your tenant. Sessions end after a period of inactivity; sign in again to see your own snapshot.</span>
        </div>
        <a className="button button-primary" href="/api/auth/sign-in">Sign in to your tenant</a>
      </div>
    );
  }
  if (connection === "no-snapshot") {
    return (
      <div className="connection-banner banner-info" role="status">
        <div>
          <strong>Connected to your tenant — no scan has completed yet.</strong>
          <span>You are viewing sample data until the first read-only scan finishes. Start one from Settings; it never changes anything in Entra.</span>
        </div>
        <Link className="button button-primary" href="/settings">Run the first scan</Link>
      </div>
    );
  }
  return (
    <div className="connection-banner banner-demo" role="status">
      <div>
        <strong>Demo workspace.</strong>
        <span>Every record on screen is synthetic sample data. Connect a tenant to explore your own directory.</span>
      </div>
    </div>
  );
}

export function AppShellClient({
  children,
  tenantLabel,
  scannedAt,
  mode,
  connection,
}: {
  children: ReactNode;
  tenantLabel: string;
  scannedAt: string;
  mode: "fixture" | "tenant";
  connection: ConnectionState;
}) {
  const pathname = usePathname();
  const scanDate = new Intl.DateTimeFormat("en", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(scannedAt));
  const live = mode === "tenant";

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" href="/overview" aria-label="Entra Relationship Explorer home">
          <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
          <span><strong>Entra</strong><small>Relationship Explorer</small></span>
        </Link>
        <div className="tenant-context" aria-label="Current data source">
          <span className={`status-dot ${live ? "" : "status-sample"}`} aria-hidden="true" />
          <span>
            <strong>{tenantLabel}</strong>
            <small suppressHydrationWarning>{live ? `Live tenant snapshot · ${relativeTime(scannedAt)} (${scanDate})` : `Sample data · not from a tenant`}</small>
          </span>
        </div>
        <form className="global-search" action="/map" role="search">
          <label className="sr-only" htmlFor="global-search">Search relationships</label>
          <span aria-hidden="true">⌕</span>
          <input id="global-search" name="q" placeholder="Search names or permissions" />
        </form>
        <span className={`read-only-badge ${live ? "" : "badge-sample"}`}>{live ? "Read-only · Live tenant" : "Read-only · Sample data"}</span>
      </header>
      <nav className="primary-nav" aria-label="Product sections">
        {navItems.map((item) => {
          const active = pathname === item.href || (item.href === "/map" && pathname.startsWith("/applications/"));
          return <Link key={item.href} href={item.href} aria-current={active ? "page" : undefined}>{item.label}</Link>;
        })}
      </nav>
      <ConnectionBanner connection={connection} />
      <main id="main-content">{children}</main>
    </div>
  );
}
