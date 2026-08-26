"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

const navItems = [
  { href: "/overview", label: "Overview" },
  { href: "/map", label: "Relationship map" },
  { href: "/permissions", label: "Permissions" },
  { href: "/changes", label: "Changes" },
  { href: "/security", label: "Threat workspace" },
  { href: "/settings", label: "Settings" },
];

export function AppShellClient({
  children,
  tenantLabel,
  scannedAt,
  mode,
}: {
  children: ReactNode;
  tenantLabel: string;
  scannedAt: string;
  mode: "fixture" | "tenant";
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
  const sourceLabel = mode === "tenant" ? "Tenant snapshot" : "Fixture mode";

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" href="/overview" aria-label="Entra Relationship Explorer home">
          <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
          <span><strong>Entra</strong><small>Relationship Explorer</small></span>
        </Link>
        <div className="tenant-context" aria-label="Current data source">
          <span className="status-dot" aria-hidden="true" />
          <span><strong>{tenantLabel}</strong><small>{sourceLabel} · scanned {scanDate}</small></span>
        </div>
        <form className="global-search" action="/map" role="search">
          <label className="sr-only" htmlFor="global-search">Search relationships</label>
          <span aria-hidden="true">⌕</span>
          <input id="global-search" name="q" placeholder="Search names or permissions" />
        </form>
        <span className="read-only-badge">Read-only {mode === "fixture" ? "fixture" : "tenant"}</span>
      </header>
      <nav className="primary-nav" aria-label="Product sections">
        {navItems.map((item) => {
          const active = pathname === item.href || (item.href === "/map" && pathname.startsWith("/applications/"));
          return <Link key={item.href} href={item.href} aria-current={active ? "page" : undefined}>{item.label}</Link>;
        })}
      </nav>
      <main id="main-content">{children}</main>
    </div>
  );
}
