"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { Exposure, PermissionGrant } from "@/server/tenant-security";
import { PermissionPills } from "./permission-pills";

type SortKey = "caller" | "resource" | "type" | "exposure";
type ExposureFilter = "all" | Exposure;
type AccessFilter = "all" | "application" | "delegated";

const PAGE_SIZE = 50;
const EXPOSURE_ORDER: Record<Exposure, number> = { high: 0, review: 1, low: 2 };
const exposureLabel: Record<Exposure, string> = { high: "High exposure", review: "Review", low: "Low" };

export function PermissionsTable({ grants }: { grants: PermissionGrant[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("exposure");
  const [ascending, setAscending] = useState(true);
  const [query, setQuery] = useState("");
  const [exposureFilter, setExposureFilter] = useState<ExposureFilter>("all");
  const [accessFilter, setAccessFilter] = useState<AccessFilter>("all");
  const [writeOnly, setWriteOnly] = useState(false);
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const counts = useMemo(() => ({
    high: grants.filter((grant) => grant.exposure === "high").length,
    review: grants.filter((grant) => grant.exposure === "review").length,
    low: grants.filter((grant) => grant.exposure === "low").length,
  }), [grants]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return grants.filter((grant) => {
      if (exposureFilter !== "all" && grant.exposure !== exposureFilter) return false;
      if (accessFilter !== "all" && grant.accessType !== accessFilter) return false;
      if (writeOnly && grant.writeCapable.length === 0) return false;
      if (!needle) return true;
      return grant.caller.label.toLocaleLowerCase().includes(needle)
        || grant.resource.label.toLocaleLowerCase().includes(needle)
        || grant.permissions.some((permission) => permission.toLocaleLowerCase().includes(needle));
    });
  }, [grants, query, exposureFilter, accessFilter, writeOnly]);

  const sorted = useMemo(() => {
    const compare = (a: PermissionGrant, b: PermissionGrant) => {
      if (sortKey === "exposure") return EXPOSURE_ORDER[a.exposure] - EXPOSURE_ORDER[b.exposure] || a.caller.label.localeCompare(b.caller.label);
      if (sortKey === "caller") return a.caller.label.localeCompare(b.caller.label);
      if (sortKey === "resource") return a.resource.label.localeCompare(b.resource.label);
      return a.accessType.localeCompare(b.accessType) || a.caller.label.localeCompare(b.caller.label);
    };
    return [...filtered].sort((a, b) => compare(a, b) * (ascending ? 1 : -1));
  }, [ascending, sortKey, filtered]);

  const visible = sorted.slice(0, visibleCount);

  function chooseSort(next: SortKey) {
    if (sortKey === next) setAscending((current) => !current);
    else { setSortKey(next); setAscending(true); }
  }

  function chooseExposure(next: ExposureFilter) {
    setExposureFilter((current) => current === next ? "all" : next);
    setVisibleCount(PAGE_SIZE);
  }

  const header = (key: SortKey, label: string) => (
    <button onClick={() => chooseSort(key)}>
      {label} {sortKey === key ? <span aria-hidden="true">{ascending ? "↑" : "↓"}</span> : null}
    </button>
  );
  const sortDirection = (key: SortKey) => sortKey === key ? (ascending ? "ascending" as const : "descending" as const) : "none" as const;

  if (grants.length === 0) {
    return <div className="panel map-empty compact"><h2>No configured grants</h2><p>The current snapshot contains no application or delegated permission grants.</p></div>;
  }

  return (
    <>
      <div className="table-controls" role="group" aria-label="Filter the permission inventory">
        <label className="table-search">
          <span className="sr-only">Search callers, resources, or permissions</span>
          <input
            value={query}
            onChange={(event) => { setQuery(event.target.value); setVisibleCount(PAGE_SIZE); }}
            placeholder="Filter by caller, resource, or permission"
          />
        </label>
        <div className="filter-chips" aria-label="Exposure filter">
          <button type="button" aria-pressed={exposureFilter === "high"} className="chip chip-high" onClick={() => chooseExposure("high")}>High · {counts.high}</button>
          <button type="button" aria-pressed={exposureFilter === "review"} className="chip chip-review" onClick={() => chooseExposure("review")}>Review · {counts.review}</button>
          <button type="button" aria-pressed={exposureFilter === "low"} className="chip chip-low" onClick={() => chooseExposure("low")}>Low · {counts.low}</button>
        </div>
        <label className="control-select">
          <span>Access type</span>
          <select value={accessFilter} onChange={(event) => { setAccessFilter(event.target.value as AccessFilter); setVisibleCount(PAGE_SIZE); }}>
            <option value="all">All</option>
            <option value="application">Application (runs as itself)</option>
            <option value="delegated">Delegated (signed-in person)</option>
          </select>
        </label>
        <label className="control-checkbox">
          <input type="checkbox" checked={writeOnly} onChange={(event) => { setWriteOnly(event.target.checked); setVisibleCount(PAGE_SIZE); }} />
          <span>Write-capable only</span>
        </label>
      </div>

      <p className="table-result-count" role="status">
        Showing {visible.length} of {filtered.length} grants{filtered.length !== grants.length ? ` (filtered from ${grants.length})` : ""}, most exposed first.
      </p>

      <div className="data-table-wrap">
        <table className="data-table permissions-data-table">
          <caption className="sr-only">Configured application permission inventory with exposure assessment</caption>
          <thead><tr>
            <th aria-sort={sortDirection("exposure")}>{header("exposure", "Exposure")}</th>
            <th aria-sort={sortDirection("caller")}>{header("caller", "Caller")}</th>
            <th aria-sort={sortDirection("type")}>{header("type", "Access type")}</th>
            <th aria-sort={sortDirection("resource")}>{header("resource", "Resource")}</th>
            <th>Permissions</th>
            <th>Evidence</th>
          </tr></thead>
          <tbody>
            {visible.map((grant) => (
              <tr key={grant.edgeId}>
                <td>
                  <span className={`severity-pill exposure-${grant.exposure}`}>{exposureLabel[grant.exposure]}</span>
                  <small className="exposure-reason">{grant.reason}</small>
                </td>
                <td><strong>{grant.caller.label}</strong><small>Tenant identity</small></td>
                <td>{grant.accessType === "application" ? "Application" : "Delegated"}<small>{grant.accessType === "application" ? "Runs as itself" : "Acts for a signed-in person"}</small></td>
                <td><strong>{grant.resource.label}</strong><small>Resource identity</small></td>
                <td className="permissions-cell">
                  <PermissionPills permissions={grant.permissions} limit={4} />
                </td>
                <td><Link className="text-link" href={`/map?edge=${grant.edgeId}`}>Inspect</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 ? <div className="table-empty"><strong>No grants match the current filters.</strong><button type="button" className="text-button" onClick={() => { setQuery(""); setExposureFilter("all"); setAccessFilter("all"); setWriteOnly(false); }}>Clear filters</button></div> : null}
      </div>

      {sorted.length > visibleCount ? (
        <div className="table-load-more">
          <button type="button" className="button button-secondary" onClick={() => setVisibleCount((current) => current + PAGE_SIZE)}>
            Show {Math.min(PAGE_SIZE, sorted.length - visibleCount)} more of {sorted.length - visibleCount} remaining
          </button>
        </div>
      ) : null}
    </>
  );
}
