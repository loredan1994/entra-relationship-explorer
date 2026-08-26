"use client";

import type { RelationshipView } from "@entra-explorer/domain";
import Link from "next/link";
import { useMemo, useState } from "react";

type SortKey = "source" | "target" | "permission" | "type";

export function PermissionsTable({ views }: { views: RelationshipView[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("source");
  const [ascending, setAscending] = useState(true);
  const sorted = useMemo(() => {
    const value = (view: RelationshipView) => {
      if (sortKey === "source") return view.source.label;
      if (sortKey === "target") return view.target.label;
      if (sortKey === "permission") return view.edge.permissions.join(", ");
      return view.edge.type;
    };
    return [...views].sort((a, b) => value(a).localeCompare(value(b)) * (ascending ? 1 : -1));
  }, [ascending, sortKey, views]);

  function chooseSort(next: SortKey) {
    if (sortKey === next) setAscending((current) => !current);
    else { setSortKey(next); setAscending(true); }
  }

  const header = (key: SortKey, label: string) => (
    <button onClick={() => chooseSort(key)}>
      {label} {sortKey === key ? <span aria-hidden="true">{ascending ? "↑" : "↓"}</span> : null}
    </button>
  );
  const sortDirection = (key: SortKey) => sortKey === key ? (ascending ? "ascending" as const : "descending" as const) : "none" as const;

  return (
    <div className="data-table-wrap">
      <table className="data-table">
        <caption className="sr-only">Configured application permission inventory</caption>
        <thead><tr><th aria-sort={sortDirection("source")}>{header("source", "Caller")}</th><th aria-sort={sortDirection("type")}>{header("type", "Access type")}</th><th aria-sort={sortDirection("target")}>{header("target", "Resource")}</th><th aria-sort={sortDirection("permission")}>{header("permission", "Permissions")}</th><th>State</th><th>Evidence</th></tr></thead>
        <tbody>
          {sorted.map(({ edge, source, target }) => (
            <tr key={edge.id}>
              <td><strong>{source.label}</strong><small>Tenant identity</small></td>
              <td>{edge.type === "CAN_CALL_AS_APP" ? "Application" : "Delegated"}<small>{edge.type === "CAN_CALL_AS_APP" ? "Runs as itself" : "Signed-in person"}</small></td>
              <td><strong>{target.label}</strong><small>Resource identity</small></td>
              <td><div className="permission-pills">{edge.permissions.map((permission) => <span key={permission}>{permission}</span>)}</div></td>
              <td><span className="configured-tag"><i aria-hidden="true" /> Configured</span><small>Not observed</small></td>
              <td><Link className="text-link" href={`/map?edge=${edge.id}`}>Inspect</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
