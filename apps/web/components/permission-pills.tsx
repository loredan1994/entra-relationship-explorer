"use client";

import { useState } from "react";
import { isUnresolvedPermission, isWritePermission, rankPermissions } from "./permission-utils";

/**
 * Permission list that stays calm at tenant scale: the most consequential values
 * first, write-capable ones flagged, and everything past `limit` behind a toggle.
 */
export function PermissionPills({ permissions, limit = 4 }: { permissions: string[]; limit?: number }) {
  const [expanded, setExpanded] = useState(false);
  const ranked = rankPermissions(permissions);
  const visible = expanded ? ranked : ranked.slice(0, limit);
  const hidden = ranked.length - visible.length;
  if (ranked.length === 0) return null;
  return (
    <div className="permission-pills">
      {visible.map((permission) => (
        <span
          key={permission}
          className={isWritePermission(permission) ? "is-write" : undefined}
          title={isWritePermission(permission) ? `${permission} — write-capable` : isUnresolvedPermission(permission) ? `${permission} — unresolved app role ID` : permission}
        >
          {permission}
        </span>
      ))}
      {hidden > 0 ? <button type="button" className="pill-more" onClick={() => setExpanded(true)}>+{hidden} more</button> : null}
      {expanded && ranked.length > limit ? <button type="button" className="pill-more" onClick={() => setExpanded(false)}>Show fewer</button> : null}
    </div>
  );
}
