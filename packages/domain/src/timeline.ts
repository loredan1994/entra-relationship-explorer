import { compareSnapshots } from "./comparisons";
import type { TenantSnapshot } from "./types";

export function snapshotTimeline(before: TenantSnapshot, after: TenantSnapshot) {
  const diff = compareSnapshots(before, after);
  const events = after.auditEvents?.filter(e => {
    return Date.parse(e.occurredAt) > Date.parse(before.scannedAt) && Date.parse(e.occurredAt) <= Date.parse(after.scannedAt);
  }) ?? [];
  return { ...diff, changes: diff.changes.map(change => {
    const edge = change.subject === "relationship" ? [...after.edges, ...before.edges].find(e => e.id === change.id) : undefined;
    const targetIds = new Set<unknown>(edge ? [edge.sourceId, edge.targetId] : [change.id]);
    for (const node of [...before.nodes, ...after.nodes]) {
      if (!targetIds.has(node.id) || node.kind !== "federatedCredential") continue;
      for (const key of ["parentId", "credentialId"]) {
        const id = node.metadata?.[key];
        // Exact-type membership keeps numeric/boolean metadata from matching string audit IDs.
        if (id) targetIds.add(id);
      }
    }
    const candidates = events.filter(e => e.result.toLowerCase() === "success" && e.targetIds.some(id => targetIds.has(id)));
    return { ...change, auditCandidates: candidates, attribution: candidates.length ? "Related events share an object and time window; they do not prove the cause of this change." : "Actor unknown: no matching directory audit evidence was collected." };
  }) };
}
