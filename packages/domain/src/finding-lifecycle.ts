import { analyzeTenantIntelligenceHistory, type FindingSeverity, type IamFinding } from "./intelligence";
import { assertTenantBoundary } from "./queries";
import type { TenantSnapshot } from "./types";

export type FindingLifecycleStatus = "new" | "ongoing" | "returned" | "no-longer-detected" | "unconfirmed";

export interface FindingLifecycleRecord {
  finding: IamFinding;
  status: FindingLifecycleStatus;
  currentSnapshotId: string;
  previousSnapshotId: string | null;
  lastDetectedSnapshotId: string;
  firstDetectedAt: string;
  lastDetectedAt: string;
}

export interface FindingLifecycle {
  currentSnapshotId: string;
  previousSnapshotId: string | null;
  records: FindingLifecycleRecord[];
  counts: Record<FindingLifecycleStatus, number>;
}

const severityOrder: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const statusOrder: Record<FindingLifecycleStatus, number> = { returned: 0, new: 1, ongoing: 2, unconfirmed: 3, "no-longer-detected": 4 };

/**
 * Compare retained snapshots ordered newest first. The module reports scan evidence only:
 * a finding disappearing never changes an analyst's review disposition.
 */
export function analyzeFindingLifecycle(history: TenantSnapshot[]): FindingLifecycle {
  if (history.length === 0) throw new Error("At least one snapshot is required for finding lifecycle analysis.");
  validateHistory(history);

  const [current, previous] = history;
  const analyses = history.map((_, index) => analyzeTenantIntelligenceHistory(history.slice(index)));
  const findingsBySnapshot = analyses.map(({ findings }) => new Map(findings.map((finding) => [finding.id, finding])));
  const currentFindings = findingsBySnapshot[0]!;
  const previousFindings = findingsBySnapshot[1] ?? new Map<string, IamFinding>();
  const records: FindingLifecycleRecord[] = [];

  for (const finding of currentFindings.values()) {
    const previousMatch = previousFindings.get(finding.id);
    const olderMatches = history.flatMap((snapshot, index) => findingsBySnapshot[index]!.has(finding.id) ? [{ snapshot, index }] : []);
    const oldestMatch = olderMatches.at(-1)!.snapshot;
    records.push({
      finding,
      status: previousMatch ? "ongoing" : olderMatches.some(({ index }) => index > 1) ? "returned" : "new",
      currentSnapshotId: current!.id,
      previousSnapshotId: previous?.id ?? null,
      lastDetectedSnapshotId: current!.id,
      firstDetectedAt: oldestMatch.scannedAt,
      lastDetectedAt: current!.scannedAt,
    });
  }

  if (previous) {
    for (const finding of previousFindings.values()) {
      if (currentFindings.has(finding.id)) continue;
      const olderMatches = history.slice(1).filter((_, index) => findingsBySnapshot[index + 1]!.has(finding.id));
      // The previous snapshot itself always matches because this loop iterates its findings.
      const oldestMatch = olderMatches.at(-1)!;
      records.push({
        finding,
        status: absenceIsTrustworthy(current!, previous, finding) ? "no-longer-detected" : "unconfirmed",
        currentSnapshotId: current!.id,
        previousSnapshotId: previous.id,
        lastDetectedSnapshotId: previous.id,
        firstDetectedAt: oldestMatch.scannedAt,
        lastDetectedAt: previous.scannedAt,
      });
    }
  }

  records.sort((left, right) => severityOrder[left.finding.severity] - severityOrder[right.finding.severity]
    || statusOrder[left.status] - statusOrder[right.status]
    || left.finding.title.localeCompare(right.finding.title)
    || left.finding.id.localeCompare(right.finding.id));
  const counts: Record<FindingLifecycleStatus, number> = { new: 0, ongoing: 0, returned: 0, "no-longer-detected": 0, unconfirmed: 0 };
  for (const record of records) counts[record.status] += 1;
  return { currentSnapshotId: current!.id, previousSnapshotId: previous?.id ?? null, records, counts };
}

function validateHistory(history: TenantSnapshot[]): void {
  const tenantId = history[0]!.tenant.tenantId;
  let newestAllowed = Number.POSITIVE_INFINITY;
  for (const snapshot of history) {
    assertTenantBoundary(snapshot);
    if (snapshot.tenant.tenantId !== tenantId) throw new Error("Finding lifecycle snapshots must belong to the same tenant.");
    const scannedAt = new Date(snapshot.scannedAt).getTime();
    if (!Number.isFinite(scannedAt) || scannedAt > newestAllowed) throw new Error("Finding lifecycle snapshots must be ordered newest to oldest.");
    newestAllowed = scannedAt;
  }
}

function absenceIsTrustworthy(current: TenantSnapshot, previous: TenantSnapshot, finding: IamFinding): boolean {
  if (current.completion.status !== "complete") return false;
  const previousCoverage = new Set(previous.completion.collectedEndpoints.map(endpointPattern));
  const currentCoverage = new Set(current.completion.collectedEndpoints.map(endpointPattern));
  const required = new Set(finding.sourceEndpoints.map(endpointPattern).filter((endpoint) => previousCoverage.has(endpoint)));
  return [...required].every((endpoint) => currentCoverage.has(endpoint));
}

function endpointPattern(endpoint: string): string {
  return endpoint.split("?", 1)[0]!.replace(/\/(applications|servicePrincipals|groups)\/[^/?]+(?=\/|$)/gi, "/$1/{id}");
}
