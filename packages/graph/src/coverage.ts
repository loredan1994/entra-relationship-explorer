import { COLLECTORS, type CollectorCoverage } from "@entra-explorer/domain";
import type { RawTenantScan, ScanStage } from "./types";

const optional = new Set(["roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity"]);
// Stryker disable next-line ArrayDeclaration: an unrecognized scope string cannot enable any optional collector.
export function recordStageCoverage(scan: RawTenantScan, stage: ScanStage, scopes: readonly string[] = [], collectAudits = false): void {
  const definition = COLLECTORS.find(c => c.id === stage);
  if (!definition) return;
  const enabled = collectionEnabled(stage, definition.scope, scopes, collectAudits);
  const matches = (endpoint: string) => {
    if (stage === "groupMemberships") return /^\/groups\/[^/]+\/members(?:\?|$)/.test(endpoint);
    if (stage === "applications") return endpoint.startsWith("/applications?");
    if (stage === "servicePrincipals") return endpoint.startsWith("/servicePrincipals?") && !endpoint.includes("$expand=");
    return definition.prefixes.some(prefix => endpoint.includes(prefix));
  };
  const endpoints = scan.collectedEndpoints.filter(matches);
  const failedEndpoints = scan.skippedEndpoints.filter(matches);
  let state: CollectorCoverage["state"] = !enabled ? "not-enabled" : failedEndpoints.length ? (endpoints.length ? "partial" : "unavailable") : "complete";
  let reason = !enabled ? "Collection was not enabled for this scan." : failedEndpoints.length ? "One or more reads failed; missing records cannot establish absence." : "All attempted reads completed, including successful empty collections.";
  const dependencies: Partial<Record<ScanStage, string[]>> = { owners: ["applications", "servicePrincipals"], appRoleAssignments: ["servicePrincipals"], groupMemberships: ["usersAndGroups"], federatedIdentityCredentials: ["applications", "servicePrincipals"] };
  if (enabled && dependencies[stage]?.some(id => scan.coverage?.find(c => c.id === id)?.state !== "complete")) {
    state = "partial";
    reason = "A parent inventory was incomplete. Unattempted child reads and missing records cannot establish absence.";
  }
  const failures = scan.errors.filter(e => matches(e.endpoint));
  if (isDeniedRead(enabled, failedEndpoints.length, endpoints.length, failures)) state = "denied";
  if (enabled && stage === "groupMemberships" && (scan.groups?.length ?? 0) > 0) {
    if (state === "complete") state = "partial";
    reason = "Graph v1.0 group members can omit service principals. Workload membership coverage is incomplete; hidden membership may also be unavailable.";
  }
  if (enabled && stage === "activity" && state === "complete") {
    state = "partial";
    reason = "User sign-ins only. Workload and non-interactive activity are unavailable under this v1.0 contract; tenant retention may shorten the requested window.";
  }
  if (stage === "conditionalAccess" && state === "complete") reason = "Policy inclusion references collected; applicability, exclusions and effective enforcement are not evaluated.";
  const coverage: CollectorCoverage = { id: stage, state, reason, scope: definition.scope, collectedAt: enabled ? scan.scannedAt : null, endpoints, failedEndpoints, itemCount: itemCount(scan, stage) };
  if (enabled && (stage === "activity" || stage === "directoryAudits")) coverage.window = { startsAt: new Date(Date.parse(scan.scannedAt) - 30 * 86_400_000).toISOString(), endsAt: scan.scannedAt, eventClasses: stage === "activity" ? ["interactiveUser"] : ["directoryAudit"] };
  scan.coverage = [...(scan.coverage ?? []).filter(c => c.id !== stage), coverage];
}

function itemCount(scan: RawTenantScan, stage: ScanStage): number {
  const counts: Partial<Record<ScanStage, number>> = {
    applications: scan.applications.length, servicePrincipals: scan.servicePrincipals.length,
    federatedIdentityCredentials: scan.federatedIdentityCredentials?.length, usersAndGroups: (scan.users?.length ?? 0) + (scan.groups?.length ?? 0),
    groupMemberships: scan.groupMemberships?.length, devices: scan.devices?.length, administrativeUnits: scan.administrativeUnits?.length,
    delegatedPermissionGrants: scan.oauth2PermissionGrants.length, appRoleAssignments: scan.appRoleAssignments.length,
    owners: scan.applicationOwners.length + scan.servicePrincipalOwners.length, roles: (scan.roleAssignments?.length ?? 0) + (scan.roleEligibilities?.length ?? 0),
    conditionalAccess: scan.conditionalAccessPolicies?.length, authorizationPolicy: scan.authorizationPolicies?.length,
    permissionGrantPolicies: scan.permissionGrantPolicies?.length, crossTenantAccess: scan.crossTenantPartners?.length,
    activity: scan.signIns?.length, directoryAudits: scan.auditEvents?.length,
  };
  return counts[stage] ?? 0;
}

function isDeniedRead(enabled: boolean, failedCount: number, collectedCount: number, failures: RawTenantScan["errors"]): boolean {
  return enabled && failedCount > 0 && collectedCount === 0 && failures.length > 0 && failures.every(e => /403|Authorization_RequestDenied|Forbidden|accessDenied/i.test(`${e.code} ${e.message}`));
}

function collectionEnabled(stage: ScanStage, scope: string, scopes: readonly string[], collectAudits: boolean): boolean {
  return stage === "directoryAudits" ? collectAudits : !optional.has(stage) || scopes.some(s => s === scope || s.endsWith(`/${scope}`));
}
