import { expect, it } from "vitest";
import { recordStageCoverage } from "./coverage";
import { rawScan, sourced, SCANNED_AT } from "./test-support";
import type { RawTenantScan, ScanStage } from "./types";
const success = "All attempted reads completed, including successful empty collections.";
const failed = "One or more reads failed; missing records cannot establish absence.";
const parent = "A parent inventory was incomplete. Unattempted child reads and missing records cannot establish absence.";
const cases: [ScanStage, string, string, (keyof RawTenantScan)[]][] = [
  ["applications", "/applications?$select=id", "Application.Read.All", ["applications"]],
  ["servicePrincipals", "/servicePrincipals?$select=id", "Application.Read.All", ["servicePrincipals"]],
  ["federatedIdentityCredentials", "/applications/app/federatedIdentityCredentials", "Application.Read.All", ["federatedIdentityCredentials"]],
  ["usersAndGroups", "/users?$select=id", "Directory.Read.All", ["users", "groups"]],
  ["groupMemberships", "/groups/g/members?$select=id", "Directory.Read.All", ["groupMemberships"]],
  ["devices", "/devices?$select=id", "Directory.Read.All", ["devices"]],
  ["administrativeUnits", "/directory/administrativeUnits", "Directory.Read.All", ["administrativeUnits"]],
  ["delegatedPermissionGrants", "/oauth2PermissionGrants", "Directory.Read.All", ["oauth2PermissionGrants"]],
  ["appRoleAssignments", "/servicePrincipals/sp/appRoleAssignedTo", "Application.Read.All", ["appRoleAssignments"]],
  ["owners", "/applications/app/owners", "Application.Read.All", ["applicationOwners", "servicePrincipalOwners"]],
  ["roles", "/roleManagement/directory/roleAssignments", "RoleManagement.Read.Directory", ["roleAssignments", "roleEligibilities"]],
  ["conditionalAccess", "/identity/conditionalAccess/policies", "Policy.Read.All", ["conditionalAccessPolicies"]],
  ["authorizationPolicy", "/policies/authorizationPolicy", "Policy.Read.All", ["authorizationPolicies"]],
  ["permissionGrantPolicies", "/policies/permissionGrantPolicies", "Policy.Read.PermissionGrant", ["permissionGrantPolicies"]],
  ["crossTenantAccess", "/policies/crossTenantAccessPolicy/partners", "Policy.Read.All", ["crossTenantPartners"]],
  ["activity", "/auditLogs/signIns", "AuditLog.Read.All", ["signIns"]],
  ["directoryAudits", "/auditLogs/directoryAudits", "Directory.Read.All", ["auditEvents"]],
];
function scanWithParents() {
  const scan = rawScan();
  for (const stage of ["applications", "servicePrincipals", "usersAndGroups"] as const) recordStageCoverage(scan, stage);
  return scan;
}
const last = (scan: RawTenantScan) => scan.coverage!.at(-1)!;
it.each(cases)("records %s counts, endpoint provenance, scope, timestamps and successful emptiness", (stage, endpoint, scope, fields) => {
  const scan = scanWithParents();
  scan.collectedEndpoints = ["/unrelated", endpoint];
  scan.skippedEndpoints = ["/irrelevant"];
  // Coverage reads collection lengths only; values are irrelevant to this contract.
  for (const [i, field] of fields.entries()) Object.assign(scan, { [field]: Array.from({ length: i + 2 }, () => sourced({ id: "synthetic" })) });
  recordStageCoverage(scan, stage, [scope], true);
  const result = last(scan);
  const special = stage === "activity" ? "User sign-ins only. Workload and non-interactive activity are unavailable under this v1.0 contract; tenant retention may shorten the requested window."
    : stage === "conditionalAccess" ? "Policy inclusion references collected; applicability, exclusions and effective enforcement are not evaluated." : success;
  expect(result).toMatchObject({ id: stage, state: stage === "activity" ? "partial" : "complete", reason: special, scope, collectedAt: SCANNED_AT, endpoints: [endpoint], failedEndpoints: [], itemCount: fields.length === 2 ? 5 : 2 });
  expect(scan.coverage!.filter(c => c.id === stage)).toHaveLength(1);
  if (stage === "activity" || stage === "directoryAudits") expect(result.window).toEqual({ startsAt: "2026-07-27T12:00:00.000Z", endsAt: SCANNED_AT, eventClasses: [stage === "activity" ? "interactiveUser" : "directoryAudit"] });
  else expect(result.window).toBeUndefined();
  const empty = scanWithParents();
  for (const field of fields) if (!["applications", "servicePrincipals", "oauth2PermissionGrants", "appRoleAssignments", "applicationOwners", "servicePrincipalOwners"].includes(field)) Object.assign(empty, { [field]: undefined });
  recordStageCoverage(empty, stage, [scope], true);
  expect(last(empty).itemCount).toBe(0);
});
it.each(cases)("distinguishes unavailable, partial and denied %s reads", (stage, endpoint, scope) => {
  const scan = scanWithParents(); scan.skippedEndpoints = [endpoint];
  scan.errors = [{ endpoint, code: "503", message: "Unavailable" }];
  recordStageCoverage(scan, stage, [scope], true);
  expect(last(scan)).toMatchObject({ state: "unavailable", reason: failed, endpoints: [], failedEndpoints: [endpoint] });
  scan.collectedEndpoints = [endpoint];
  recordStageCoverage(scan, stage, [scope], true);
  expect(last(scan)).toMatchObject({ state: "partial", reason: failed });
  scan.collectedEndpoints = [];
  scan.errors = [{ endpoint, code: "Authorization_RequestDenied", message: "Forbidden" }, { endpoint: "/unrelated", code: "500", message: "Unrelated" }];
  recordStageCoverage(scan, stage, [scope], true);
  expect(last(scan)).toMatchObject({ state: "denied", reason: failed });
});
it.each(cases.filter(([stage]) => ["roles", "conditionalAccess", "authorizationPolicy", "permissionGrantPolicies", "crossTenantAccess", "activity", "directoryAudits"].includes(stage)))("requires explicit opt-in for %s", (stage, endpoint, scope) => {
  const scan = scanWithParents();
  for (const scopes of [[], ["unrelated"], [`wrong${scope}`]]) {
    recordStageCoverage(scan, stage, scopes);
    expect(last(scan)).toEqual({ id: stage, state: "not-enabled", reason: "Collection was not enabled for this scan.", scope, collectedAt: null, endpoints: [], failedEndpoints: [], itemCount: 0 });
  }
  recordStageCoverage(scan, stage, [`https://graph.microsoft.com/${scope}`], true);
  expect(last(scan).state).not.toBe("not-enabled");
  expect(last(scan).collectedAt).toBe(SCANNED_AT);
  expect(endpoint).not.toBe("");
});
it.each(["owners", "appRoleAssignments", "groupMemberships", "federatedIdentityCredentials"] as const)("requires complete parent inventory before certifying %s", (stage) => {
  const scan = rawScan(); recordStageCoverage(scan, stage);
  expect(last(scan)).toMatchObject({ state: "partial", reason: parent });
  const complete = scanWithParents();
  recordStageCoverage(complete, stage);
  expect(last(complete).state).toBe("complete");
  const deps = stage === "groupMemberships" ? ["usersAndGroups"] : stage === "appRoleAssignments" ? ["servicePrincipals"] : ["applications", "servicePrincipals"];
  for (const dependency of deps) {
    const partial = scanWithParents(); partial.coverage!.find(c => c.id === dependency)!.state = "denied";
    recordStageCoverage(partial, stage);
    expect(last(partial)).toMatchObject({ state: "partial", reason: parent });
  }
});
it("does not mistake nested memberships, expanded identities or child application reads for base inventories", () => {
  const scan = scanWithParents();
  scan.collectedEndpoints = ["/applications/a/owners", "/servicePrincipals?$expand=owners", "/directory/administrativeUnits/u/members?$select=id", "/groups/g/owners", "/groups/g/membershipRules", "/groups/g/h/members"];
  for (const stage of ["applications", "servicePrincipals", "groupMemberships"] as const) {
    recordStageCoverage(scan, stage);
    expect(last(scan).endpoints).toEqual([]);
  }
});
it("marks workload membership incomplete only for a nonempty group inventory", () => {
  const scan = scanWithParents(); scan.groups = [sourced({ id: "g" })];
  recordStageCoverage(scan, "groupMemberships");
  expect(last(scan)).toMatchObject({ state: "partial", reason: "Graph v1.0 group members can omit service principals. Workload membership coverage is incomplete; hidden membership may also be unavailable." });
  scan.skippedEndpoints = ["/groups/g/members"];
  scan.errors = [{ endpoint: "/groups/g/members", code: "403", message: "Denied" }];
  recordStageCoverage(scan, "groupMemberships"); expect(last(scan).state).toBe("denied");
});
it.each(["403", "Authorization_RequestDenied", "Forbidden", "accessDenied"])("recognizes permission failure %s without losing non-permission failures", code => {
  const scan = rawScan({ skippedEndpoints: ["/devices"], errors: [{ endpoint: "/devices", code: code.toUpperCase(), message: "Failure" }] });
  recordStageCoverage(scan, "devices"); expect(last(scan).state).toBe("denied");
  scan.errors.push({ endpoint: "/devices", code: "503", message: "Unavailable" });
  recordStageCoverage(scan, "devices"); expect(last(scan).state).toBe("unavailable");
  scan.errors = [];
  recordStageCoverage(scan, "devices"); expect(last(scan).state).toBe("unavailable");
});
it("ignores stages outside the collector catalog", () => {
  const scan = rawScan(); recordStageCoverage(scan, "complete" as ScanStage);
  expect(scan.coverage).toBeUndefined();
});

it("does not classify an unrelated error record as a failed collection", () => {
  const scan = rawScan({ errors: [{ endpoint: "/devices", code: "403", message: "Forbidden" }] });
  recordStageCoverage(scan, "devices");
  expect(last(scan)).toMatchObject({ state: "complete", failedEndpoints: [] });
});

it("retains unrelated coverage records and isolates denied evidence from disabled or successful collection", () => {
  const scan = rawScan({ coverage: [{ id: "unrelated", state: "unknown", reason: "Historical", collectedAt: null, endpoints: [], failedEndpoints: [], itemCount: 0, scope: "None" }] });
  recordStageCoverage(scan, "devices");
  expect(scan.coverage!.map(c => c.id)).toEqual(["unrelated", "devices"]);
  const absent = rawScan(); recordStageCoverage(absent, "devices"); expect(absent.coverage).toHaveLength(1);
  const denied = rawScan({ skippedEndpoints: ["/auditLogs/signIns"], errors: [{ endpoint: "/auditLogs/signIns", code: "403", message: "Forbidden" }] });
  recordStageCoverage(denied, "activity"); expect(last(denied).state).toBe("not-enabled");
  denied.collectedEndpoints = ["/auditLogs/signIns"];
  recordStageCoverage(denied, "activity", ["AuditLog.Read.All"]); expect(last(denied).state).toBe("partial");
  denied.skippedEndpoints = [];
  recordStageCoverage(denied, "activity", ["AuditLog.Read.All"]); expect(last(denied).state).toBe("partial");
  const missingGroups = scanWithParents(); delete missingGroups.groups;
  recordStageCoverage(missingGroups, "groupMemberships"); expect(last(missingGroups).state).toBe("complete");
});
it("matches complete root collection paths, including multi-character group IDs", () => {
  const scan = scanWithParents();
  scan.collectedEndpoints = ["/groups/long-id/members?x=y", "/nested/groups/other/members", "/nested/applications?x=y", "/wrong"];
  recordStageCoverage(scan, "groupMemberships"); expect(last(scan).endpoints).toEqual(["/groups/long-id/members?x=y"]);
  recordStageCoverage(scan, "applications"); expect(last(scan).endpoints).toEqual([]);
});
