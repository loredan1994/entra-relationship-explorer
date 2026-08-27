import { vi } from "vitest";
import { ReadOnlyGraphClient, type ReadOnlyGraphClientOptions } from "./client";
import type {
  GraphApplication,
  GraphAppRoleAssignment,
  GraphConditionalAccessPolicy,
  GraphCrossTenantPartner,
  GraphDirectoryObject,
  GraphOAuth2PermissionGrant,
  GraphRoleDefinition,
  GraphRoleSchedule,
  GraphServicePrincipal,
  GraphSignIn,
  RawTenantScan,
  Sourced,
} from "./types";

/**
 * Test fixture builders. Excluded from mutation and coverage reports: this file
 * exists only to let tests assemble one precise scan shape at a time, so a
 * surviving mutant points at a real assertion gap rather than at fixture noise.
 */

export const TENANT = "11111111-1111-4111-8111-111111111111";
export const SCANNED_AT = "2026-08-26T12:00:00.000Z";

export function rawScan(partial: Partial<RawTenantScan> = {}): RawTenantScan {
  return {
    tenantId: TENANT,
    scannedAt: SCANNED_AT,
    applications: [],
    servicePrincipals: [],
    appRoleAssignments: [],
    oauth2PermissionGrants: [],
    applicationOwners: [],
    servicePrincipalOwners: [],
    users: [],
    groups: [],
    groupMemberships: [],
    roleDefinitions: [],
    roleAssignments: [],
    roleEligibilities: [],
    conditionalAccessPolicies: [],
    signIns: [],
    crossTenantPartners: [],
    collectedEndpoints: [],
    skippedEndpoints: [],
    errors: [],
    ...partial,
  };
}

export function sourced<T>(record: T, endpoint = "/test-endpoint"): Sourced<T> {
  return { endpoint, record };
}

export function application(
  partial: Partial<GraphApplication> & Pick<GraphApplication, "id" | "appId" | "displayName">,
): GraphApplication {
  return { appRoles: [], passwordCredentials: [], keyCredentials: [], ...partial };
}

export function servicePrincipal(
  partial: Partial<GraphServicePrincipal> & Pick<GraphServicePrincipal, "id" | "appId" | "displayName">,
): GraphServicePrincipal {
  return { appRoles: [], passwordCredentials: [], keyCredentials: [], ...partial };
}

export function assignment(
  partial: Partial<GraphAppRoleAssignment> & Pick<GraphAppRoleAssignment, "id" | "appRoleId" | "principalId" | "resourceId">,
): GraphAppRoleAssignment {
  return { principalType: "ServicePrincipal", ...partial };
}

export function grant(
  partial: Partial<GraphOAuth2PermissionGrant> & Pick<GraphOAuth2PermissionGrant, "id" | "clientId" | "resourceId" | "scope">,
): GraphOAuth2PermissionGrant {
  return { consentType: "AllPrincipals", ...partial };
}

export function directoryObject(
  partial: Partial<GraphDirectoryObject> & Pick<GraphDirectoryObject, "id">,
): GraphDirectoryObject {
  return { ...partial };
}

export function roleDefinition(
  partial: Partial<GraphRoleDefinition> & Pick<GraphRoleDefinition, "id" | "displayName">,
): GraphRoleDefinition {
  return { ...partial };
}

export function roleSchedule(
  partial: Partial<GraphRoleSchedule> & Pick<GraphRoleSchedule, "id" | "principalId" | "roleDefinitionId">,
): GraphRoleSchedule {
  return { ...partial };
}

export function conditionalAccessPolicy(
  partial: Partial<GraphConditionalAccessPolicy> & Pick<GraphConditionalAccessPolicy, "id" | "displayName" | "state">,
): GraphConditionalAccessPolicy {
  return { ...partial };
}

export function signIn(
  partial: Partial<GraphSignIn> & Pick<GraphSignIn, "id" | "createdDateTime">,
): GraphSignIn {
  return { ...partial };
}

export function crossTenantPartner(
  partial: Partial<GraphCrossTenantPartner> & Pick<GraphCrossTenantPartner, "tenantId">,
): GraphCrossTenantPartner {
  return { ...partial };
}

/** Records the Graph paths a scan requested, so tests can assert which stages ran. */
export interface RouteRecorder {
  fetchImpl: typeof fetch;
  requested: string[];
  requestedPath(fragment: string): boolean;
}

/**
 * A fetch stand-in that answers by URL fragment. Values are returned as a single
 * Graph collection page; `Error` values reject, so tests can drive the collector's
 * failure branch without reaching the network.
 */
export function routedFetch(routes: Record<string, unknown[] | Response | Error> = {}): RouteRecorder {
  const requested: string[] = [];
  const fetchImpl = vi.fn<typeof fetch>(async (input) => {
    const url = String(input instanceof Request ? input.url : input);
    requested.push(url);
    const match = Object.keys(routes).find((fragment) => url.includes(fragment));
    const route = match ? routes[match] : undefined;
    if (route instanceof Error) throw route;
    if (route instanceof Response) return route;
    return jsonResponse({ value: route ?? [] });
  });
  return {
    fetchImpl,
    requested,
    requestedPath: (fragment) => requested.some((url) => url.includes(fragment)),
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/**
 * Retries are kept but made free: `sleep` resolves immediately so a test that
 * drives the retry ladder finishes in microseconds instead of real backoff.
 */
export function clientFor(recorder: RouteRecorder, options: ReadOnlyGraphClientOptions = {}): ReadOnlyGraphClient {
  return new ReadOnlyGraphClient("test-token", {
    fetchImpl: recorder.fetchImpl,
    sleep: async () => {},
    random: () => 0.5,
    ...options,
  });
}

export const ALL_OPTIONAL_SCOPES = [
  "https://graph.microsoft.com/RoleManagement.Read.Directory",
  "https://graph.microsoft.com/Policy.Read.All",
  "https://graph.microsoft.com/AuditLog.Read.All",
] as const;
