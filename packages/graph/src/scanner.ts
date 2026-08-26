import { GraphRequestError, ReadOnlyGraphClient } from "./client";
import type {
  GraphAppRoleAssignment,
  GraphApplication,
  GraphCredentialMetadata,
  GraphDirectoryObject,
  GraphOAuth2PermissionGrant,
  GraphServicePrincipal,
  RawTenantScan,
  ScanProgressEvent,
  Sourced,
} from "./types";

const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface ScanTenantOptions {
  now?: () => Date;
  concurrency?: number;
  onProgress?: (event: ScanProgressEvent) => void;
}

export async function scanTenant(
  client: ReadOnlyGraphClient,
  tenantId: string,
  options: ScanTenantOptions = {},
): Promise<RawTenantScan> {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error("A concrete Microsoft Entra tenant ID is required.");
  const scan: RawTenantScan = {
    tenantId,
    scannedAt: (options.now ?? (() => new Date()))().toISOString(),
    applications: [],
    servicePrincipals: [],
    appRoleAssignments: [],
    oauth2PermissionGrants: [],
    applicationOwners: [],
    servicePrincipalOwners: [],
    collectedEndpoints: [],
    skippedEndpoints: [],
    errors: [],
  };
  const concurrency = options.concurrency ?? 4;

  const applicationsEndpoint = "/applications?$select=id,appId,displayName,publisherDomain,appRoles,passwordCredentials,keyCredentials";
  const applications = await collect(client, applicationsEndpoint, sanitizeApplication, scan, (count) =>
    options.onProgress?.({ stage: "applications", collected: count, detail: "Application blueprints collected" }),
  );
  scan.applications.push(...applications);

  const servicePrincipalsEndpoint = "/servicePrincipals?$select=id,appId,displayName,publisherName,servicePrincipalType,appRoles,passwordCredentials,keyCredentials";
  const servicePrincipals = await collect(client, servicePrincipalsEndpoint, sanitizeServicePrincipal, scan, (count) =>
    options.onProgress?.({ stage: "servicePrincipals", collected: count, detail: "Tenant identities collected" }),
  );
  scan.servicePrincipals.push(...servicePrincipals);

  const grantsEndpoint = "/oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope";
  const grants = await collect(client, grantsEndpoint, sanitizeGrant, scan, (count) =>
    options.onProgress?.({ stage: "delegatedPermissionGrants", collected: count, detail: "Delegated permission grants collected" }),
  );
  scan.oauth2PermissionGrants.push(...grants);

  await mapLimit(servicePrincipals, concurrency, async ({ record }) => {
    const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/appRoleAssignedTo?$select=id,appRoleId,principalDisplayName,principalId,principalType,resourceDisplayName,resourceId`;
    const assignments = await collect(client, endpoint, sanitizeAssignment, scan);
    scan.appRoleAssignments.push(...assignments);
    options.onProgress?.({
      stage: "appRoleAssignments",
      collected: scan.appRoleAssignments.length,
      detail: "Application and user assignments collected",
    });
  });

  await mapLimit(applications, concurrency, async ({ record }) => {
    const endpoint = `/applications/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
    const owners = await collect(client, endpoint, sanitizeDirectoryObject, scan);
    scan.applicationOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
  });

  await mapLimit(servicePrincipals, concurrency, async ({ record }) => {
    const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
    const owners = await collect(client, endpoint, sanitizeDirectoryObject, scan);
    scan.servicePrincipalOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
  });
  options.onProgress?.({
    stage: "owners",
    collected: scan.applicationOwners.length + scan.servicePrincipalOwners.length,
    detail: "Ownership relationships collected",
  });

  return scan;
}

async function collect<TInput, TOutput>(
  client: ReadOnlyGraphClient,
  endpoint: string,
  sanitize: (record: TInput) => TOutput,
  scan: RawTenantScan,
  onPage?: (count: number) => void,
): Promise<Sourced<TOutput>[]> {
  try {
    const records = await client.getAll<TInput>(endpoint, onPage);
    scan.collectedEndpoints.push(endpoint);
    return records.map((record) => ({ endpoint, record: sanitize(record) }));
  } catch (error) {
    const graphError = error instanceof GraphRequestError ? error : null;
    scan.skippedEndpoints.push(endpoint);
    scan.errors.push({
      endpoint,
      code: graphError?.code ?? "unexpected_error",
      message: graphError?.message ?? "The read failed without exposing response data.",
    });
    return [];
  }
}

async function mapLimit<T>(items: T[], limit: number, task: (item: T) => Promise<void>): Promise<void> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new RangeError("Scanner concurrency must be between 1 and 20.");
  let nextIndex = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (nextIndex < items.length) {
        const item = items[nextIndex++];
        if (item !== undefined) await task(item);
      }
    }),
  );
}

function credentialMetadata(value: unknown): GraphCredentialMetadata[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((candidate) => {
    if (!candidate || typeof candidate !== "object") return [];
    const item = candidate as Record<string, unknown>;
    if (typeof item.keyId !== "string") return [];
    return [{
      keyId: item.keyId,
      displayName: stringOrNull(item.displayName),
      startDateTime: stringOrNull(item.startDateTime),
      endDateTime: stringOrNull(item.endDateTime),
      type: stringOrNull(item.type),
      usage: stringOrNull(item.usage),
    }];
  });
}

function sanitizeApplication(value: GraphApplication): GraphApplication {
  return {
    id: requiredString(value.id), appId: requiredString(value.appId), displayName: requiredString(value.displayName),
    publisherDomain: stringOrNull(value.publisherDomain), appRoles: sanitizeRoles(value.appRoles),
    passwordCredentials: credentialMetadata(value.passwordCredentials), keyCredentials: credentialMetadata(value.keyCredentials),
  };
}

function sanitizeServicePrincipal(value: GraphServicePrincipal): GraphServicePrincipal {
  return {
    id: requiredString(value.id), appId: requiredString(value.appId), displayName: requiredString(value.displayName),
    publisherName: stringOrNull(value.publisherName), servicePrincipalType: stringOrNull(value.servicePrincipalType),
    appRoles: sanitizeRoles(value.appRoles), passwordCredentials: credentialMetadata(value.passwordCredentials),
    keyCredentials: credentialMetadata(value.keyCredentials),
  };
}

function sanitizeRoles(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((candidate) => {
    if (!candidate || typeof candidate !== "object") return [];
    const role = candidate as Record<string, unknown>;
    if (typeof role.id !== "string") return [];
    return [{ id: role.id, value: stringOrNull(role.value), displayName: stringOrNull(role.displayName), isEnabled: role.isEnabled === true,
      allowedMemberTypes: Array.isArray(role.allowedMemberTypes) ? role.allowedMemberTypes.filter((item): item is string => typeof item === "string") : [] }];
  });
}

function sanitizeAssignment(value: GraphAppRoleAssignment): GraphAppRoleAssignment {
  return {
    id: requiredString(value.id), appRoleId: requiredString(value.appRoleId), principalId: requiredString(value.principalId),
    principalType: requiredString(value.principalType), resourceId: requiredString(value.resourceId),
    principalDisplayName: stringOrNull(value.principalDisplayName), resourceDisplayName: stringOrNull(value.resourceDisplayName),
  };
}

function sanitizeGrant(value: GraphOAuth2PermissionGrant): GraphOAuth2PermissionGrant {
  return {
    id: requiredString(value.id), clientId: requiredString(value.clientId), consentType: requiredString(value.consentType),
    principalId: stringOrNull(value.principalId), resourceId: requiredString(value.resourceId), scope: requiredString(value.scope),
  };
}

function sanitizeDirectoryObject(value: GraphDirectoryObject): GraphDirectoryObject {
  return { id: requiredString(value.id), displayName: stringOrNull(value.displayName), "@odata.type": stringOrNull(value["@odata.type"]) ?? undefined };
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError("Microsoft Graph returned a record without a required identifier.");
  return value;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
