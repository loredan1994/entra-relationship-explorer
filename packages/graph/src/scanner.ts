import { GraphRequestError, ReadOnlyGraphClient } from "./client";
import type {
  GraphAppRoleAssignment,
  GraphApplication,
  GraphCredentialMetadata,
  GraphDirectoryObject,
  GraphGroup,
  GraphConditionalAccessPolicy,
  GraphOAuth2PermissionGrant,
  GraphServicePrincipal,
  GraphRoleDefinition,
  GraphRoleSchedule,
  GraphSignIn,
  GraphCrossTenantPartner,
  GraphUser,
  RawTenantScan,
  ScanProgressEvent,
  Sourced,
} from "./types";

const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface ScanTenantOptions {
  now?: () => Date;
  concurrency?: number;
  onProgress?: (event: ScanProgressEvent) => void;
  shouldCancel?: () => Promise<boolean>;
  enabledScopes?: readonly string[];
  resumeFrom?: RawTenantScan;
  onCheckpoint?: (scan: RawTenantScan) => Promise<void>;
}

export class ScanCancelledError extends Error { constructor() { super("The scan was cancelled safely."); this.name = "ScanCancelledError"; } }

export async function scanTenant(
  client: ReadOnlyGraphClient,
  tenantId: string,
  options: ScanTenantOptions = {},
): Promise<RawTenantScan> {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error("A concrete Microsoft Entra tenant ID is required.");
  if (options.resumeFrom && options.resumeFrom.tenantId !== tenantId) throw new Error("A scan checkpoint cannot cross tenant boundaries.");
  const scan: RawTenantScan = options.resumeFrom ? structuredClone(options.resumeFrom) : {
    tenantId,
    scannedAt: (options.now ?? (() => new Date()))().toISOString(),
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
    completedStages: [],
  };
  scan.completedStages ??= [];
  const concurrency = options.concurrency ?? 4;
  const ensureActive = async () => { if (await options.shouldCancel?.()) throw new ScanCancelledError(); };

  const stageComplete = (stage: ScanProgressEvent["stage"]) => scan.completedStages?.includes(stage) === true;
  const checkpoint = async (stage: ScanProgressEvent["stage"]) => {
    if (!scan.completedStages?.includes(stage)) scan.completedStages?.push(stage);
    await options.onCheckpoint?.(scan);
  };

  await ensureActive();
  const applicationsEndpoint = "/applications?$select=id,appId,displayName,publisherDomain,appRoles,passwordCredentials,keyCredentials";
  if (!stageComplete("applications")) {
    scan.applications.push(...await collect(client, applicationsEndpoint, sanitizeApplication, scan, (count) =>
      options.onProgress?.({ stage: "applications", collected: count, detail: "Application blueprints collected" }),
    ));
    await checkpoint("applications");
  }
  const applications = scan.applications;

  await ensureActive();
  const servicePrincipalsEndpoint = "/servicePrincipals?$select=id,appId,displayName,publisherName,servicePrincipalType,appRoles,passwordCredentials,keyCredentials";
  if (!stageComplete("servicePrincipals")) {
    scan.servicePrincipals.push(...await collect(client, servicePrincipalsEndpoint, sanitizeServicePrincipal, scan, (count) =>
      options.onProgress?.({ stage: "servicePrincipals", collected: count, detail: "Tenant identities collected" }),
    ));
    await checkpoint("servicePrincipals");
  }
  const servicePrincipals = scan.servicePrincipals;

  await ensureActive();
  const usersEndpoint = "/users?$select=id,displayName,userType,externalUserState";
  if (!stageComplete("usersAndGroups")) {
  const users = await collect(client, usersEndpoint, sanitizeUser, scan);
  scan.users!.push(...users);
  const groupsEndpoint = "/groups?$select=id,displayName,securityEnabled";
  const groups = await collect(client, groupsEndpoint, sanitizeGroup, scan);
  scan.groups!.push(...groups);
  options.onProgress?.({ stage: "usersAndGroups", collected: users.length + groups.length, detail: "People and groups collected" });
  await checkpoint("usersAndGroups");
  }
  const groups = scan.groups!;

  if (!stageComplete("groupMemberships")) await mapLimit(groups, concurrency, async ({ record }) => {
    await ensureActive();
    const endpoint = `/groups/${encodeURIComponent(record.id)}/members?$select=id,displayName,userType`;
    const members = await collect(client, endpoint, sanitizeDirectoryObject, scan);
    scan.groupMemberships!.push(...members.map((member) => ({ ...member, groupId: record.id })));
    options.onProgress?.({ stage: "groupMemberships", collected: scan.groupMemberships!.length, detail: "Direct group memberships collected" });
  });
  if (!stageComplete("groupMemberships")) await checkpoint("groupMemberships");

  await ensureActive();
  const grantsEndpoint = "/oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope";
  if (!stageComplete("delegatedPermissionGrants")) scan.oauth2PermissionGrants.push(...await collect(client, grantsEndpoint, sanitizeGrant, scan, (count) =>
    options.onProgress?.({ stage: "delegatedPermissionGrants", collected: count, detail: "Delegated permission grants collected" }),
  ));
  if (!stageComplete("delegatedPermissionGrants")) await checkpoint("delegatedPermissionGrants");

  if (!stageComplete("appRoleAssignments")) await mapLimit(servicePrincipals, concurrency, async ({ record }) => {
    await ensureActive();
    const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/appRoleAssignedTo?$select=id,appRoleId,principalDisplayName,principalId,principalType,resourceDisplayName,resourceId`;
    const assignments = await collect(client, endpoint, sanitizeAssignment, scan);
    scan.appRoleAssignments.push(...assignments);
    options.onProgress?.({
      stage: "appRoleAssignments",
      collected: scan.appRoleAssignments.length,
      detail: "Application and user assignments collected",
    });
  });
  if (!stageComplete("appRoleAssignments")) await checkpoint("appRoleAssignments");

  if (!stageComplete("owners")) await mapLimit(applications, concurrency, async ({ record }) => {
    await ensureActive();
    const endpoint = `/applications/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
    const owners = await collect(client, endpoint, sanitizeDirectoryObject, scan);
    scan.applicationOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
  });

  if (!stageComplete("owners")) await mapLimit(servicePrincipals, concurrency, async ({ record }) => {
    await ensureActive();
    const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
    const owners = await collect(client, endpoint, sanitizeDirectoryObject, scan);
    scan.servicePrincipalOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
  });
  options.onProgress?.({
    stage: "owners",
    collected: scan.applicationOwners.length + scan.servicePrincipalOwners.length,
    detail: "Ownership relationships collected",
  });
  if (!stageComplete("owners")) await checkpoint("owners");

  if (!stageComplete("roles") && hasScope(options.enabledScopes, "RoleManagement.Read.Directory")) {
    await ensureActive();
    scan.roleDefinitions!.push(...await collect(client, "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn", sanitizeRoleDefinition, scan));
    scan.roleAssignments!.push(...await collect(client, "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId", sanitizeRoleSchedule, scan));
    scan.roleEligibilities!.push(...await collect(client, "/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId", sanitizeRoleSchedule, scan));
    options.onProgress?.({ stage: "roles", collected: scan.roleAssignments!.length + scan.roleEligibilities!.length, detail: "Active and eligible administrative roles collected" });
  }
  if (!stageComplete("roles")) await checkpoint("roles");
  if (!stageComplete("conditionalAccess") && hasScope(options.enabledScopes, "Policy.Read.All")) {
    await ensureActive();
    scan.conditionalAccessPolicies!.push(...await collect(client, "/identity/conditionalAccess/policies?$select=id,displayName,state,conditions,grantControls", sanitizeConditionalAccessPolicy, scan));
    options.onProgress?.({ stage: "conditionalAccess", collected: scan.conditionalAccessPolicies!.length, detail: "Conditional Access policies collected" });
  }
  if (!stageComplete("conditionalAccess")) await checkpoint("conditionalAccess");
  if (!stageComplete("crossTenantAccess") && hasScope(options.enabledScopes, "Policy.Read.All")) {
    await ensureActive();
    scan.crossTenantPartners!.push(...await collect(client, "/policies/crossTenantAccessPolicy/partners?$select=tenantId,inboundTrust,isInMultiTenantOrganization", sanitizeCrossTenantPartner, scan));
    options.onProgress?.({ stage: "crossTenantAccess", collected: scan.crossTenantPartners!.length, detail: "Partner-specific cross-tenant trust collected" });
  }
  if (!stageComplete("crossTenantAccess")) await checkpoint("crossTenantAccess");
  if (!stageComplete("activity") && hasScope(options.enabledScopes, "AuditLog.Read.All")) {
    await ensureActive();
    const since = new Date(Date.parse(scan.scannedAt) - 30 * 24 * 60 * 60 * 1_000).toISOString();
    scan.signIns!.push(...await collect(client, `/auditLogs/signIns?$top=250&$filter=createdDateTime%20ge%20${encodeURIComponent(since)}&$select=id,createdDateTime,servicePrincipalId,resourceServicePrincipalId,appDisplayName,resourceDisplayName,status`, sanitizeSignIn, scan));
    options.onProgress?.({ stage: "activity", collected: scan.signIns!.length, detail: "Time-bounded sign-in activity collected" });
  }
  if (!stageComplete("activity")) await checkpoint("activity");

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
  return { id: requiredString(value.id), displayName: stringOrNull(value.displayName), userType: stringOrNull(value.userType), "@odata.type": stringOrNull(value["@odata.type"]) ?? undefined };
}

function sanitizeUser(value: GraphUser): GraphUser { return { ...sanitizeDirectoryObject(value), userType: stringOrNull(value.userType), externalUserState: stringOrNull(value.externalUserState), "@odata.type": "#microsoft.graph.user" }; }
function sanitizeGroup(value: GraphGroup): GraphGroup { return { ...sanitizeDirectoryObject(value), securityEnabled: typeof value.securityEnabled === "boolean" ? value.securityEnabled : null, "@odata.type": "#microsoft.graph.group" }; }
function sanitizeRoleDefinition(value: GraphRoleDefinition): GraphRoleDefinition { return { id: requiredString(value.id), displayName: requiredString(value.displayName), templateId: stringOrNull(value.templateId), isBuiltIn: typeof value.isBuiltIn === "boolean" ? value.isBuiltIn : null }; }
function sanitizeRoleSchedule(value: GraphRoleSchedule): GraphRoleSchedule { return { id: requiredString(value.id), principalId: requiredString(value.principalId), roleDefinitionId: requiredString(value.roleDefinitionId), directoryScopeId: stringOrNull(value.directoryScopeId) }; }
function sanitizeConditionalAccessPolicy(value: GraphConditionalAccessPolicy): GraphConditionalAccessPolicy { const conditions = value.conditions && typeof value.conditions === "object" ? value.conditions : {}; const users = conditions.users && typeof conditions.users === "object" ? conditions.users : {}; const applications = conditions.applications && typeof conditions.applications === "object" ? conditions.applications : {}; const strings = (item: unknown) => Array.isArray(item) ? item.filter((entry): entry is string => typeof entry === "string") : []; return { id: requiredString(value.id), displayName: requiredString(value.displayName), state: requiredString(value.state), conditions: { users: { includeUsers: strings(users.includeUsers), includeGroups: strings(users.includeGroups) }, applications: { includeApplications: strings(applications.includeApplications) } }, grantControls: value.grantControls && typeof value.grantControls === "object" ? { builtInControls: strings(value.grantControls.builtInControls), operator: stringOrNull(value.grantControls.operator) } : null }; }
function sanitizeSignIn(value: GraphSignIn): GraphSignIn { return { id: requiredString(value.id), createdDateTime: requiredString(value.createdDateTime), servicePrincipalId: stringOrNull(value.servicePrincipalId), resourceServicePrincipalId: stringOrNull(value.resourceServicePrincipalId), appDisplayName: stringOrNull(value.appDisplayName), resourceDisplayName: stringOrNull(value.resourceDisplayName), status: value.status && typeof value.status === "object" ? { errorCode: typeof value.status.errorCode === "number" ? value.status.errorCode : null } : null }; }
function sanitizeCrossTenantPartner(value: GraphCrossTenantPartner): GraphCrossTenantPartner { return { tenantId: requiredString(value.tenantId), inboundTrust: value.inboundTrust ? { isMfaAccepted: value.inboundTrust.isMfaAccepted === true, isCompliantDeviceAccepted: value.inboundTrust.isCompliantDeviceAccepted === true, isHybridAzureADJoinedDeviceAccepted: value.inboundTrust.isHybridAzureADJoinedDeviceAccepted === true } : null, isInMultiTenantOrganization: value.isInMultiTenantOrganization === true }; }

function hasScope(scopes: readonly string[] | undefined, shortName: string): boolean { return Boolean(scopes?.some((scope) => scope === shortName || scope.endsWith(`/${shortName}`))); }

function requiredString(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError("Microsoft Graph returned a record without a required identifier.");
  return value;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
