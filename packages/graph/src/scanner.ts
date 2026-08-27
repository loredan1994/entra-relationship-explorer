import { GraphRequestError, ReadOnlyGraphClient } from "./client";
import type {
  GraphAppRoleAssignment,
  GraphApplication,
  GraphAdministrativeUnit,
  GraphAuthorizationPolicy,
  GraphCredentialMetadata,
  GraphDevice,
  GraphDirectoryObject,
  GraphFederatedIdentityCredential,
  GraphGroup,
  GraphConditionalAccessPolicy,
  GraphOAuth2PermissionGrant,
  GraphPermissionGrantConditionSet,
  GraphPermissionGrantPolicy,
  GraphServicePrincipal,
  GraphServicePrincipalFederation,
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

type ScanStage = ScanProgressEvent["stage"];

/** Everything one scan run needs to reach Graph and record what it found. */
interface ScanRun {
  readonly client: ReadOnlyGraphClient;
  readonly scan: RawTenantScan;
  readonly options: ScanTenantOptions;
  readonly concurrency: number;
  readonly completedStages: ScanStage[];
}

const APPLICATIONS_ENDPOINT = "/applications?$select=id,appId,displayName,publisherDomain,appRoles,passwordCredentials,keyCredentials";
const SERVICE_PRINCIPALS_ENDPOINT = "/servicePrincipals?$select=id,appId,displayName,publisherName,servicePrincipalType,appRoles,passwordCredentials,keyCredentials";
const SERVICE_PRINCIPAL_FEDERATION_ENDPOINT = "/servicePrincipals?$select=id,servicePrincipalType&$expand=federatedIdentityCredentials($select=id,name,issuer,subject,audiences,description)";
const USERS_ENDPOINT = "/users?$select=id,displayName,userType,externalUserState";
const GROUPS_ENDPOINT = "/groups?$select=id,displayName,securityEnabled";
const DEVICES_ENDPOINT = "/devices?$select=id,deviceId,displayName,accountEnabled,isCompliant,isManaged,isManagementRestricted,operatingSystem,operatingSystemVersion,profileType,registrationDateTime,trustType";
const ADMINISTRATIVE_UNITS_ENDPOINT = "/directory/administrativeUnits?$select=id,displayName,description,isMemberManagementRestricted,membershipType,membershipRuleProcessingState,visibility";
const GRANTS_ENDPOINT = "/oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope";
const ROLE_DEFINITIONS_ENDPOINT = "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn";
const ROLE_ASSIGNMENTS_ENDPOINT = "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId";
const ROLE_ELIGIBILITIES_ENDPOINT = "/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId";
const CONDITIONAL_ACCESS_ENDPOINT = "/identity/conditionalAccess/policies?$select=id,displayName,state,conditions,grantControls";
const AUTHORIZATION_POLICY_ENDPOINT = "/policies/authorizationPolicy?$select=id,displayName,allowInvitesFrom,allowEmailVerifiedUsersToJoinOrganization,blockMsolPowerShell,defaultUserRolePermissions";
const PERMISSION_GRANT_POLICIES_ENDPOINT = "/policies/permissionGrantPolicies?$select=id,displayName,description";
const CROSS_TENANT_ENDPOINT = "/policies/crossTenantAccessPolicy/partners?$select=tenantId,inboundTrust,isInMultiTenantOrganization";
/** Sign-in activity is read for the 30 days before the scan, never the whole history. */
const ACTIVITY_WINDOW_MS = 30 * 24 * 60 * 60 * 1_000;

export async function scanTenant(
  client: ReadOnlyGraphClient,
  tenantId: string,
  options: ScanTenantOptions = {},
): Promise<RawTenantScan> {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error("A concrete Microsoft Entra tenant ID is required.");
  if (options.resumeFrom && options.resumeFrom.tenantId !== tenantId) throw new Error("A scan checkpoint cannot cross tenant boundaries.");
  const scan: RawTenantScan = options.resumeFrom ? structuredClone(options.resumeFrom) : emptyScan(tenantId, options);
  initializeAddedCollections(scan);
  const run: ScanRun = {
    client,
    scan,
    options,
    concurrency: options.concurrency ?? 4,
    completedStages: (scan.completedStages ??= []),
  };

  // Stage order is the collection order: later stages fan out over what earlier ones found.
  await runStage(run, "applications", () => collectApplications(run));
  await runStage(run, "servicePrincipals", () => collectServicePrincipals(run));
  await runStage(run, "federatedIdentityCredentials", () => collectFederatedIdentityCredentials(run));
  await runStage(run, "usersAndGroups", () => collectUsersAndGroups(run));
  await runStage(run, "groupMemberships", () => collectGroupMemberships(run));
  await runStage(run, "devices", () => collectDevices(run));
  await runStage(run, "administrativeUnits", () => collectAdministrativeUnits(run));
  await runStage(run, "delegatedPermissionGrants", () => collectDelegatedGrants(run));
  await runStage(run, "appRoleAssignments", () => collectAppRoleAssignments(run));
  await collectOwners(run);
  await runStage(run, "roles", () => collectDirectoryRoles(run));
  await runStage(run, "conditionalAccess", () => collectConditionalAccess(run));
  await runStage(run, "authorizationPolicy", () => collectAuthorizationPolicy(run));
  await runStage(run, "permissionGrantPolicies", () => collectPermissionGrantPolicies(run));
  await runStage(run, "crossTenantAccess", () => collectCrossTenantAccess(run));
  await runStage(run, "activity", () => collectActivity(run));

  return scan;
}

function initializeAddedCollections(scan: RawTenantScan): void {
  scan.devices ??= [];
  scan.administrativeUnits ??= [];
  scan.administrativeUnitMemberships ??= [];
  scan.federatedIdentityCredentials ??= [];
  scan.authorizationPolicies ??= [];
  scan.permissionGrantPolicies ??= [];
  scan.permissionGrantPolicyIncludes ??= [];
  scan.permissionGrantPolicyExcludes ??= [];
}

function emptyScan(tenantId: string, options: ScanTenantOptions): RawTenantScan {
  return {
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
    devices: [],
    administrativeUnits: [],
    administrativeUnitMemberships: [],
    federatedIdentityCredentials: [],
    roleDefinitions: [],
    roleAssignments: [],
    roleEligibilities: [],
    conditionalAccessPolicies: [],
    signIns: [],
    crossTenantPartners: [],
    authorizationPolicies: [],
    permissionGrantPolicies: [],
    permissionGrantPolicyIncludes: [],
    permissionGrantPolicyExcludes: [],
    collectedEndpoints: [],
    skippedEndpoints: [],
    errors: [],
    completedStages: [],
  };
}

/**
 * Runs one stage unless a resumed checkpoint already completed it, then records it as done.
 * Cancellation is checked before every stage, including a completed one, so a caller that
 * withdraws consent stops the run even when the remaining work is only bookkeeping.
 */
async function runStage(run: ScanRun, stage: ScanStage, work: () => Promise<void>): Promise<void> {
  await ensureActive(run);
  if (run.completedStages.includes(stage)) return;
  await work();
  await completeStage(run, stage);
}

async function completeStage(run: ScanRun, stage: ScanStage): Promise<void> {
  run.completedStages.push(stage);
  await run.options.onCheckpoint?.(run.scan);
}

async function ensureActive(run: ScanRun): Promise<void> {
  if (await run.options.shouldCancel?.()) throw new ScanCancelledError();
}

function report(run: ScanRun, stage: ScanStage, collected: number, detail: string): void {
  run.options.onProgress?.({ stage, collected, detail });
}

function read<TInput, TOutput>(
  run: ScanRun,
  endpoint: string,
  sanitize: (record: TInput) => TOutput,
  onPage?: (count: number) => void,
): Promise<Sourced<TOutput>[]> {
  return collect(run.client, endpoint, sanitize, run.scan, onPage);
}

async function readOne<TInput, TOutput>(run: ScanRun, endpoint: string, sanitize: (record: TInput) => TOutput): Promise<Sourced<TOutput> | null> {
  try {
    const record = sanitize(await run.client.getOne<TInput>(endpoint));
    run.scan.collectedEndpoints.push(endpoint);
    return { endpoint, record };
  } catch (error) {
    recordCollectionError(run.scan, endpoint, error);
    return null;
  }
}

async function collectApplications(run: ScanRun): Promise<void> {
  run.scan.applications.push(...await read(run, APPLICATIONS_ENDPOINT, sanitizeApplication, (count) =>
    report(run, "applications", count, "Application blueprints collected"),
  ));
}

async function collectServicePrincipals(run: ScanRun): Promise<void> {
  run.scan.servicePrincipals.push(...await read(run, SERVICE_PRINCIPALS_ENDPOINT, sanitizeServicePrincipal, (count) =>
    report(run, "servicePrincipals", count, "Tenant identities collected"),
  ));
}

async function collectFederatedIdentityCredentials(run: ScanRun): Promise<void> {
  const { scan } = run;
  await mapLimit(scan.applications, run.concurrency, async ({ record }) => {
    await ensureActive(run);
    const endpoint = `/applications/${encodeURIComponent(record.id)}/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences,description`;
    const credentials = await read(run, endpoint, sanitizeFederatedIdentityCredential);
    scan.federatedIdentityCredentials!.push(...credentials.map((credential) => ({ ...credential, parentId: record.id, parentType: "application" as const })));
    report(run, "federatedIdentityCredentials", scan.federatedIdentityCredentials!.length, "Federated workload trust credentials collected");
  });
  const managedIdentityContainers = await read(run, SERVICE_PRINCIPAL_FEDERATION_ENDPOINT, sanitizeServicePrincipalFederation);
  for (const container of managedIdentityContainers) {
    if (container.record.servicePrincipalType?.toLocaleLowerCase() !== "managedidentity") continue;
    scan.federatedIdentityCredentials!.push(...container.record.federatedIdentityCredentials!.map((record) => ({ endpoint: container.endpoint, record, parentId: container.record.id, parentType: "managedIdentity" as const })));
  }
  report(run, "federatedIdentityCredentials", scan.federatedIdentityCredentials!.length, "Federated workload trust credentials collected");
}

async function collectUsersAndGroups(run: ScanRun): Promise<void> {
  const { scan } = run;
  const users = await read(run, USERS_ENDPOINT, sanitizeUser);
  scan.users!.push(...users);
  const groups = await read(run, GROUPS_ENDPOINT, sanitizeGroup);
  scan.groups!.push(...groups);
  report(run, "usersAndGroups", users.length + groups.length, "People and groups collected");
}

async function collectGroupMemberships(run: ScanRun): Promise<void> {
  const { scan } = run;
  await mapLimit(scan.groups!, run.concurrency, async ({ record }) => {
    await ensureActive(run);
    const endpoint = `/groups/${encodeURIComponent(record.id)}/members?$select=id,displayName,userType`;
    const members = await read(run, endpoint, sanitizeDirectoryObject);
    scan.groupMemberships!.push(...members.map((member) => ({ ...member, groupId: record.id })));
    report(run, "groupMemberships", scan.groupMemberships!.length, "Direct group memberships collected");
  });
}

async function collectDevices(run: ScanRun): Promise<void> {
  run.scan.devices!.push(...await read(run, DEVICES_ENDPOINT, sanitizeDevice, (count) =>
    report(run, "devices", count, "Directory devices collected"),
  ));
}

async function collectAdministrativeUnits(run: ScanRun): Promise<void> {
  const { scan } = run;
  const units = await read(run, ADMINISTRATIVE_UNITS_ENDPOINT, sanitizeAdministrativeUnit);
  scan.administrativeUnits!.push(...units);
  await mapLimit(units, run.concurrency, async ({ record }) => {
    await ensureActive(run);
    const endpoint = `/directory/administrativeUnits/${encodeURIComponent(record.id)}/members?$select=id,displayName,userType,deviceId`;
    const members = await read(run, endpoint, sanitizeDirectoryObject);
    scan.administrativeUnitMemberships!.push(...members.map((member) => ({ ...member, administrativeUnitId: record.id })));
    report(run, "administrativeUnits", scan.administrativeUnitMemberships!.length, "Administrative unit membership collected");
  });
  report(run, "administrativeUnits", units.length, "Administrative units collected");
}

async function collectDelegatedGrants(run: ScanRun): Promise<void> {
  run.scan.oauth2PermissionGrants.push(...await read(run, GRANTS_ENDPOINT, sanitizeGrant, (count) =>
    report(run, "delegatedPermissionGrants", count, "Delegated permission grants collected"),
  ));
}

async function collectAppRoleAssignments(run: ScanRun): Promise<void> {
  const { scan } = run;
  await mapLimit(scan.servicePrincipals, run.concurrency, async ({ record }) => {
    await ensureActive(run);
    const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/appRoleAssignedTo?$select=id,appRoleId,principalDisplayName,principalId,principalType,resourceDisplayName,resourceId`;
    const assignments = await read(run, endpoint, sanitizeAssignment);
    scan.appRoleAssignments.push(...assignments);
    report(run, "appRoleAssignments", scan.appRoleAssignments.length, "Application and user assignments collected");
  });
}

/**
 * Ownership fans out over both inventories. The progress event is reported even when the
 * stage was already complete, so a caller that reconnects mid-scan still learns the totals
 * it inherited from the checkpoint.
 */
async function collectOwners(run: ScanRun): Promise<void> {
  const { scan } = run;
  const pending = !run.completedStages.includes("owners");
  await ensureActive(run);
  if (pending) {
    await mapLimit(scan.applications, run.concurrency, async ({ record }) => {
      await ensureActive(run);
      const endpoint = `/applications/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
      const owners = await read(run, endpoint, sanitizeDirectoryObject);
      scan.applicationOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
    });
    await mapLimit(scan.servicePrincipals, run.concurrency, async ({ record }) => {
      await ensureActive(run);
      const endpoint = `/servicePrincipals/${encodeURIComponent(record.id)}/owners?$select=id,displayName`;
      const owners = await read(run, endpoint, sanitizeDirectoryObject);
      scan.servicePrincipalOwners.push(...owners.map((owner) => ({ ...owner, targetId: record.id })));
    });
  }
  report(run, "owners", scan.applicationOwners.length + scan.servicePrincipalOwners.length, "Ownership relationships collected");
  if (pending) await completeStage(run, "owners");
}

async function collectDirectoryRoles(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "RoleManagement.Read.Directory")) return;
  await ensureActive(run);
  const { scan } = run;
  scan.roleDefinitions!.push(...await read(run, ROLE_DEFINITIONS_ENDPOINT, sanitizeRoleDefinition));
  scan.roleAssignments!.push(...await read(run, ROLE_ASSIGNMENTS_ENDPOINT, sanitizeRoleSchedule));
  scan.roleEligibilities!.push(...await read(run, ROLE_ELIGIBILITIES_ENDPOINT, sanitizeRoleSchedule));
  report(run, "roles", scan.roleAssignments!.length + scan.roleEligibilities!.length, "Active and eligible administrative roles collected");
}

async function collectConditionalAccess(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "Policy.Read.All")) return;
  await ensureActive(run);
  const { scan } = run;
  scan.conditionalAccessPolicies!.push(...await read(run, CONDITIONAL_ACCESS_ENDPOINT, sanitizeConditionalAccessPolicy));
  report(run, "conditionalAccess", scan.conditionalAccessPolicies!.length, "Conditional Access policies collected");
}

async function collectAuthorizationPolicy(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "Policy.Read.All")) return;
  const policy = await readOne(run, AUTHORIZATION_POLICY_ENDPOINT, sanitizeAuthorizationPolicy);
  if (policy) run.scan.authorizationPolicies!.push(policy);
  report(run, "authorizationPolicy", run.scan.authorizationPolicies!.length, "Authorization policy collected");
}

async function collectPermissionGrantPolicies(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "Policy.Read.PermissionGrant")) return;
  const { scan } = run;
  const policies = await read(run, PERMISSION_GRANT_POLICIES_ENDPOINT, sanitizePermissionGrantPolicy);
  scan.permissionGrantPolicies!.push(...policies);
  await mapLimit(policies, run.concurrency, async ({ record }) => {
    await ensureActive(run);
    const includesEndpoint = `/policies/permissionGrantPolicies/${encodeURIComponent(record.id)}/includes`;
    const excludesEndpoint = `/policies/permissionGrantPolicies/${encodeURIComponent(record.id)}/excludes`;
    const includes = await read(run, includesEndpoint, sanitizePermissionGrantConditionSet);
    const excludes = await read(run, excludesEndpoint, sanitizePermissionGrantConditionSet);
    scan.permissionGrantPolicyIncludes!.push(...includes.map((condition) => ({ ...condition, policyId: record.id })));
    scan.permissionGrantPolicyExcludes!.push(...excludes.map((condition) => ({ ...condition, policyId: record.id })));
    report(run, "permissionGrantPolicies", scan.permissionGrantPolicyIncludes!.length + scan.permissionGrantPolicyExcludes!.length, "Consent policy conditions collected");
  });
  report(run, "permissionGrantPolicies", policies.length, "Consent policies collected");
}

async function collectCrossTenantAccess(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "Policy.Read.All")) return;
  await ensureActive(run);
  const { scan } = run;
  scan.crossTenantPartners!.push(...await read(run, CROSS_TENANT_ENDPOINT, sanitizeCrossTenantPartner));
  report(run, "crossTenantAccess", scan.crossTenantPartners!.length, "Partner-specific cross-tenant trust collected");
}

async function collectActivity(run: ScanRun): Promise<void> {
  if (!hasScope(run.options.enabledScopes, "AuditLog.Read.All")) return;
  await ensureActive(run);
  const { scan } = run;
  const since = new Date(Date.parse(scan.scannedAt) - ACTIVITY_WINDOW_MS).toISOString();
  const endpoint = `/auditLogs/signIns?$top=250&$filter=createdDateTime%20ge%20${encodeURIComponent(since)}&$select=id,createdDateTime,servicePrincipalId,resourceServicePrincipalId,appDisplayName,resourceDisplayName,status`;
  scan.signIns!.push(...await read(run, endpoint, sanitizeSignIn));
  report(run, "activity", scan.signIns!.length, "Time-bounded sign-in activity collected");
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
    // Sanitize before claiming coverage: a record that fails validation leaves the
    // endpoint skipped, so downstream findings never read absence as assurance.
    const collected = records.map((record) => ({ endpoint, record: sanitize(record) }));
    scan.collectedEndpoints.push(endpoint);
    return collected;
  } catch (error) {
    recordCollectionError(scan, endpoint, error);
    return [];
  }
}

function recordCollectionError(scan: RawTenantScan, endpoint: string, error: unknown): void {
  const graphError = error instanceof GraphRequestError ? error : null;
  scan.skippedEndpoints.push(endpoint);
  scan.errors.push({ endpoint, code: graphError?.code ?? "unexpected_error", message: graphError?.message ?? "The read failed without exposing response data." });
}

async function mapLimit<T>(items: T[], limit: number, task: (item: T) => Promise<void>): Promise<void> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new RangeError("Scanner concurrency must be between 1 and 20.");
  let nextIndex = 0;
  await Promise.all(
    // Stryker disable next-line MethodExpression: extra workers past the item count exit immediately, so the bound only avoids idle promises.
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (nextIndex < items.length) {
        await task(items[nextIndex++]!);
      }
    }),
  );
}

function credentialMetadata(value: unknown): GraphCredentialMetadata[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((candidate) => {
    // Stryker disable next-line ConditionalExpression: a non-object entry carries no string `keyId` either, so both guards drop the same records.
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

function sanitizeFederatedIdentityCredential(value: GraphFederatedIdentityCredential): GraphFederatedIdentityCredential {
  return { id: requiredString(value.id), name: requiredString(value.name), issuer: requiredString(value.issuer), subject: requiredString(value.subject), audiences: stringArray(value.audiences), description: stringOrNull(value.description) };
}

function sanitizeServicePrincipalFederation(value: GraphServicePrincipalFederation): GraphServicePrincipalFederation {
  return { id: requiredString(value.id), servicePrincipalType: stringOrNull(value.servicePrincipalType), federatedIdentityCredentials: Array.isArray(value.federatedIdentityCredentials) ? value.federatedIdentityCredentials.map(sanitizeFederatedIdentityCredential) : [] };
}

function sanitizeRoles(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((candidate) => {
    // Stryker disable next-line ConditionalExpression: a non-object entry carries no string `id` either, so both guards drop the same records.
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
function sanitizeDevice(value: GraphDevice): GraphDevice { return { ...sanitizeDirectoryObject(value), deviceId: requiredString(value.deviceId), accountEnabled: booleanOrNull(value.accountEnabled), isCompliant: booleanOrNull(value.isCompliant), isManaged: booleanOrNull(value.isManaged), isManagementRestricted: booleanOrNull(value.isManagementRestricted), operatingSystem: stringOrNull(value.operatingSystem), operatingSystemVersion: stringOrNull(value.operatingSystemVersion), profileType: stringOrNull(value.profileType), registrationDateTime: stringOrNull(value.registrationDateTime), trustType: stringOrNull(value.trustType), "@odata.type": "#microsoft.graph.device" }; }
function sanitizeAdministrativeUnit(value: GraphAdministrativeUnit): GraphAdministrativeUnit { return { ...sanitizeDirectoryObject(value), description: stringOrNull(value.description), isMemberManagementRestricted: booleanOrNull(value.isMemberManagementRestricted), membershipType: stringOrNull(value.membershipType), membershipRuleProcessingState: stringOrNull(value.membershipRuleProcessingState), visibility: stringOrNull(value.visibility), "@odata.type": "#microsoft.graph.administrativeUnit" }; }
function sanitizeRoleDefinition(value: GraphRoleDefinition): GraphRoleDefinition { return { id: requiredString(value.id), displayName: requiredString(value.displayName), templateId: stringOrNull(value.templateId), isBuiltIn: typeof value.isBuiltIn === "boolean" ? value.isBuiltIn : null }; }
function sanitizeRoleSchedule(value: GraphRoleSchedule): GraphRoleSchedule { return { id: requiredString(value.id), principalId: requiredString(value.principalId), roleDefinitionId: requiredString(value.roleDefinitionId), directoryScopeId: stringOrNull(value.directoryScopeId) }; }
// Stryker disable next-line ConditionalExpression,LogicalOperator: Graph returns JSON, whose only
// truthy non-objects are strings, numbers, and true — none carry the properties read below, so the
// type guards and the truthiness checks always agree.
function sanitizeConditionalAccessPolicy(value: GraphConditionalAccessPolicy): GraphConditionalAccessPolicy { const conditions = value.conditions && typeof value.conditions === "object" ? value.conditions : {}; const users = conditions.users && typeof conditions.users === "object" ? conditions.users : {}; const applications = conditions.applications && typeof conditions.applications === "object" ? conditions.applications : {}; const strings = (item: unknown) => Array.isArray(item) ? item.filter((entry): entry is string => typeof entry === "string") : []; return { id: requiredString(value.id), displayName: requiredString(value.displayName), state: requiredString(value.state), conditions: { users: { includeUsers: strings(users.includeUsers), includeGroups: strings(users.includeGroups) }, applications: { includeApplications: strings(applications.includeApplications) } }, grantControls: value.grantControls && typeof value.grantControls === "object" ? { builtInControls: strings(value.grantControls.builtInControls), operator: stringOrNull(value.grantControls.operator) } : null }; }
function sanitizeSignIn(value: GraphSignIn): GraphSignIn { return { id: requiredString(value.id), createdDateTime: requiredString(value.createdDateTime), servicePrincipalId: stringOrNull(value.servicePrincipalId), resourceServicePrincipalId: stringOrNull(value.resourceServicePrincipalId), appDisplayName: stringOrNull(value.appDisplayName), resourceDisplayName: stringOrNull(value.resourceDisplayName), status: value.status && typeof value.status === "object" ? { errorCode: typeof value.status.errorCode === "number" ? value.status.errorCode : null } : null }; }
function sanitizeCrossTenantPartner(value: GraphCrossTenantPartner): GraphCrossTenantPartner { return { tenantId: requiredString(value.tenantId), inboundTrust: value.inboundTrust ? { isMfaAccepted: value.inboundTrust.isMfaAccepted === true, isCompliantDeviceAccepted: value.inboundTrust.isCompliantDeviceAccepted === true, isHybridAzureADJoinedDeviceAccepted: value.inboundTrust.isHybridAzureADJoinedDeviceAccepted === true } : null, isInMultiTenantOrganization: value.isInMultiTenantOrganization === true }; }
function sanitizeAuthorizationPolicy(value: GraphAuthorizationPolicy): GraphAuthorizationPolicy { const permissions = value.defaultUserRolePermissions && typeof value.defaultUserRolePermissions === "object" ? value.defaultUserRolePermissions : {}; return { id: requiredString(value.id), displayName: requiredString(value.displayName), allowInvitesFrom: stringOrNull(value.allowInvitesFrom), allowEmailVerifiedUsersToJoinOrganization: booleanOrNull(value.allowEmailVerifiedUsersToJoinOrganization), blockMsolPowerShell: booleanOrNull(value.blockMsolPowerShell), defaultUserRolePermissions: { allowedToCreateApps: booleanOrNull(permissions.allowedToCreateApps), allowedToCreateSecurityGroups: booleanOrNull(permissions.allowedToCreateSecurityGroups), allowedToCreateTenants: booleanOrNull(permissions.allowedToCreateTenants), allowedToReadBitlockerKeysForOwnedDevice: booleanOrNull(permissions.allowedToReadBitlockerKeysForOwnedDevice), allowedToReadOtherUsers: booleanOrNull(permissions.allowedToReadOtherUsers), permissionGrantPoliciesAssigned: stringArray(permissions.permissionGrantPoliciesAssigned) } }; }
function sanitizePermissionGrantPolicy(value: GraphPermissionGrantPolicy): GraphPermissionGrantPolicy { return { id: requiredString(value.id), displayName: requiredString(value.displayName), description: stringOrNull(value.description) }; }
function sanitizePermissionGrantConditionSet(value: GraphPermissionGrantConditionSet): GraphPermissionGrantConditionSet { return { id: requiredString(value.id), permissionClassification: stringOrNull(value.permissionClassification), permissionType: stringOrNull(value.permissionType), resourceApplication: stringOrNull(value.resourceApplication), permissions: stringArray(value.permissions), clientApplicationIds: stringArray(value.clientApplicationIds), clientApplicationTenantIds: stringArray(value.clientApplicationTenantIds), clientApplicationPublisherIds: stringArray(value.clientApplicationPublisherIds), clientApplicationsFromVerifiedPublisherOnly: booleanOrNull(value.clientApplicationsFromVerifiedPublisherOnly) }; }

function hasScope(scopes: readonly string[] | undefined, shortName: string): boolean { return Boolean(scopes?.some((scope) => scope === shortName || scope.endsWith(`/${shortName}`))); }

function requiredString(value: unknown): string {
  // Stryker disable next-line ConditionalExpression,StringLiteral: a non-string value throws on .trim()
  // as well, and `collect` reports either throw as the same skipped endpoint without this text.
  if (typeof value !== "string" || !value.trim()) throw new TypeError("Microsoft Graph returned a record without a required identifier.");
  return value;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function booleanOrNull(value: unknown): boolean | null { return typeof value === "boolean" ? value : null; }
function stringArray(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
