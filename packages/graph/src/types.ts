export interface GraphCredentialMetadata {
  keyId: string;
  displayName?: string | null;
  startDateTime?: string | null;
  endDateTime?: string | null;
  type?: string | null;
  usage?: string | null;
}

export interface GraphAppRole {
  id: string;
  value?: string | null;
  displayName?: string | null;
  isEnabled?: boolean;
  allowedMemberTypes?: string[];
}

export interface GraphApplication {
  id: string;
  appId: string;
  displayName: string;
  publisherDomain?: string | null;
  appRoles: GraphAppRole[];
  passwordCredentials: GraphCredentialMetadata[];
  keyCredentials: GraphCredentialMetadata[];
}

export interface GraphServicePrincipal {
  id: string;
  appId: string;
  displayName: string;
  publisherName?: string | null;
  servicePrincipalType?: string | null;
  appRoles: GraphAppRole[];
  passwordCredentials: GraphCredentialMetadata[];
  keyCredentials: GraphCredentialMetadata[];
}

export type GraphPrincipalType = "User" | "Group" | "ServicePrincipal" | string;

export interface GraphAppRoleAssignment {
  id: string;
  appRoleId: string;
  principalDisplayName?: string | null;
  principalId: string;
  principalType: GraphPrincipalType;
  resourceDisplayName?: string | null;
  resourceId: string;
}

export interface GraphOAuth2PermissionGrant {
  id: string;
  clientId: string;
  consentType: "AllPrincipals" | "Principal" | string;
  principalId?: string | null;
  resourceId: string;
  scope: string;
}

export interface GraphDirectoryObject {
  "@odata.type"?: string;
  id: string;
  displayName?: string | null;
  userType?: string | null;
}

export interface GraphGroup extends GraphDirectoryObject { securityEnabled?: boolean | null; }
export interface GraphUser extends GraphDirectoryObject { userType?: string | null; externalUserState?: string | null; }
export interface GraphGroupMembership extends Sourced<GraphDirectoryObject> { groupId: string; }
export interface GraphRoleDefinition { id: string; displayName: string; templateId?: string | null; isBuiltIn?: boolean | null; }
export interface GraphRoleSchedule { id: string; principalId: string; roleDefinitionId: string; directoryScopeId?: string | null; }
export interface GraphConditionalAccessPolicy { id: string; displayName: string; state: string; conditions?: { users?: { includeUsers?: string[]; includeGroups?: string[] }; applications?: { includeApplications?: string[] } }; grantControls?: { builtInControls?: string[]; operator?: string | null } | null; }
export interface GraphSignIn { id: string; createdDateTime: string; servicePrincipalId?: string | null; resourceServicePrincipalId?: string | null; appDisplayName?: string | null; resourceDisplayName?: string | null; status?: { errorCode?: number | null } | null; }
export interface GraphCrossTenantPartner { tenantId: string; inboundTrust?: { isMfaAccepted?: boolean | null; isCompliantDeviceAccepted?: boolean | null; isHybridAzureADJoinedDeviceAccepted?: boolean | null } | null; isInMultiTenantOrganization?: boolean | null; }

export interface Sourced<T> {
  endpoint: string;
  record: T;
}

export interface RawTenantScan {
  tenantId: string;
  scannedAt: string;
  applications: Sourced<GraphApplication>[];
  servicePrincipals: Sourced<GraphServicePrincipal>[];
  appRoleAssignments: Sourced<GraphAppRoleAssignment>[];
  oauth2PermissionGrants: Sourced<GraphOAuth2PermissionGrant>[];
  applicationOwners: Array<Sourced<GraphDirectoryObject> & { targetId: string }>;
  servicePrincipalOwners: Array<Sourced<GraphDirectoryObject> & { targetId: string }>;
  users?: Sourced<GraphUser>[];
  groups?: Sourced<GraphGroup>[];
  groupMemberships?: GraphGroupMembership[];
  roleDefinitions?: Sourced<GraphRoleDefinition>[];
  roleAssignments?: Sourced<GraphRoleSchedule>[];
  roleEligibilities?: Sourced<GraphRoleSchedule>[];
  conditionalAccessPolicies?: Sourced<GraphConditionalAccessPolicy>[];
  signIns?: Sourced<GraphSignIn>[];
  crossTenantPartners?: Sourced<GraphCrossTenantPartner>[];
  collectedEndpoints: string[];
  skippedEndpoints: string[];
  errors: Array<{ endpoint: string; code: string; message: string }>;
  completedStages?: ScanStage[];
}

export type ScanStage =
  | "applications"
  | "servicePrincipals"
  | "appRoleAssignments"
  | "delegatedPermissionGrants"
  | "owners"
  | "usersAndGroups"
  | "groupMemberships"
  | "roles"
  | "conditionalAccess"
  | "crossTenantAccess"
  | "activity"
  | "normalizing"
  | "complete";

export interface ScanProgressEvent {
  stage: ScanStage;
  collected: number;
  detail: string;
}
