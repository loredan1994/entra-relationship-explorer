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
}

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
  collectedEndpoints: string[];
  skippedEndpoints: string[];
  errors: Array<{ endpoint: string; code: string; message: string }>;
}

export type ScanStage =
  | "applications"
  | "servicePrincipals"
  | "appRoleAssignments"
  | "delegatedPermissionGrants"
  | "owners"
  | "normalizing"
  | "complete";

export interface ScanProgressEvent {
  stage: ScanStage;
  collected: number;
  detail: string;
}
