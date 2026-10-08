export type NodeKind = "application" | "servicePrincipal" | "managedIdentity" | "user" | "group" | "device" | "administrativeUnit" | "federatedCredential" | "appRole" | "directoryRole" | "policy" | "externalTenant";

export type RelationshipType =
  | "INSTANTIATES_AS"
  | "CAN_CALL_AS_APP"
  | "CAN_CALL_DELEGATED"
  | "ASSIGNED_TO"
  | "EXPOSES_APP_ROLE"
  | "GRANTED_APP_ROLE"
  | "MEMBER_OF"
  | "IN_ADMINISTRATIVE_UNIT"
  | "FEDERATES_AS"
  | "ACTIVE_IN_ROLE"
  | "ELIGIBLE_FOR_ROLE"
  | "GOVERNED_BY"
  | "ASSIGNS_CONSENT_POLICY"
  | "CROSS_TENANT_ACCESS"
  | "OWNS"
  | "OBSERVED_CALL";

export type RiskLevel = "low" | "review" | "high";

export interface TenantRef {
  tenantId: string;
  tenantLabel: string;
}

export interface DirectoryNode {
  id: string;
  tenantId: string;
  kind: NodeKind;
  label: string;
  description: string;
  appId?: string;
  publisher?: string;
  isExternal?: boolean;
  metadata?: Record<string, string | boolean | number | null>;
  ownerIds: string[];
  /** Absent in older snapshots means not collected, not an empty manifest. */
  requestedPermissions?: RequestedPermission[];
  permissionDefinitions?: PermissionDefinition[];
  credentials?: CredentialMetadata[];
  sourceEndpoint?: string;
  /** Missing historical fields remain unknown, never false or disabled. */
  applicationProfile?: ApplicationProfile;
  credential?: {
    status: "healthy" | "expiring" | "expired" | "none";
    expiresAt: string | null;
  };
  risk: {
    level: RiskLevel;
    reason: string;
  };
}

export interface ApplicationProfile {
  signInAudience: string | null;
  verifiedPublisherId: string | null;
  verifiedPublisherName: string | null;
  accountEnabled?: boolean | null;
  assignmentRequired?: boolean | null;
  homeTenantId?: string | null;
  preferredSsoMode?: string | null;
}

export interface RelationshipEvidence {
  configured: boolean;
  observed: {
    lastSeenAt: string;
    windowStartsAt: string;
  } | null;
  scannedAt: string;
  sourceEndpoint: string;
  sourceRecordIds: string[];
  sourceObjectId: string;
  targetObjectId: string;
  completeness: "complete" | "partial" | "unresolved";
}

export interface RelationshipEdge {
  id: string;
  tenantId: string;
  type: RelationshipType;
  sourceId: string;
  targetId: string;
  plainLabel: string;
  permissions: string[];
  permissionIds?: string[];
  consent?: { audience: "all-users" | "single-user" | "unknown"; principalId: string | null };
  scope?: {
    directoryScopeId: string;
    objectId: string | null;
  };
  evidence: RelationshipEvidence;
}

export interface TenantSnapshot {
  id: string;
  tenant: TenantRef;
  scannedAt: string;
  mode: "fixture" | "tenant";
  completion: {
    status: "complete" | "partial";
    collectedEndpoints: string[];
    skippedEndpoints: string[];
    errors: string[];
    collectors?: CollectorCoverage[];
  };
  auditEvents?: DirectoryAuditEvent[];
  nodes: DirectoryNode[];
  edges: RelationshipEdge[];
}

export interface RequestedPermission { resourceAppId: string; permissionId: string; kind: "application" | "delegated"; }
export interface PermissionDefinition { id: string; value: string; kind: "application" | "delegated"; }
export interface CredentialMetadata {
  id: string;
  kind: "password" | "certificate";
  label: string | null;
  startsAt: string | null;
  expiresAt: string | null;
  sourceEndpoint: string;
}
export type CoverageState = "complete" | "partial" | "denied" | "unavailable" | "not-enabled" | "unknown";
export interface CollectorCoverage {
  id: string;
  state: CoverageState;
  reason: string;
  collectedAt: string | null;
  endpoints: string[];
  failedEndpoints: string[];
  itemCount: number;
  scope: string;
  limits?: { maxPagesPerEndpoint: number; maxItemsPerEndpoint: number };
  window?: { startsAt: string; endsAt: string; eventClasses: string[] };
}
export interface DirectoryAuditEvent {
  id: string;
  tenantId: string;
  occurredAt: string;
  activity: string;
  result: string;
  actor: { id: string | null; kind: "user" | "application" | "unknown" };
  targetIds: string[];
  sourceEndpoint: string;
}

export interface RelationshipView {
  edge: RelationshipEdge;
  source: DirectoryNode;
  target: DirectoryNode;
}
