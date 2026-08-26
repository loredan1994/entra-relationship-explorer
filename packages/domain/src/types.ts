export type NodeKind = "application" | "servicePrincipal" | "user" | "group";

export type RelationshipType =
  | "INSTANTIATES_AS"
  | "CAN_CALL_AS_APP"
  | "CAN_CALL_DELEGATED"
  | "ASSIGNED_TO"
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
  ownerIds: string[];
  credential?: {
    status: "healthy" | "expiring" | "expired" | "none";
    expiresAt: string | null;
  };
  risk: {
    level: RiskLevel;
    reason: string;
  };
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
  };
  nodes: DirectoryNode[];
  edges: RelationshipEdge[];
}

export interface RelationshipView {
  edge: RelationshipEdge;
  source: DirectoryNode;
  target: DirectoryNode;
}
