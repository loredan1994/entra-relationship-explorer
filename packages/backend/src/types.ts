import type { TenantSnapshot } from "@entra-explorer/domain";

export type ScanJobStatus = "queued" | "running" | "complete" | "failed" | "cancel_requested" | "cancelled";
export type ScanJobStage = "applications" | "servicePrincipals" | "usersAndGroups" | "groupMemberships" | "appRoleAssignments" | "delegatedPermissionGrants" | "owners" | "roles" | "conditionalAccess" | "crossTenantAccess" | "activity" | "normalizing" | "complete";

export interface DurableSession {
  id: string;
  tenantId: string;
  account: unknown;
  accessToken: string;
  accessTokenExpiresAt: number;
  tokenCache: string;
  sessionExpiresAt: number;
}

export interface DurableAuthFlow {
  id: string;
  tenantId: string;
  state: string;
  verifier: string;
  expiresAt: number;
}

export interface ScanJob {
  id: string;
  tenantId: string;
  sessionId: string | null;
  status: ScanJobStatus;
  stage: ScanJobStage;
  collected: number;
  detail: string;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
  snapshotId: string | null;
  completion: "complete" | "partial" | null;
  error: string | null;
  attempt: number;
  workerId: string | null;
}

export interface BackendHealth {
  ok: boolean;
  database: "postgres" | "memory";
}

export interface AccessEvent {
  id: string;
  tenantId: string;
  sessionId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  createdAt: string;
}

export interface ThreatReview {
  findingId: string;
  snapshotId: string;
  tenantId: string;
  disposition: "open" | "mitigating" | "accepted" | "resolved";
  owner: string;
  expiresAt: string | null;
  assumption: string;
  flowDraft?: Array<{ id: string; title: string; evidenceEdgeId: string | null }>;
  updatedAt: string;
}

export interface ScanCheckpoint {
  jobId: string;
  tenantId: string;
  payload: unknown;
  updatedAt: string;
}

export interface Backend {
  migrate(): Promise<void>;
  health(): Promise<BackendHealth>;
  createAuthFlow(flow: DurableAuthFlow): Promise<void>;
  consumeAuthFlow(id: string, tenantId: string, state: string): Promise<DurableAuthFlow | null>;
  createSession(session: DurableSession): Promise<void>;
  getSession(id: string, tenantId: string): Promise<DurableSession | null>;
  updateSession(session: DurableSession): Promise<void>;
  deleteSession(id: string, tenantId: string): Promise<void>;
  enqueueScan(tenantId: string, sessionId: string): Promise<ScanJob>;
  getJob(id: string, tenantId: string): Promise<ScanJob | null>;
  getLatestJob(tenantId: string): Promise<ScanJob | null>;
  recoverStaleJobs(staleBefore: Date): Promise<number>;
  claimNextJob(workerId: string): Promise<ScanJob | null>;
  updateJobProgress(id: string, workerId: string, stage: ScanJobStage, collected: number, detail: string): Promise<void>;
  completeJob(id: string, workerId: string, snapshot: TenantSnapshot, retainAfter: Date): Promise<void>;
  failJob(id: string, workerId: string, error: string): Promise<void>;
  requestScanCancellation(id: string, tenantId: string): Promise<ScanJob | null>;
  isScanCancellationRequested(id: string, workerId: string): Promise<boolean>;
  cancelJob(id: string, workerId: string): Promise<void>;
  getScanCheckpoint(id: string, tenantId: string): Promise<ScanCheckpoint | null>;
  saveScanCheckpoint(checkpoint: ScanCheckpoint, workerId: string): Promise<void>;
  recentSnapshots(tenantId: string, limit?: number): Promise<TenantSnapshot[]>;
  recordAccess(tenantId: string, sessionId: string | null, action: string, resourceType: string, resourceId?: string): Promise<void>;
  recentAccessEvents(tenantId: string, limit?: number): Promise<AccessEvent[]>;
  getThreatReview(tenantId: string, snapshotId: string, findingId: string): Promise<ThreatReview | null>;
  upsertThreatReview(review: ThreatReview, sessionId: string | null): Promise<ThreatReview>;
  close(): Promise<void>;
}
