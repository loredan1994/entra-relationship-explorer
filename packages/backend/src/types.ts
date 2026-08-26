import type { TenantSnapshot } from "@entra-explorer/domain";

export type ScanJobStatus = "queued" | "running" | "complete" | "failed";
export type ScanJobStage = "applications" | "servicePrincipals" | "appRoleAssignments" | "delegatedPermissionGrants" | "owners" | "normalizing" | "complete";

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
  recentSnapshots(tenantId: string, limit?: number): Promise<TenantSnapshot[]>;
  recordAccess(tenantId: string, sessionId: string | null, action: string, resourceType: string, resourceId?: string): Promise<void>;
  recentAccessEvents(tenantId: string, limit?: number): Promise<AccessEvent[]>;
  close(): Promise<void>;
}
