import type { CollectorCoverage, DirectoryNode, RelationshipEdge, RelationshipType } from "@entra-explorer/domain";

export const ENGINE_VERSION = "1.0.2";
export const RULE_VERSION = "entra-configured/3";
export type Verdict = "supported" | "refuted" | "unknown" | "conflicting";
export type EvidenceClass = "configured" | "observed" | "inferred";
export interface Budget { maxSteps: number; maxPaths: number; maxDepth: number }
export const DEFAULT_BUDGET: Budget = { maxSteps: 50_000, maxPaths: 128, maxDepth: 12 };
export interface Limits extends Budget { steps: number; exhausted: boolean }
export interface EngineContext {
  tenantId: string;
  snapshotIds: string[];
  engineVersion: string;
  ruleVersion: string;
  collectedAt: string[];
}
export interface Conflict { factId: string; variants: string[] }
export interface EvidenceModel extends EngineContext {
  nodes: DirectoryNode[];
  edges: RelationshipEdge[];
  coverage: CollectorCoverage[];
  conflicts: Conflict[];
}
export type QueryKind = "application-permission" | "delegated-permission" | "assignment" | "membership" | "ownership" | "active-role" | "eligible-role" | "control-path";
export interface AuthorizationQuery {
  tenantId: string;
  kind: QueryKind;
  principalId: string;
  resourceId: string;
  permissionId?: string;
  userId?: string;
  directoryScopeId?: string;
}
export interface ProofFact {
  id: string;
  kind: "relationship" | "object" | "coverage";
  sourceEndpoint: string;
  sourceEndpoints?: string[];
  sourceRecordIds: string[];
  sourceObjectId: string;
  targetObjectId: string;
  collectedAt: string;
  completeness: string;
  relationshipType?: RelationshipType;
}
export interface ProofStep { id: string; rule: string; inputs: string[]; conclusion: string }
export interface EvidenceProof extends EngineContext {
  query: AuthorizationQuery;
  verdict: Verdict;
  evidenceClass: EvidenceClass;
  paths: string[][];
  facts: ProofFact[];
  derivation: ProofStep[];
  dependencies: string[];
  missing: string[];
  assumptions: string[];
  conflicts: Conflict[];
  limits: Limits;
}
export interface TimeWindow { startsAt: string; endsAt: string }
export interface WorkflowResult extends EngineContext {
  verdict: Verdict;
  assumptions: string[];
  missing: string[];
  limits: { steps: number; maxSteps: number; exhausted: boolean };
}
