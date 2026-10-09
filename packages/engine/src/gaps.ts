import { COLLECTORS } from "@entra-explorer/domain";
import { unique } from "./canonical";
import { solveChanges } from "./solver";
import type { EvidenceProof, WorkflowResult } from "./types";

export interface ReadCandidate { id: string; resolves: string[]; endpoints: string[]; scopes: string[]; cost: number; requirement: string }
export interface ReadPlan { reads: string[]; endpoints: string[]; requiredScopes: string[]; unavailableScopes: string[]; cost: number; mayResolve: string[] }
export interface GapResult extends WorkflowResult { plans: ReadPlan[]; unresolved: string[]; optimal: boolean; lowerBound: number }

const ENDPOINTS: Record<string, string[]> = {
  applications: ["/applications"], servicePrincipals: ["/servicePrincipals"],
  appRoleAssignments: ["/servicePrincipals/{resource-id}/appRoleAssignedTo"], delegatedPermissionGrants: ["/oauth2PermissionGrants"],
  usersAndGroups: ["/users", "/groups"], groupMemberships: ["/groups/{group-id}/members"],
  owners: ["/applications/{id}/owners", "/servicePrincipals/{id}/owners"],
  roles: ["/roleManagement/directory/roleDefinitions", "/roleManagement/directory/roleAssignments", "/roleManagement/directory/roleEligibilitySchedules"],
  federatedIdentityCredentials: ["/applications/{id}/federatedIdentityCredentials", "/servicePrincipals?$select=id,servicePrincipalType&$expand=federatedIdentityCredentials($select=id,name,issuer,subject,audiences,description)"],
  conditionalAccess: ["/identity/conditionalAccess/policies"],
};

function prerequisites(proof: EvidenceProof): string[] {
  return unique([...proof.missing, ...proof.conflicts.map(conflict => conflict.factId)]);
}

export function suggestReads(proof: EvidenceProof): ReadCandidate[] {
  const gaps = prerequisites(proof);
  return COLLECTORS.flatMap(c => {
    const missing = gaps.filter(m => m === `coverage:${c.id}`);
    return missing.length && ENDPOINTS[c.id] ? [{ id: c.id, resolves: missing, endpoints: ENDPOINTS[c.id]!, scopes: [c.scope], cost: ENDPOINTS[c.id]!.length,
      requirement: `${c.role}. All pages and object instances must succeed; a read may still be denied or partial.` }] : [];
  });
}

function readScope(scope: string): boolean {
  if (scope.length > 256) return false;
  const segments = scope.split(".");
  return segments.includes("Read", 1) && segments.every(segment => /^[A-Za-z]+$/.test(segment));
}

export function planEvidenceGaps(proof: EvidenceProof, reads = suggestReads(proof), availableScopes: string[] = [], maxSteps = 100_000): GapResult {
  if (reads.some(r => r.endpoints.some(e => !e.startsWith("/") || e.startsWith("//")) || r.scopes.some(s => !readScope(s)))) throw new Error("Evidence plans accept relative GET endpoints and read scopes only.");
  const gaps = prerequisites(proof);
  const resolvable = gaps.filter(m => reads.some(r => r.resolves.includes(m)));
  const solution = solveChanges({ context: proof, paths: resolvable.map(id => ({ id, dependencies: [id] })),
    candidates: reads.map(r => ({ id: r.id, cost: r.cost, removes: r.resolves, description: r.requirement })), protectedIntegrations: [], evidenceComplete: true, maxSteps });
  const plans = solution.plans.map(p => {
    const chosen = reads.filter(r => p.changes.includes(r.id));
    const scopes = unique(chosen.flatMap(r => r.scopes));
    return { reads: p.changes, endpoints: unique(chosen.flatMap(r => r.endpoints)), requiredScopes: scopes, unavailableScopes: scopes.filter(s => !availableScopes.includes(s)), cost: p.cost, mayResolve: unique(chosen.flatMap(r => r.resolves).filter(m => gaps.includes(m))) };
  });
  const unresolved = gaps.filter(m => !resolvable.includes(m));
  return { tenantId: proof.tenantId, snapshotIds: proof.snapshotIds, engineVersion: proof.engineVersion, ruleVersion: proof.ruleVersion, collectedAt: proof.collectedAt,
    verdict: unresolved.length || solution.limits.exhausted ? "unknown" : "supported", plans, unresolved, optimal: solution.status === "optimal", lowerBound: solution.lowerBound,
    missing: unresolved, limits: solution.limits, assumptions: ["Plans minimize declared read cost over supplied candidates. Shared prerequisites are fetched once.", "This is a proposed collection plan, not consent or a guarantee that a read will resolve a question. Role, license, pagination, retention, and unsupported semantics remain separate constraints."] };
}
