import type { NodeKind, RelationshipEdge, RelationshipType } from "@entra-explorer/domain";
import { bound, canonical, compare, immutable, unique } from "./canonical";
import { assertTenant, complete, context } from "./model";
import { DEFAULT_BUDGET, type AuthorizationQuery, type Budget, type EvidenceModel, type EvidenceProof, type Limits, type ProofFact, type QueryKind } from "./types";

export const QUERY_COLLECTORS: Record<QueryKind, string[]> = {
  "application-permission": ["servicePrincipals", "appRoleAssignments"],
  "delegated-permission": ["servicePrincipals", "delegatedPermissionGrants", "usersAndGroups"],
  assignment: ["servicePrincipals", "usersAndGroups", "appRoleAssignments", "groupMemberships"],
  membership: ["usersAndGroups", "groupMemberships"],
  ownership: ["applications", "servicePrincipals", "owners"],
  "active-role": ["roles", "usersAndGroups", "groupMemberships"],
  "eligible-role": ["roles", "usersAndGroups", "groupMemberships"],
  "control-path": ["applications", "servicePrincipals", "owners", "federatedIdentityCredentials", "appRoleAssignments"],
};

const TYPES: Record<QueryKind, RelationshipType[]> = {
  "application-permission": ["CAN_CALL_AS_APP"],
  "delegated-permission": ["CAN_CALL_DELEGATED"],
  assignment: ["ASSIGNED_TO", "MEMBER_OF"], membership: ["MEMBER_OF"], ownership: ["OWNS"],
  "active-role": ["ACTIVE_IN_ROLE", "MEMBER_OF"], "eligible-role": ["ELIGIBLE_FOR_ROLE", "MEMBER_OF"],
  "control-path": ["OWNS", "FEDERATES_AS", "INSTANTIATES_AS", "CAN_CALL_AS_APP"],
};

export function validateQuery(query: AuthorizationQuery): void {
  const allowed = ["tenantId", "kind", "principalId", "resourceId", "permissionId", "userId", "directoryScopeId"];
  if (!query || typeof query !== "object" || Object.entries(query).some(([key, value]) => !allowed.includes(key) || (value !== undefined && (typeof value !== "string" || value.length > 500)))) throw new Error("Unknown or invalid authorization query fields.");
  if (!Object.hasOwn(TYPES, query.kind) || !query.tenantId || !query.principalId || !query.resourceId) throw new Error("Invalid authorization query.");
  if ((query.kind === "application-permission" || query.kind === "delegated-permission") && !query.permissionId) throw new Error("A resource-specific permission ID is required.");
}

/** Predicate buckets include absent facts, so a newly added alternative invalidates prior negatives. */
export function relevantEdges(model: EvidenceModel, query: AuthorizationQuery): RelationshipEdge[] {
  const types = TYPES[query.kind];
  const matches = (e: RelationshipEdge) => types.includes(e.type) && (
    query.kind === "control-path" || query.kind === "membership" || (e.sourceId === query.principalId && (e.targetId === query.resourceId || e.type === "MEMBER_OF")) ||
    ((query.kind === "assignment" || query.kind === "active-role" || query.kind === "eligible-role") && e.targetId === query.resourceId)
  );
  const conflictingIds = new Set(model.conflicts.filter(c => c.factId.startsWith("relationship:") && c.variants.some(v => matches(JSON.parse(v) as RelationshipEdge))).map(c => c.factId));
  return model.edges.filter(e => matches(e) || conflictingIds.has(`relationship:${e.id}`));
}

export function queryFingerprint(model: EvidenceModel, query: AuthorizationQuery, budget: Budget): string {
  const edges = relevantEdges(model, query);
  const ids = new Set([query.principalId, query.resourceId, query.userId, ...edges.flatMap(e => [e.sourceId, e.targetId])]);
  return canonical({ tenant: model.tenantId, version: model.ruleVersion, engine: model.engineVersion, query, budget,
    collectedAt: model.collectedAt, edges, nodes: model.nodes.filter(n => ids.has(n.id)).map(n => ({ id: n.id, kind: n.kind, sourceEndpoint: n.sourceEndpoint })),
    coverage: model.coverage.filter(c => QUERY_COLLECTORS[query.kind].includes(c.id)), conflicts: model.conflicts });
}

function controlStep(source: NodeKind, target: NodeKind, type: RelationshipType): boolean {
  switch (type) {
    case "OWNS": return (source === "user" || source === "servicePrincipal" || source === "managedIdentity") && (target === "application" || target === "servicePrincipal");
    case "FEDERATES_AS": return source === "federatedCredential" && (target === "application" || target === "managedIdentity");
    case "INSTANTIATES_AS": return source === "application" && (target === "servicePrincipal" || target === "managedIdentity");
    case "CAN_CALL_AS_APP": return (source === "servicePrincipal" || source === "managedIdentity") && target === "servicePrincipal";
    default: return false;
  }
}

function validStep(nodes: Map<string, EvidenceModel["nodes"][number]>, query: AuthorizationQuery, path: RelationshipEdge[], edge: RelationshipEdge): boolean {
  const source = nodes.get(edge.sourceId);
  const target = nodes.get(edge.targetId);
  if (!source || !target || !edge.evidence.configured) return false;
  if (query.kind === "delegated-permission") return (source.kind === "servicePrincipal" || source.kind === "managedIdentity") && target.kind === "servicePrincipal";
  if (edge.type === "MEMBER_OF") return target.kind === "group" && (query.kind === "membership" || path.length === 0);
  if (query.kind === "assignment") return edge.type === "ASSIGNED_TO" && (source.kind === "user" || source.kind === "group") && target.kind === "servicePrincipal";
  if (query.kind === "active-role" || query.kind === "eligible-role") return ["user", "group", "servicePrincipal", "managedIdentity"].includes(source.kind) && target.kind === "directoryRole" && edge.type === (query.kind === "active-role" ? "ACTIVE_IN_ROLE" : "ELIGIBLE_FOR_ROLE");
  return controlStep(source.kind, target.kind, edge.type);
}

function isTerminal(query: AuthorizationQuery, edge: RelationshipEdge): boolean {
  if (edge.targetId !== query.resourceId) return false;
  if (query.kind === "control-path" && edge.type !== "CAN_CALL_AS_APP") return false;
  if (query.kind === "assignment" && edge.type !== "ASSIGNED_TO") return false;
  if ((query.kind === "active-role" || query.kind === "eligible-role") && edge.type === "MEMBER_OF") return false;
  if (query.permissionId && edge.permissionIds && !edge.permissionIds.includes(query.permissionId)) return false;
  if (query.directoryScopeId && edge.scope && edge.scope.directoryScopeId !== query.directoryScopeId) return false;
  if (query.kind === "delegated-permission" && query.userId && edge.consent?.audience === "single-user" && edge.consent.principalId && edge.consent.principalId !== query.userId) return false;
  return true;
}

function canContinue(query: AuthorizationQuery, edge: RelationshipEdge): boolean {
  if (query.kind === "membership") return true;
  if (["assignment", "active-role", "eligible-role"].includes(query.kind)) return edge.type === "MEMBER_OF";
  return query.kind === "control-path" && edge.type !== "CAN_CALL_AS_APP";
}

function pathsFor(nodes: Map<string, EvidenceModel["nodes"][number]>, query: AuthorizationQuery, edges: RelationshipEdge[], limits: Limits) {
  const outgoing = new Map<string, RelationshipEdge[]>();
  for (const edge of edges) {
    const bucket = outgoing.get(edge.sourceId);
    if (bucket) bucket.push(edge);
    else outgoing.set(edge.sourceId, [edge]);
  }
  const queue: Array<{ node: string; path: RelationshipEdge[]; visited: Set<string> }> = [{ node: query.principalId, path: [], visited: new Set([query.principalId]) }];
  const paths: RelationshipEdge[][] = [];
  // Failed type checks depend on the objects too: missing or conflicting
  // intermediate records cannot establish that a configured path is absent.
  const objectIds = new Set([query.principalId, query.resourceId, ...(query.userId ? [query.userId] : [])]);
  const result = { paths, objectIds };
  // Monotone worklist: extend only typed, simple derivations; no arbitrary reachability rule.
  for (let index = 0; index < queue.length; index++) {
    const state = queue[index]!;
    for (const edge of outgoing.get(state.node) ?? []) {
      if (limits.steps === limits.maxSteps) { limits.exhausted = true; return result; }
      limits.steps++;
      objectIds.add(edge.targetId);
      if (state.visited.has(edge.targetId) || !validStep(nodes, query, state.path, edge)) continue;
      const path = [...state.path, edge];
      if (isTerminal(query, edge)) {
        if (paths.length === limits.maxPaths) { limits.exhausted = true; return result; }
        paths.push(path);
      }
      if (canContinue(query, edge)) {
        if (path.length >= limits.maxDepth) {
          if ((outgoing.get(edge.targetId) ?? []).some(e => !state.visited.has(e.targetId))) limits.exhausted = true;
        } else queue.push({ node: edge.targetId, path, visited: new Set([...state.visited, edge.targetId]) });
      }
    }
  }
  return result;
}

function pathMissing(query: AuthorizationQuery, path: RelationshipEdge[]): string[] {
  const missing = path.filter(e => e.evidence.completeness !== "complete" || !e.evidence.sourceEndpoint || !e.evidence.sourceRecordIds.length).map(e => `relationship:${e.id}:complete-source`);
  const last = path.at(-1)!;
  if (query.permissionId && !last.permissionIds) missing.push(`relationship:${last.id}:permission-ids`);
  if (query.kind === "delegated-permission") {
    if (!query.userId) missing.push("query:user-context");
    if (!last.consent || last.consent.audience === "unknown" || (last.consent.audience === "single-user" && !last.consent.principalId)) missing.push(`relationship:${last.id}:consent-audience`);
  }
  if (query.kind === "active-role" || query.kind === "eligible-role") {
    if (!query.directoryScopeId) missing.push("query:directory-scope");
    if (!last.scope) missing.push(`relationship:${last.id}:directory-scope`);
  }
  return missing;
}

function proofFacts(model: EvidenceModel, nodes: Map<string, EvidenceModel["nodes"][number]>, paths: RelationshipEdge[][], collectors: string[], objectIds: string[]): ProofFact[] {
  const edges = new Map(paths.flat().map(e => [e.id, e]));
  const facts: ProofFact[] = [...edges.values()].map(e => ({ id: `relationship:${e.id}`, kind: "relationship", sourceEndpoint: e.evidence.sourceEndpoint,
    sourceRecordIds: [...e.evidence.sourceRecordIds], sourceObjectId: e.sourceId, targetObjectId: e.targetId, collectedAt: e.evidence.scannedAt, completeness: e.evidence.completeness, relationshipType: e.type }));
  for (const id of objectIds) {
    const node = nodes.get(id);
    if (node) facts.push({ id: `object:${id}`, kind: "object", sourceEndpoint: node.sourceEndpoint ?? "", sourceRecordIds: [id], sourceObjectId: id, targetObjectId: id, collectedAt: model.collectedAt[0]!, completeness: "recorded" });
  }
  for (const id of collectors) {
    const c = model.coverage.find(item => item.id === id);
    facts.push({ id: `coverage:${id}`, kind: "coverage", sourceEndpoint: c?.endpoints[0] ?? "", sourceEndpoints: [...(c?.endpoints ?? [])], sourceRecordIds: [], sourceObjectId: id, targetObjectId: id, collectedAt: c?.collectedAt ?? "", completeness: complete(model, id) ? "complete" : c?.state ?? "unknown" });
  }
  return facts.sort((a, b) => compare(a.id, b.id));
}

export function evaluateAuthorization(model: EvidenceModel, query: AuthorizationQuery, budget: Budget = DEFAULT_BUDGET): EvidenceProof {
  assertTenant(model, query.tenantId);
  validateQuery(query);
  const limits: Limits = { maxSteps: bound(budget.maxSteps, 1_000_000, "steps"), maxPaths: bound(budget.maxPaths, 10_000, "paths"), maxDepth: bound(budget.maxDepth, 32, "depth"), steps: 0, exhausted: false };
  const edges = relevantEdges(model, query);
  const nodes = new Map(model.nodes.map(n => [n.id, n]));
  const search = pathsFor(nodes, query, edges, limits);
  const paths = search.paths.sort((a, b) => compare(canonical(a.map(e => e.id)), canonical(b.map(e => e.id))));
  const collectors = QUERY_COLLECTORS[query.kind];
  const objectIds = unique([...search.objectIds]);
  const missingObjects = objectIds.filter(id => !nodes.has(id)).map(id => `object:${id}`);
  const missingCoverage = collectors.filter(c => !complete(model, c)).map(c => `coverage:${c}`);
  const missingPaths = paths.flatMap(p => pathMissing(query, p));
  const missing = unique([...missingObjects, ...missingCoverage, ...missingPaths, ...(limits.exhausted ? ["budget:search"] : [])]);
  const facts = proofFacts(model, nodes, paths, collectors, objectIds);
  const dependencies = unique([...facts.map(f => f.id), ...edges.map(e => `relationship:${e.id}`), ...collectors.map(c => `collection:${c}`)]);
  const dependencyIds = new Set(dependencies);
  const conflicts = model.conflicts.filter(c => dependencyIds.has(c.factId));
  const hasWitness = paths.some(p => pathMissing(query, p).length === 0);
  const verdict = conflicts.length ? "conflicting" : missingObjects.length || limits.exhausted ? "unknown" : hasWitness ? "supported" : paths.length || missingCoverage.length ? "unknown" : "refuted";
  const assumptions = ["This conclusion describes recorded configuration under the published rule subset, not effective access or observed use."];
  if (query.kind === "delegated-permission") assumptions.push("Delegated use additionally requires successful user authentication, user resource authorization, requested scope, and applicable policy satisfaction.");
  if (query.kind === "control-path") assumptions.push("Ownership is modeled as a potential configuration-control capability; credential creation, possession, token issuance, policy, and resource enforcement are not proven.");
  if (query.kind === "eligible-role") assumptions.push("Eligibility is not activation. Approval, activation conditions, and current role use are not established.");
  if (query.kind === "assignment") assumptions.push("Application assignment expands direct group members only. Nested group assignment is not supported by Entra.");
  return { ...context(model), query: { ...query }, verdict, evidenceClass: query.kind === "control-path" ? "inferred" : "configured",
    paths: paths.map(p => p.map(e => e.id)), facts,
    derivation: [...paths.flatMap((p, i) => p.map((e, j) => ({ id: `path:${i}:step:${j}`, rule: `${model.ruleVersion}/${e.type}`,
      inputs: [`relationship:${e.id}`, ...(j ? [`path:${i}:step:${j - 1}`] : [])], conclusion: `Recorded ${e.type}: ${e.sourceId} → ${e.targetId}.` }))),
      { id: "query", rule: `${model.ruleVersion}/${query.kind}`, inputs: [...paths.map((p, i) => `path:${i}:step:${p.length - 1}`), ...facts.filter(f => f.kind !== "relationship").map(f => f.id)], conclusion: verdict }],
    dependencies, missing, assumptions, conflicts, limits };
}

/** Query cache lives only in the caller. Reused derivations receive the new collection context. */
export function createEvaluator(initial: EvidenceModel) {
  let model = initial;
  const cache = new Map<string, { fingerprint: string; proof: EvidenceProof; query: AuthorizationQuery; budget: Budget }>();
  return {
    evaluate(query: AuthorizationQuery, budget: Budget = DEFAULT_BUDGET): { proof: EvidenceProof; reused: boolean } {
      assertTenant(model, query.tenantId); validateQuery(query);
      const key = canonical({ query, budget });
      const fingerprint = queryFingerprint(model, query, budget);
      const prior = cache.get(key);
      if (prior?.fingerprint === fingerprint) return { proof: immutable({ ...prior.proof, ...context(model) }), reused: true };
      const proof = immutable(evaluateAuthorization(model, query, budget));
      cache.set(key, { fingerprint, proof, query: { ...query }, budget: { ...budget } });
      return { proof, reused: false };
    },
    replace(next: EvidenceModel): { invalidated: number; retained: number } {
      assertTenant(model, next.tenantId);
      let invalidated = 0;
      for (const [key, value] of cache) if (value.fingerprint !== queryFingerprint(next, value.query, value.budget)) { cache.delete(key); invalidated++; }
      model = next;
      return { invalidated, retained: cache.size };
    },
  };
}
