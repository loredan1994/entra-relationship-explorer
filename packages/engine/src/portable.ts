import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "@entra-explorer/domain";
import { evaluateAuthorization, QUERY_COLLECTORS, relevantEdges, validateQuery } from "./authorization";
import { canonical, unique } from "./canonical";
import { compileSnapshot, projectEdge } from "./model";
import { parseUniqueJson } from "./json";
import { DEFAULT_BUDGET, ENGINE_VERSION, RULE_VERSION, type AuthorizationQuery, type Budget, type EvidenceModel, type EvidenceProof } from "./types";

export interface InvestigationPackage {
  format: "entra-investigation/1";
  sharing: "identified" | "pseudonymized";
  snapshot: TenantSnapshot;
  query: AuthorizationQuery;
  budget: Budget;
  proof: EvidenceProof;
  manifest: { algorithm: "SHA-256"; digest: string; engineVersion: string; ruleVersion: string; dependencies: string[] };
}
const MAX_BYTES = 5_000_000;

async function digest(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonical(value));
  const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, "0")).join("");
}

function minimalNode(node: DirectoryNode): DirectoryNode {
  return { id: node.id, tenantId: node.tenantId, kind: node.kind, label: node.id, description: "", ownerIds: [],
    risk: { level: "low", reason: "No score exported." }, ...(node.sourceEndpoint ? { sourceEndpoint: node.sourceEndpoint } : {}) };
}

/** Retain the query's dependency region, not disconnected tenant topology. */
function projectionEdges(model: EvidenceModel, query: AuthorizationQuery): RelationshipEdge[] {
  const candidates = relevantEdges(model, query);
  if (query.kind !== "control-path" && query.kind !== "membership") return candidates;
  const outgoing = new Map<string, RelationshipEdge[]>();
  const variants = model.conflicts.filter(c => c.factId.startsWith("relationship:") && candidates.some(e => c.factId === `relationship:${e.id}`)).flatMap(c => c.variants.map(v => JSON.parse(v) as RelationshipEdge));
  for (const edge of [...candidates, ...variants]) {
    const edges = outgoing.get(edge.sourceId);
    if (edges) edges.push(edge);
    else outgoing.set(edge.sourceId, [edge]);
  }
  const queue = [query.principalId], reached = new Set(queue), included = new Set<string>();
  for (let index = 0; index < queue.length; index++) for (const edge of outgoing.get(queue[index]!) ?? []) {
    // Application grants are terminal; another resource cannot be a control hop.
    if (edge.type === "CAN_CALL_AS_APP" && edge.targetId !== query.resourceId) continue;
    included.add(edge.id);
    if (edge.type !== "CAN_CALL_AS_APP" && !reached.has(edge.targetId)) { reached.add(edge.targetId); queue.push(edge.targetId); }
  }
  return candidates.filter(e => included.has(e.id));
}

function project(model: EvidenceModel, query: AuthorizationQuery): TenantSnapshot {
  const edges = projectionEdges(model, query).map(projectEdge);
  const ids = new Set([query.principalId, query.resourceId, query.userId, ...edges.flatMap(e => [e.sourceId, e.targetId])]);
  const nodes = model.nodes.filter(n => ids.has(n.id)).map(minimalNode);
  // Reintroduce conflicting source variants so replay independently derives the conflict.
  for (const conflict of model.conflicts) {
    const variants: unknown[] = conflict.variants.map(v => JSON.parse(v));
    if (conflict.factId.startsWith("object:") && ids.has(conflict.factId.slice(7))) nodes.push(...variants.map(v => minimalNode(v as DirectoryNode)));
    if (conflict.factId.startsWith("relationship:") && edges.some(e => `relationship:${e.id}` === conflict.factId)) edges.push(...variants.map(v => projectEdge(v as RelationshipEdge)));
  }
  const relatedEndpoint = (endpoint: string): boolean => {
    const path = endpoint.split("?")[0]!.split("/").filter(Boolean);
    if (["applications", "servicePrincipals", "users", "groups"].includes(path[0] ?? "") && path.length > 1) return ids.has(path[1]!);
    return true;
  };
  const collectors = model.coverage.filter(c => QUERY_COLLECTORS[query.kind].includes(c.id)).map(c => ({ ...c, endpoints: c.endpoints.filter(relatedEndpoint) }));
  for (const conflict of model.conflicts.filter(c => c.factId.startsWith("coverage:") && QUERY_COLLECTORS[query.kind].includes(c.factId.slice(9)))) collectors.push(...conflict.variants.map(v => {
    const c = JSON.parse(v) as EvidenceModel["coverage"][number]; return { ...c, endpoints: c.endpoints.filter(relatedEndpoint) };
  }));
  return { id: model.snapshotIds[0]!, tenant: { tenantId: model.tenantId, tenantLabel: "Investigation projection" }, scannedAt: model.collectedAt[0]!, mode: "tenant",
    completion: { status: "partial", collectedEndpoints: [], skippedEndpoints: [], errors: [], collectors }, nodes, edges };
}

function decodedEndpoint(value: string): string {
  try { return decodeURIComponent(value); } catch {
    // Invalid escapes must not hide otherwise valid ASCII identifiers in the
    // same expression. Preserve undecodable bytes and literal percent signs.
    return value.replace(/%([0-7][0-9a-f])/gi, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
  }
}

function pseudonymize(snapshot: TenantSnapshot, query: AuthorizationQuery): { snapshot: TenantSnapshot; query: AuthorizationQuery; privateMapping: Record<string, string> } {
  const endpoints = [query.directoryScopeId ?? "", ...snapshot.nodes.flatMap(n => n.sourceEndpoint ? [n.sourceEndpoint] : []),
    ...snapshot.edges.flatMap(e => [e.evidence.sourceEndpoint, ...(e.scope ? [e.scope.directoryScopeId] : [])]),
    ...(snapshot.completion.collectors ?? []).flatMap(c => [...c.endpoints, ...c.failedEndpoints])];
  const identifiers = unique([snapshot.id, snapshot.tenant.tenantId, query.principalId, query.resourceId, ...(query.userId ? [query.userId] : []), ...(query.permissionId ? [query.permissionId] : []),
    ...snapshot.nodes.map(n => n.id), ...snapshot.edges.flatMap(e => [e.id, e.sourceId, e.targetId, e.evidence.sourceObjectId, e.evidence.targetObjectId, ...e.evidence.sourceRecordIds, ...(e.permissionIds ?? []), ...(e.consent?.principalId ? [e.consent.principalId] : []), ...(e.scope?.objectId ? [e.scope.objectId] : [])]),
    ...endpoints.flatMap(value => decodedEndpoint(value).match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) ?? [])]);
  const mapping = Object.fromEntries(identifiers.map((id, i) => [id, `p${String(i + 1).padStart(6, "0")}`]));
  const id = (v: string) => Object.hasOwn(mapping, v) ? mapping[v]! : v;
  const endpoint = (v: string) => v.split(/([/?&=;,])/).map(part => {
    const decoded = decodedEndpoint(part);
    // Match complete identifiers inside OData expressions, including escaped
    // values. Do not replace a GUID embedded in an unrelated larger token.
    const translated = id(decoded) !== decoded ? id(decoded) : decoded.split(/([^\p{L}\p{N}_-]+)/u).map(id).join("");
    return decoded === part ? translated : translated === decoded ? part : encodeURIComponent(translated);
  }).join("");
  const copy = structuredClone(snapshot);
  copy.id = id(copy.id); copy.tenant.tenantId = id(copy.tenant.tenantId);
  copy.nodes = copy.nodes.map(n => ({ ...n, id: id(n.id), label: id(n.id), tenantId: id(n.tenantId), ...(n.sourceEndpoint ? { sourceEndpoint: endpoint(n.sourceEndpoint) } : {}) }));
  copy.edges = copy.edges.map(e => ({ ...e, id: id(e.id), tenantId: id(e.tenantId), sourceId: id(e.sourceId), targetId: id(e.targetId),
    permissions: [], ...(e.permissionIds ? { permissionIds: e.permissionIds.map(id) } : {}),
    ...(e.consent ? { consent: { ...e.consent, principalId: e.consent.principalId ? id(e.consent.principalId) : null } } : {}),
    ...(e.scope ? { scope: { directoryScopeId: endpoint(e.scope.directoryScopeId), objectId: e.scope.objectId ? id(e.scope.objectId) : null } } : {}),
    evidence: { ...e.evidence, sourceObjectId: id(e.evidence.sourceObjectId), targetObjectId: id(e.evidence.targetObjectId), sourceRecordIds: e.evidence.sourceRecordIds.map(id), sourceEndpoint: endpoint(e.evidence.sourceEndpoint) } }));
  copy.completion.collectors = copy.completion.collectors?.map(c => ({ ...c, endpoints: c.endpoints.map(endpoint), failedEndpoints: c.failedEndpoints.map(endpoint) }));
  return { snapshot: copy, query: { ...query, tenantId: id(query.tenantId), principalId: id(query.principalId), resourceId: id(query.resourceId),
    ...(query.userId ? { userId: id(query.userId) } : {}), ...(query.permissionId ? { permissionId: id(query.permissionId) } : {}),
    ...(query.directoryScopeId ? { directoryScopeId: endpoint(query.directoryScopeId) } : {}) }, privateMapping: mapping };
}

export async function exportInvestigation(model: EvidenceModel, query: AuthorizationQuery, sharing: InvestigationPackage["sharing"] = "identified", budget = DEFAULT_BUDGET): Promise<{ package: InvestigationPackage; privateMapping: Record<string, string> }> {
  const originalProof = evaluateAuthorization(model, query, budget);
  if (originalProof.limits.exhausted) throw new Error("Narrow the query before export: its search budget was exhausted.");
  const projected = project(model, query);
  const result = sharing === "pseudonymized" ? pseudonymize(projected, query) : { snapshot: projected, query: { ...query }, privateMapping: {} };
  const proof = evaluateAuthorization(compileSnapshot(result.snapshot), result.query, budget);
  if (proof.verdict !== originalProof.verdict) throw new Error("The minimized projection cannot preserve this conclusion. Inspect its conflicting or incomplete sources first.");
  const body = { format: "entra-investigation/1" as const, sharing, snapshot: result.snapshot, query: result.query, budget: { ...budget }, proof };
  const packet: InvestigationPackage = { ...body, manifest: { algorithm: "SHA-256", digest: await digest(body), engineVersion: ENGINE_VERSION, ruleVersion: RULE_VERSION, dependencies: proof.dependencies } };
  if (new TextEncoder().encode(canonical(packet)).length > MAX_BYTES) throw new Error("Investigation exceeds the 5 MB export limit. Narrow the query.");
  inspectJson(packet);
  return { package: packet, privateMapping: result.privateMapping };
}

function secretLike(value: string): boolean {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) return true;
  // Tokenize once. Repeated header-like prefixes without a following dot must
  // not restart a greedy JWT match over the rest of an untrusted scalar.
  for (const run of value.split(/[^A-Za-z0-9_.-]+/)) {
    const segments = run.split(".");
    for (let index = 0; index + 2 < segments.length; index++) {
      if (!segments[index + 1] || !segments[index + 2]) continue;
      const header = segments[index]!;
      const start = header.search(/(?:^|-)eyJ/);
      if (start >= 0 && header.length - start - (header[start] === "-" ? 1 : 0) >= 13) return true;
    }
  }
  return false;
}

function inspectJson(value: unknown, depth = 0, count = { value: 0 }): void {
  if (depth > 24 || ++count.value > 150_000) throw new Error("Investigation exceeds structural limits.");
  if (typeof value === "string" && (value.length > 50_000 || secretLike(value))) throw new Error("Secret-like or oversized content rejected.");
  if (Array.isArray(value)) { for (const item of value) inspectJson(item, depth + 1, count); return; }
  if (value && typeof value === "object") for (const [key, item] of Object.entries(value)) {
    if (["__proto__", "constructor", "prototype", "accessToken", "refreshToken", "clientSecret", "secretText", "privateKey", "files", "path", "filename"].includes(key)) throw new Error("Forbidden investigation field.");
    inspectJson(item, depth + 1, count);
  }
}

function exactFields(value: object, fields: string[]) {
  if (Object.keys(value).some(k => !fields.includes(k)) || fields.some(k => !Object.hasOwn(value, k))) throw new Error("Unknown or missing investigation fields.");
}

export async function verifyInvestigation(text: string): Promise<{ verified: true; proof: EvidenceProof; sharing: InvestigationPackage["sharing"]; notice: string }> {
  if (new TextEncoder().encode(text).length > MAX_BYTES) throw new Error("Investigation exceeds 5 MB.");
  const value = parseUniqueJson(text, "Investigation", 24);
  inspectJson(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid investigation document.");
  exactFields(value, ["format", "sharing", "snapshot", "query", "budget", "proof", "manifest"]);
  const packet = value as InvestigationPackage;
  if (packet.format !== "entra-investigation/1" || !["identified", "pseudonymized"].includes(packet.sharing)) throw new Error("Unsupported investigation format.");
  exactFields(packet.manifest, ["algorithm", "digest", "engineVersion", "ruleVersion", "dependencies"]);
  exactFields(packet.budget, ["maxSteps", "maxPaths", "maxDepth"]);
  if (packet.manifest.algorithm !== "SHA-256" || packet.manifest.engineVersion !== ENGINE_VERSION || packet.manifest.ruleVersion !== RULE_VERSION) throw new Error("Unsupported engine or integrity version.");
  validateQuery(packet.query);
  const { manifest, ...body } = packet;
  if (await digest(body) !== manifest.digest) throw new Error("Investigation integrity check failed.");
  // Round-trip the allowlisted projection: extra fields, arbitrary metadata, secrets, or executable inputs fail closed.
  const model = compileSnapshot(packet.snapshot);
  if (canonical(project(model, packet.query)) !== canonical(packet.snapshot)) throw new Error("Investigation contains nonminimal or unsupported facts.");
  const proof = evaluateAuthorization(model, packet.query, packet.budget);
  if (canonical(proof.dependencies) !== canonical(manifest.dependencies) || canonical(proof) !== canonical(packet.proof)) throw new Error("Proof replay or dependency check failed.");
  return { verified: true, proof, sharing: packet.sharing, notice: "Integrity and model replay verified. Hashes do not authenticate Microsoft as the source. Pseudonymization does not anonymize topology." };
}
