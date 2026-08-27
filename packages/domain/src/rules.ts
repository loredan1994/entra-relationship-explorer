import type { AttackPath, FindingSeverity, IamFinding } from "./intelligence";
import type { DirectoryNode, TenantSnapshot } from "./types";

export type EntraRuleId = "ERE-IAM-001" | "ERE-IAM-002" | "ERE-IAM-003" | "ERE-IAM-004";

export interface EntraRuleReference {
  id: EntraRuleId;
  version: number;
  title: string;
  requiredCoverage: string[];
  references: string[];
}

export interface EntraRuleContext {
  current: TenantSnapshot;
  previous: TenantSnapshot | null;
  paths: AttackPath[];
  previousPaths: AttackPath[];
}

export interface EntraRule {
  reference: EntraRuleReference;
  scope: "snapshot" | "history";
  evaluate(context: EntraRuleContext): IamFinding[];
}

const severityOrder: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const rule001 = defineRule({
  id: "ERE-IAM-001",
  version: 1,
  title: "Privileged application control path",
  requiredCoverage: ["application ownership or workload federation", "application identity instantiation", "application permission or Entra role assignment"],
  references: [
    "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview",
    "https://attack.mitre.org/techniques/T1098/",
  ],
}, "snapshot", ({ current, paths }) => paths.flatMap((path) => {
  if (!isPowerful(path) || !hasPrivilegedTerminal(path)) return [];
  const controlled = controlledIdentity(current, path);
  if (!controlled) return [];
  return [ruleFinding(rule001.reference, {
    id: stableId(rule001.reference.id, [path.id]),
    title: `${path.source.label} can control privileged access through ${controlled.label}`,
    category: path.source.id.startsWith("federated-credential:") ? "federated-identity" : "privilege-path",
    severity: path.severity,
    summary: `${path.steps.length}-stage configured control path reaches ${path.target.label}.`,
    whyItMatters: "Control of the starting principal could make the application identity's powerful configured access available without granting a new permission first.",
    remediation: path.mitigations,
    affectedObjectIds: unique(path.steps.flatMap((item) => [item.source.id, item.target.id])),
    edgeIds: path.steps.map((item) => item.edgeId),
    attackPathId: path.id,
    sourceEndpoints: unique(path.steps.map((item) => item.sourceEndpoint)),
    uncertainty: path.uncertainty,
    prerequisites: path.prerequisites,
  })];
}));

const rule002 = defineRule({
  id: "ERE-IAM-002",
  version: 1,
  title: "Privilege path amplification",
  requiredCoverage: ["the same relationship path in consecutive snapshots", "unchanged tenant boundary", "complete evidence for every compared path step"],
  references: ["https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices"],
}, "history", ({ current, previous, paths, previousPaths }) => {
  if (!previous) return [];
  const previousById = new Map(previousPaths.map((path) => [path.id, path]));
  return paths.flatMap((path) => {
    const before = previousById.get(path.id);
    if (!before) return [];
    const changes = amplificationChanges(before, path);
    if (changes.length === 0) return [];
    return [ruleFinding(rule002.reference, {
      id: stableId(rule002.reference.id, [path.id, ...changes]),
      title: `Privilege increased along ${path.source.label} → ${path.target.label}`,
      category: path.source.id.startsWith("federated-credential:") ? "federated-identity" : "privilege-path",
      severity: path.severity,
      summary: `${changes.join("; ")}. This is a change between ${previous.id} and ${current.id}.`,
      whyItMatters: "An existing configured route now ends in broader or more severe access than it did in the immediately preceding retained snapshot.",
      remediation: ["Confirm that the privilege increase was approved and remains necessary.", "Inspect every changed relationship, then remove unintended access through the approved Entra change process."],
      affectedObjectIds: unique(path.steps.flatMap((item) => [item.source.id, item.target.id])),
      edgeIds: path.steps.map((item) => item.edgeId),
      attackPathId: path.id,
      sourceEndpoints: unique(path.steps.map((item) => item.sourceEndpoint)),
      uncertainty: ["This comparison proves a configured change, not that the added privilege was exercised.", ...(current.completion.status === "partial" ? ["The latest snapshot is partial, so other path changes may be missing."] : [])],
      prerequisites: path.prerequisites,
    })];
  });
});

const rule003 = defineRule({
  id: "ERE-IAM-003",
  version: 1,
  title: "Privileged federated trust rewired",
  requiredCoverage: ["federated identity credentials in consecutive snapshots", "the parent workload's effective privileged path"],
  references: [
    "https://learn.microsoft.com/en-us/graph/api/application-list-federatedidentitycredentials?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation",
  ],
}, "history", ({ current, previous, paths }) => {
  if (!previous) return [];
  const previousNodes = new Map(previous.nodes.map((node) => [node.id, node]));
  return current.nodes.filter((node) => node.kind === "federatedCredential").flatMap((node) => {
    const before = previousNodes.get(node.id);
    if (!before || before.kind !== "federatedCredential") return [];
    const path = paths.find((candidate) => candidate.source.id === node.id && isPowerful(candidate));
    if (!path) return [];
    const changed = changedFederationFields(before, node);
    if (changed.length === 0) return [];
    const beforeState = changed.map((field) => `${field}=${metadataValue(before, field)}`).join("|");
    const currentState = changed.map((field) => `${field}=${metadataValue(node, field)}`).join("|");
    return [ruleFinding(rule003.reference, {
      id: stableId(rule003.reference.id, [node.id, beforeState, currentState]),
      title: `Privileged federated trust changed: ${node.label}`,
      category: "federated-identity",
      severity: path.severity,
      summary: `${changed.join(", ")} changed while this credential can reach ${path.target.label}.`,
      whyItMatters: "Changing a privileged workload trust can transfer which external token identity is able to authenticate as the application or managed identity.",
      remediation: ["Confirm the issuer, subject, audience, parent workload, and approving owner against the deployment system that should hold this trust.", "Remove an unintended federated credential through the approved Entra change process and re-scan."],
      affectedObjectIds: unique([node.id, ...path.steps.flatMap((item) => [item.source.id, item.target.id])]),
      edgeIds: path.steps.map((item) => item.edgeId),
      attackPathId: path.id,
      sourceEndpoints: unique(path.steps.map((item) => item.sourceEndpoint)),
      uncertainty: ["The configuration changed, but this does not prove that a matching external token was issued or used.", ...(current.completion.status === "partial" ? ["The latest snapshot is partial, so related trust evidence may be missing."] : [])],
      prerequisites: path.prerequisites,
    })];
  });
});

const rule004 = defineRule({
  id: "ERE-IAM-004",
  version: 1,
  title: "Privileged workload lacks accountable control",
  requiredCoverage: ["application or service-principal owners", "the workload's effective application permissions and Entra roles"],
  references: ["https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems"],
}, "snapshot", ({ current, paths }) => {
  const nodes = new Map(current.nodes.map((node) => [node.id, node]));
  const instantiations = current.edges.filter((edge) => edge.type === "INSTANTIATES_AS");
  const matches = new Map<string, { accountable: DirectoryNode; path: AttackPath; instantiationEndpoint: string | null; instantiationEdgeId: string | null }>();
  for (const path of paths.filter(isPowerful)) {
    const source = nodes.get(path.source.id)!;
    const accountable = accountableWorkload(source, nodes, instantiations);
    if (!accountable || accountable.ownerIds.length > 0 || matches.has(accountable.id)) continue;
    const instantiation = instantiations.find((edge) => edge.sourceId === accountable.id && edge.targetId === source.id);
    matches.set(accountable.id, { accountable, path, instantiationEndpoint: instantiation?.evidence.sourceEndpoint ?? null, instantiationEdgeId: instantiation?.id ?? null });
  }
  return [...matches.values()].map(({ accountable, path, instantiationEndpoint, instantiationEdgeId }) => ruleFinding(rule004.reference, {
    id: stableId(rule004.reference.id, [accountable.id]),
    title: `${accountable.label} has powerful access without a recorded owner`,
    category: "ownership",
    severity: path.severity,
    summary: `No accountable owner was collected for this workload, and its configured path reaches ${path.target.label}.`,
    whyItMatters: "A powerful workload without an accountable owner is harder to validate, retire, and contain when its credential, federation, or hosting environment is compromised.",
    remediation: ["Assign current business and technical owners and confirm the workload is still required.", "Review and remove unnecessary permissions, roles, credentials, and federation through the approved Entra change process."],
    affectedObjectIds: unique([accountable.id, ...path.steps.flatMap((item) => [item.source.id, item.target.id])]),
    edgeIds: unique([...(instantiationEdgeId ? [instantiationEdgeId] : []), ...path.steps.map((item) => item.edgeId)]),
    attackPathId: path.id,
    sourceEndpoints: unique([ownersEndpoint(accountable), ...(instantiationEndpoint ? [instantiationEndpoint] : []), ...path.steps.map((item) => item.sourceEndpoint)]),
    uncertainty: ["No recorded owner is an accountability gap, not proof that the workload is abandoned or compromised.", ...(current.completion.status === "partial" ? ["Owner or privilege evidence may be incomplete in this partial snapshot."] : [])],
    prerequisites: path.prerequisites,
  }));
});

export const ENTRA_CONTROL_PATH_RULES: readonly EntraRule[] = Object.freeze([rule001, rule002, rule003, rule004]);

export function evaluateEntraRules(context: EntraRuleContext, scope: EntraRule["scope"]): IamFinding[] {
  return ENTRA_CONTROL_PATH_RULES.filter((rule) => rule.scope === scope).flatMap((rule) => rule.evaluate(context));
}

function defineRule(reference: EntraRuleReference, scope: EntraRule["scope"], evaluate: EntraRule["evaluate"]): EntraRule {
  return { reference: Object.freeze({ ...reference, requiredCoverage: [...reference.requiredCoverage], references: [...reference.references] }), scope, evaluate };
}

function ruleFinding(reference: EntraRuleReference, finding: Omit<IamFinding, "evidenceClass" | "rule" | "requiredCoverage"> & { prerequisites: string[] }): IamFinding {
  return { ...finding, evidenceClass: "inferred", rule: reference, requiredCoverage: [...reference.requiredCoverage] };
}

function isPowerful(path: AttackPath): boolean {
  return path.severity === "critical" || path.severity === "high";
}

function hasPrivilegedTerminal(path: AttackPath): boolean {
  const terminal = path.steps.at(-1)!.relationship;
  return terminal === "CAN_CALL_AS_APP" || terminal === "ACTIVE_IN_ROLE" || terminal === "ELIGIBLE_FOR_ROLE";
}

function controlledIdentity(snapshot: TenantSnapshot, path: AttackPath): DirectoryNode | undefined {
  const nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const control = path.steps.find((item) => (item.relationship === "OWNS" || item.relationship === "FEDERATES_AS") && isWorkload(nodes.get(item.target.id)!));
  return control ? nodes.get(control.target.id) : undefined;
}

function isWorkload(node: DirectoryNode): boolean {
  return node.kind === "application" || node.kind === "servicePrincipal" || node.kind === "managedIdentity";
}

function accountableWorkload(source: DirectoryNode, nodes: Map<string, DirectoryNode>, instantiations: TenantSnapshot["edges"]): DirectoryNode | null {
  if (source.kind === "managedIdentity") return source.metadata?.ownershipExpected === true ? source : null;
  if (source.kind === "servicePrincipal") {
    const registration = instantiations.find((edge) => edge.targetId === source.id);
    if (registration) {
      const application = nodes.get(registration.sourceId);
      if (application?.kind === "application") return application;
    }
    return source.metadata?.ownershipExpected === true ? source : null;
  }
  return null;
}

function ownersEndpoint(node: DirectoryNode): string {
  return node.kind === "application" ? `/applications/${node.id}/owners` : `/servicePrincipals/${node.id}/owners`;
}

function amplificationChanges(before: AttackPath, after: AttackPath): string[] {
  const changes: string[] = [];
  if (severityOrder[after.severity] < severityOrder[before.severity]) changes.push(`severity increased from ${before.severity} to ${after.severity}`);
  const beforeFinal = before.steps.at(-1)!;
  const afterFinal = after.steps.at(-1)!;
  const added = afterFinal.permissions.filter((permission) => !beforeFinal.permissions.includes(permission)).sort();
  if (added.length > 0) changes.push(`terminal permissions added: ${added.join(", ")}`);
  const beforeScopes = new Map(before.steps.map((item) => [item.edgeId, item.scope?.directoryScopeId]));
  if (after.steps.some((item) => item.scope?.directoryScopeId === "/" && beforeScopes.get(item.edgeId) && beforeScopes.get(item.edgeId) !== "/")) changes.push("directory scope expanded to the tenant root");
  return changes;
}

const federationFields = ["issuer", "subject", "audiences", "parentId"] as const;

function changedFederationFields(before: DirectoryNode, after: DirectoryNode): Array<typeof federationFields[number]> {
  return federationFields.filter((field) => metadataValue(before, field) !== metadataValue(after, field));
}

function metadataValue(node: DirectoryNode, field: typeof federationFields[number]): string {
  return String(node.metadata?.[field] ?? "");
}

function stableId(ruleId: EntraRuleId, parts: string[]): string {
  const value = `${ruleId}:${parts.join(":")}`;
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) { hash ^= value.charCodeAt(index); hash = Math.imul(hash, 16777619); }
  // Stryker disable next-line StringLiteral: the padding character is observable only for a short hash; all durable rule fixtures currently exercise eight-digit hashes.
  return `finding-${ruleId.toLocaleLowerCase()}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}
