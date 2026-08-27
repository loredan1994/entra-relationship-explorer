import { relationships } from "./queries";
import type { DirectoryNode, RelationshipView, TenantSnapshot } from "./types";

export type EvidenceClass = "configured" | "observed" | "inferred" | "missing";
export type FindingSeverity = "critical" | "high" | "medium" | "low";

export interface AttackStep {
  index: number;
  edgeId: string;
  source: { id: string; label: string };
  target: { id: string; label: string };
  relationship: string;
  permissions: string[];
  evidenceClass: EvidenceClass;
  sourceEndpoint: string;
  explanation: string;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: FindingSeverity;
  confidence: "high" | "medium" | "low";
  source: { id: string; label: string };
  target: { id: string; label: string };
  steps: AttackStep[];
  prerequisites: string[];
  attackMappings: Array<{ id: string; name: string }>;
  mitigations: string[];
  uncertainty: string[];
}

export interface IamFinding {
  id: string;
  title: string;
  category: "privilege-path" | "oauth-consent" | "application-credential" | "ownership" | "dormant-access" | "guest-exposure" | "managed-identity" | "conditional-access" | "cross-tenant" | "coverage";
  severity: FindingSeverity;
  evidenceClass: EvidenceClass;
  summary: string;
  whyItMatters: string;
  remediation: string[];
  affectedObjectIds: string[];
  edgeIds: string[];
  attackPathId: string | null;
  sourceEndpoints: string[];
  uncertainty: string[];
}

export interface TenantIntelligence {
  generatedAt: string;
  paths: AttackPath[];
  findings: IamFinding[];
  counts: Record<FindingSeverity, number>;
  evidence: Record<EvidenceClass, number>;
}

const DIRECTORY_ESCALATION = new Set([
  "approleassignment.readwrite.all", "rolemanagement.readwrite.directory", "application.readwrite.all",
  "directory.readwrite.all", "privilegedaccess.readwrite.azuread", "user.readwrite.all", "group.readwrite.all",
]);
const WRITE_PATTERN = /\.(readwrite|write|send|manage|fullcontrol)\b/i;

function severityFor(view: RelationshipView): FindingSeverity | null {
  const { edge, target } = view;
  if (edge.type === "ACTIVE_IN_ROLE") return /global administrator|privileged role administrator/i.test(target.label) ? "critical" : "high";
  if (edge.type === "ELIGIBLE_FOR_ROLE") return /global administrator|privileged role administrator/i.test(target.label) ? "high" : "medium";
  if (edge.type !== "CAN_CALL_AS_APP" && edge.type !== "CAN_CALL_DELEGATED") return null;
  if (edge.permissions.some((permission) => DIRECTORY_ESCALATION.has(permission.toLowerCase()))) return edge.type === "CAN_CALL_AS_APP" ? "critical" : "high";
  if (edge.permissions.some((permission) => WRITE_PATTERN.test(permission))) return edge.type === "CAN_CALL_AS_APP" ? "high" : "medium";
  if (edge.type === "CAN_CALL_AS_APP" && edge.permissions.some((permission) => permission.toLowerCase().endsWith(".all"))) return "medium";
  return null;
}

function stableId(prefix: string, parts: string[]): string {
  const value = parts.join(":");
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) { hash ^= value.charCodeAt(index); hash = Math.imul(hash, 16777619); }
  return `${prefix}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function step(view: RelationshipView, index: number): AttackStep {
  const { edge, source, target } = view;
  const explanation = edge.type === "CAN_CALL_AS_APP"
    ? `${source.label} is configured to call ${target.label} as the application.`
    : edge.type === "CAN_CALL_DELEGATED"
      ? `${source.label} is configured to call ${target.label} for a signed-in person.`
      : `${source.label} ${edge.plainLabel.toLocaleLowerCase()} ${target.label}.`;
  return { index, edgeId: edge.id, source: { id: source.id, label: source.label }, target: { id: target.id, label: target.label }, relationship: edge.type, permissions: edge.permissions, evidenceClass: "configured", sourceEndpoint: edge.evidence.sourceEndpoint, explanation };
}

function candidateOrigins(snapshot: TenantSnapshot): DirectoryNode[] {
  return snapshot.nodes.filter((node) => node.kind === "user" || node.kind === "group" || ((node.kind === "servicePrincipal" || node.kind === "managedIdentity") && (node.ownerIds.length === 0 || node.credential?.status === "expired")));
}

/** One hop of the walk: where it can go next, and whether arriving there is worth reporting. */
interface Traversal {
  nodeId: string;
  traversed: RelationshipView[];
  visited: Set<string>;
}

function discoverPaths(snapshot: TenantSnapshot, maxDepth = 5): AttackPath[] {
  const outgoing = outgoingRelationships(snapshot);
  const paths: AttackPath[] = [];

  for (const origin of candidateOrigins(snapshot)) {
    const queue: Traversal[] = [{ nodeId: origin.id, traversed: [], visited: new Set([origin.id]) }];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.traversed.length >= maxDepth) continue;
      for (const view of outgoing.get(current.nodeId) ?? []) {
        // A path never revisits an object, and observed activity is evidence of use rather
        // than a relationship an attacker could traverse.
        if (current.visited.has(view.target.id) || view.edge.type === "OBSERVED_CALL") continue;
        const traversed = [...current.traversed, view];
        const severity = severityFor(view);
        if (severity) paths.push(attackPath(snapshot, origin, view, traversed, severity));
        queue.push({ nodeId: view.target.id, traversed, visited: new Set([...current.visited, view.target.id]) });
      }
    }
  }
  return rankPaths(paths);
}

function outgoingRelationships(snapshot: TenantSnapshot): Map<string, RelationshipView[]> {
  const outgoing = new Map<string, RelationshipView[]>();
  for (const view of relationships(snapshot)) outgoing.set(view.source.id, [...(outgoing.get(view.source.id) ?? []), view]);
  return outgoing;
}

function attackPath(
  snapshot: TenantSnapshot,
  origin: DirectoryNode,
  view: RelationshipView,
  traversed: RelationshipView[],
  severity: FindingSeverity,
): AttackPath {
  const permissions = view.edge.permissions.join(", ") || "configured access";
  const uncertainty = ["This is an inferred possibility built from configured relationships; it is not evidence that exploitation occurred."];
  if (!view.edge.evidence.observed) uncertainty.push("No activity evidence was collected for the final permission.");
  if (snapshot.completion.status === "partial") uncertainty.push("The source snapshot is partial, so shorter or additional paths may be missing.");
  return {
  id: stableId("path", traversed.map(({ edge }) => edge.id)), title: `${origin.label} can reach ${view.target.label}`, severity,
  confidence: snapshot.completion.status === "complete" ? "medium" : "low", source: { id: origin.id, label: origin.label }, target: { id: view.target.id, label: view.target.label },
  steps: traversed.map(step),
  prerequisites: [`An attacker first controls ${origin.label} or a session/credential able to act as it.`, "Every configured relationship shown in the path remains effective at the time of attempted use."],
  attackMappings: [{ id: "T1098", name: "Account Manipulation" }, { id: "T1078.004", name: "Valid Accounts: Cloud Accounts" }],
  mitigations: [`Review and remove unnecessary ${permissions} access to ${view.target.label}.`, `Reduce control of ${origin.label} and ensure an accountable owner reviews the relationship.`, "Re-scan after remediation and verify that the configured path no longer exists."], uncertainty,
  };
}

/** Most severe first, then shortest, then by title so the order never drifts between runs. */
function rankPaths(paths: AttackPath[]): AttackPath[] {
  const order: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return Array.from(new Map(paths.map((path) => [path.id, path])).values()).sort((a, b) => order[a.severity] - order[b.severity] || a.steps.length - b.steps.length || a.title.localeCompare(b.title));
}

function findingsFor(snapshot: TenantSnapshot, paths: AttackPath[]): IamFinding[] {
  return [
    ...pathFindings(paths),
    ...relationshipFindings(snapshot),
    ...dormantAccessFindings(snapshot),
    ...ownershipFindings(snapshot),
    ...credentialFindings(snapshot),
    ...guestFindings(snapshot),
    ...managedIdentityFindings(snapshot),
    ...conditionalAccessFindings(snapshot),
    ...crossTenantFindings(snapshot),
    ...coverageFindings(snapshot),
  ];
}

/** Each walked path is also reported as a finding, so one list carries the whole review. */
function pathFindings(paths: AttackPath[]): IamFinding[] {
  return paths.map((path) => ({
    id: `finding-${path.id}`, title: path.title, category: "privilege-path", severity: path.severity, evidenceClass: "inferred",
    summary: `${path.steps.length}-stage path from ${path.source.label} to ${path.target.label}.`, whyItMatters: "Control of the starting identity could make each configured step available and end in powerful access.",
    remediation: path.mitigations, affectedObjectIds: Array.from(new Set(path.steps.flatMap((item) => [item.source.id, item.target.id]))), edgeIds: path.steps.map((item) => item.edgeId), attackPathId: path.id,
    sourceEndpoints: Array.from(new Set(path.steps.map((item) => item.sourceEndpoint))), uncertainty: path.uncertainty,
  }));
}

/** Findings a single configured relationship raises on its own, in the order they are met. */
function relationshipFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const view of relationships(snapshot)) {
    if (view.edge.type === "CAN_CALL_DELEGATED" && view.edge.permissions.length > 0) findings.push({
      id: stableId("finding-consent", [view.edge.id]), title: `Delegated consent lets ${view.source.label} act for a signed-in person`, category: "oauth-consent",
      severity: view.edge.permissions.some((permission) => WRITE_PATTERN.test(permission)) ? "high" : "medium", evidenceClass: "configured", summary: `Configured delegated access: ${view.edge.permissions.join(", ")}.`,
      whyItMatters: "If a user is tricked into authorizing or using a malicious application, delegated access can operate within that user's effective privileges.",
      remediation: ["Confirm the publisher, business owner, consent scope, and intended user population.", "Remove consent through approved Entra administration if it is unnecessary."],
      affectedObjectIds: [view.source.id, view.target.id], edgeIds: [view.edge.id], attackPathId: null, sourceEndpoints: [view.edge.evidence.sourceEndpoint], uncertainty: ["Configured consent does not prove consent phishing or permission use."],
    });
    if (view.edge.type === "CAN_CALL_AS_APP" && view.edge.permissions.length > 0) findings.push({
      id: stableId("finding-app-permission", [view.edge.id]), title: `${view.source.label} can act without a signed-in person`, category: "oauth-consent", severity: view.edge.permissions.some((permission) => DIRECTORY_ESCALATION.has(permission.toLowerCase())) ? "critical" : view.edge.permissions.some((permission) => WRITE_PATTERN.test(permission) || permission.toLowerCase().endsWith(".all")) ? "high" : "medium", evidenceClass: "configured", summary: `Configured application access: ${view.edge.permissions.join(", ")}.`, whyItMatters: "Application permissions operate as the workload identity itself. Theft of a usable credential or control of the hosting workload can make this access available without the affected user's session.", remediation: ["Confirm every application permission is required and approved by the accountable owner.", "Remove unused permissions and protect the credential or workload that can act as this identity."], affectedObjectIds: [view.source.id, view.target.id], edgeIds: [view.edge.id], attackPathId: null, sourceEndpoints: [view.edge.evidence.sourceEndpoint], uncertainty: ["Configured application access does not prove token theft, replay, or permission use."],
    });
    if (view.edge.type === "ELIGIBLE_FOR_ROLE") findings.push({ id: stableId("finding-pim", [view.edge.id]), title: `${view.source.label} is eligible for ${view.target.label}`, category: "privilege-path", severity: /global administrator|privileged role administrator/i.test(view.target.label) ? "high" : "medium", evidenceClass: "configured", summary: "A privileged role can become active through Microsoft Entra Privileged Identity Management (PIM), subject to its activation controls.", whyItMatters: "Eligibility is not active privilege, but compromise of the eligible identity can create an activation path if approval, authentication, duration, and justification controls are weak.", remediation: ["Review eligibility necessity, expiry, approval, phishing-resistant authentication, and activation duration.", "Remove standing eligibility that has no current business owner or use case."], affectedObjectIds: [view.source.id, view.target.id], edgeIds: [view.edge.id], attackPathId: null, sourceEndpoints: [view.edge.evidence.sourceEndpoint], uncertainty: ["Eligibility does not prove the role was activated or that activation controls can be bypassed."] });
  }
  return findings;
}

/**
 * Configured access with no matching sign-in in the collected window. Only reported when a
 * sign-in window was actually collected: absence of evidence is not evidence of absence.
 */
function dormantAccessFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  const hasActivityCoverage = snapshot.completion.collectedEndpoints.some((endpoint) => endpoint.startsWith("/auditLogs/signIns"));
  if (hasActivityCoverage) {
    const activeSources = new Set(snapshot.edges.filter((edge) => edge.type === "OBSERVED_CALL").map((edge) => edge.sourceId));
    for (const view of relationships(snapshot).filter((item) => (item.edge.type === "CAN_CALL_AS_APP" || item.edge.type === "CAN_CALL_DELEGATED") && !activeSources.has(item.source.id))) findings.push({ id: stableId("finding-dormant", [view.edge.id]), title: `Configured access from ${view.source.label} had no observed sign-in in the collection window`, category: "dormant-access", severity: "medium", evidenceClass: "inferred", summary: `The permission remains configured, while the collected 30-day sign-in window contained no matching workload activity for this source identity.`, whyItMatters: "Unused access can remain exploitable even when normal business activity has stopped.", remediation: ["Confirm the access is still required with the owner.", "Use an approved change process to remove unnecessary grants, then re-scan."], affectedObjectIds: [view.source.id, view.target.id], edgeIds: [view.edge.id], attackPathId: null, sourceEndpoints: [view.edge.evidence.sourceEndpoint, ...snapshot.completion.collectedEndpoints.filter((endpoint) => endpoint.startsWith("/auditLogs/signIns"))], uncertainty: ["Absence in a bounded sign-in dataset is not proof that the permission was never used."] });
  }
  return findings;
}

function ownershipFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const node of snapshot.nodes.filter((item) => (item.kind === "application" || ((item.kind === "servicePrincipal" || item.kind === "managedIdentity") && item.metadata?.ownershipExpected === true)) && item.ownerIds.length === 0)) findings.push({
    id: stableId("finding-owner", [node.id]), title: `${node.label} has no recorded owner`, category: "ownership", severity: "medium", evidenceClass: "configured",
    summary: "The latest snapshot contains no accountable owner for this application identity.", whyItMatters: "Orphaned application identities are harder to validate, retire, and respond to if a credential or permission is abused.",
    remediation: ["Assign a current business and technical owner in Microsoft Entra.", "Confirm that the application is still required before retaining its access."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null,
    sourceEndpoints: [node.kind === "application" ? `/applications/${node.id}/owners` : `/servicePrincipals/${node.id}/owners`], uncertainty: snapshot.completion.status === "partial" ? ["Owner collection may be incomplete in this partial snapshot."] : [],
  });
  return findings;
}

function credentialFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const node of snapshot.nodes.filter((item) => (item.kind === "application" || (item.kind === "servicePrincipal" && item.metadata?.ownershipExpected === true)) && (item.credential?.status === "expired" || item.credential?.status === "expiring"))) findings.push({ id: stableId("finding-credential", [node.id]), title: `${node.label} has an ${node.credential!.status} credential`, category: "application-credential", severity: node.credential!.status === "expired" ? "high" : "medium", evidenceClass: "configured", summary: `Credential metadata reports ${node.credential!.status} status with the next known expiry at ${node.credential!.expiresAt}.`, whyItMatters: "Poor credential lifecycle can cause outages and can leave old credential material outside the expected rotation process. If a usable credential is stolen, tokens may be requested and replayed within their validity and policy constraints.", remediation: ["Confirm the complete credential inventory and owning workload.", "Rotate or remove credentials through the approved Entra change process, favoring managed identity or certificate-based authentication where appropriate."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null, sourceEndpoints: [node.kind === "application" ? "/applications" : "/servicePrincipals"], uncertainty: ["The collector stores credential metadata only; it never reads secret values and does not prove compromise or token replay."] });
  return findings;
}

function guestFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const node of snapshot.nodes.filter((item) => item.kind === "user" && item.isExternal)) findings.push({ id: stableId("finding-guest", [node.id]), title: `${node.label} is an external identity`, category: "guest-exposure", severity: "medium", evidenceClass: "configured", summary: "The tenant contains a guest identity that can participate in group and assignment paths.", whyItMatters: "External identities extend trust beyond the tenant and should retain only current, sponsor-approved access.", remediation: ["Confirm the guest sponsor and business need.", "Review direct and inherited group, application, and role access, then remove stale access through approved Entra administration."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null, sourceEndpoints: ["/users"], uncertainty: ["Guest presence alone is not evidence of inappropriate access."] });
  return findings;
}

function managedIdentityFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const node of snapshot.nodes.filter((item) => item.kind === "managedIdentity")) findings.push({ id: stableId("finding-managed", [node.id]), title: `Managed identity exposure: ${node.label}`, category: "managed-identity", severity: node.risk.level === "high" ? "high" : "medium", evidenceClass: "configured", summary: "A workload identity can receive application permissions, group membership, ownership, or administrative roles without an interactive user.", whyItMatters: "Compromise of the hosting workload can make the managed identity's configured access available to an attacker.", remediation: ["Review every outgoing permission and role assignment.", "Restrict access to the hosting resource and remove unused identity relationships."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null, sourceEndpoints: ["/servicePrincipals"], uncertainty: ["The collector does not inspect the Azure resource hosting this identity."] });
  return findings;
}

function conditionalAccessFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  // Stryker disable next-line OptionalChaining: the policyType test already required metadata, so the state read never sees an absent one.
  for (const node of snapshot.nodes.filter((item) => item.kind === "policy" && item.metadata?.policyType === "conditionalAccess" && item.metadata?.state !== "enabled")) findings.push({ id: stableId("finding-ca", [node.id]), title: `Conditional Access policy is ${String(node.metadata?.state ?? "not enabled")}: ${node.label}`, category: "conditional-access", severity: "medium", evidenceClass: "configured", summary: "The policy exists but is not currently enabled.", whyItMatters: "A report-only or disabled policy does not enforce its configured grant controls.", remediation: ["Validate impact in report-only mode and enable the policy through the approved Conditional Access change process."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null, sourceEndpoints: ["/identity/conditionalAccess/policies"], uncertainty: ["Policy effectiveness depends on conditions, exclusions, authentication strengths, and other policies."] });
  return findings;
}

function crossTenantFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  for (const node of snapshot.nodes.filter((item) => item.kind === "externalTenant")) findings.push({ id: stableId("finding-cross-tenant", [node.id]), title: `Review cross-tenant trust for ${node.label}`, category: "cross-tenant", severity: node.metadata?.trustsMfa || node.metadata?.trustsCompliantDevice || node.metadata?.trustsHybridJoinedDevice ? "high" : "medium", evidenceClass: "configured", summary: "Partner-specific cross-tenant access settings extend identity trust beyond this tenant.", whyItMatters: "Inbound trust can accept authentication or device claims issued by a partner tenant, changing which controls are evaluated locally.", remediation: ["Confirm the partner owner and collaboration requirement.", "Review inbound and outbound B2B settings, scoped users, groups, and applications, plus each accepted trust claim."], affectedObjectIds: [node.id], edgeIds: [], attackPathId: null, sourceEndpoints: ["/policies/crossTenantAccessPolicy/partners"], uncertainty: ["This inventory does not assert that a partner identity actually signed in or accessed a resource."] });
  return findings;
}

/** What the scan could not read, so a reader never mistakes a gap in evidence for assurance. */
function coverageFindings(snapshot: TenantSnapshot): IamFinding[] {
  const findings: IamFinding[] = [];
  if (snapshot.completion.skippedEndpoints.length > 0 || snapshot.completion.errors.length > 0) findings.push({
    id: stableId("finding-coverage", [snapshot.id]), title: "Important evidence is not available", category: "coverage", severity: snapshot.completion.status === "partial" ? "high" : "low", evidenceClass: "missing",
    summary: `${snapshot.completion.skippedEndpoints.length} endpoint patterns were skipped and ${snapshot.completion.errors.length} collection errors were recorded.`, whyItMatters: "Missing evidence can hide paths or make configured access appear dormant when activity was simply not collected.",
    remediation: ["Review scan coverage and errors before treating absence as assurance.", "Grant optional read-only permissions only when the associated evidence is required."], affectedObjectIds: [], edgeIds: [], attackPathId: null,
    sourceEndpoints: snapshot.completion.skippedEndpoints, uncertainty: ["Audit activity, PIM, Conditional Access, and cross-tenant coverage are not part of the current core scan."],
  });
  return findings;
}

export function analyzeTenantIntelligence(snapshot: TenantSnapshot): TenantIntelligence {
  const paths = discoverPaths(snapshot);
  const findings = findingsFor(snapshot, paths);
  const counts: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const evidence: Record<EvidenceClass, number> = { configured: 0, observed: 0, inferred: 0, missing: 0 };
  for (const finding of findings) { counts[finding.severity] += 1; evidence[finding.evidenceClass] += 1; }
  return { generatedAt: snapshot.scannedAt, paths, findings, counts, evidence };
}
