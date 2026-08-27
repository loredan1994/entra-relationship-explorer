import { analyzeFindingLifecycle, type FindingLifecycleRecord } from "./finding-lifecycle";
import { analyzeTenantIntelligenceHistory, type AttackPath, type IamFinding } from "./intelligence";
import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "./types";

export const EVIDENCE_PACKET_SCHEMA = "ere-evidence-packet/1.0" as const;

export interface EvidencePacketReviewContext {
  disposition: "open" | "mitigating" | "accepted" | "resolved";
  owner: string;
  expiresAt: string | null;
  assumption: string;
  updatedAt: string;
  sourceSnapshotId: string;
}

interface PacketSnapshotIdentity {
  id: string;
  scannedAt: string;
  tenantId: string;
  tenantLabel: string;
  completion: TenantSnapshot["completion"];
}

interface PacketObject {
  id: string;
  kind: DirectoryNode["kind"];
  label: string;
  appId: string | null;
  ownerIds: string[];
  isExternal: boolean;
  risk: DirectoryNode["risk"];
}

interface PacketRelationship {
  id: string;
  type: RelationshipEdge["type"];
  sourceId: string;
  targetId: string;
  permissions: string[];
  scope?: NonNullable<RelationshipEdge["scope"]>;
  evidence: RelationshipEdge["evidence"];
}

interface PacketEvidence {
  objects: PacketObject[];
  relationships: PacketRelationship[];
}

interface PacketBase {
  schemaVersion: typeof EVIDENCE_PACKET_SCHEMA;
  snapshot: PacketSnapshotIdentity;
  evidence: PacketEvidence;
  review: EvidencePacketReviewContext | null;
}

export interface FindingEvidencePacket extends PacketBase {
  packetType: "finding";
  finding: IamFinding;
  lifecycle: Pick<FindingLifecycleRecord, "status" | "currentSnapshotId" | "previousSnapshotId" | "firstDetectedAt" | "lastDetectedAt" | "lastDetectedSnapshotId">;
  attackPath: AttackPath | null;
}

export interface AttackPathEvidencePacket extends PacketBase {
  packetType: "attack-path";
  attackPath: AttackPath;
}

export type EvidencePacket = FindingEvidencePacket | AttackPathEvidencePacket;

export function buildFindingEvidencePacket(history: TenantSnapshot[], findingId: string, review: EvidencePacketReviewContext | null = null): FindingEvidencePacket {
  const current = history[0];
  if (!current) throw new Error("At least one snapshot is required for a finding evidence packet.");
  const intelligence = analyzeTenantIntelligenceHistory(history);
  const lifecycle = analyzeFindingLifecycle(history);
  const finding = intelligence.findings.find((item) => item.id === findingId);
  const lifecycleRecord = lifecycle.records.find((item) => item.finding.id === findingId);
  if (!finding || !lifecycleRecord || lifecycleRecord.lastDetectedSnapshotId !== current.id) throw new Error("Finding is not detected in the current snapshot.");
  const attackPath = finding.attackPathId ? intelligence.paths.find((item) => item.id === finding.attackPathId)! : null;
  const edgeIds = unique(finding.edgeIds);
  const objectIds = unique(finding.affectedObjectIds);
  return {
    schemaVersion: EVIDENCE_PACKET_SCHEMA,
    packetType: "finding",
    snapshot: snapshotIdentity(current),
    finding: copyFinding(finding),
    lifecycle: {
      status: lifecycleRecord.status,
      currentSnapshotId: lifecycleRecord.currentSnapshotId,
      previousSnapshotId: lifecycleRecord.previousSnapshotId,
      firstDetectedAt: lifecycleRecord.firstDetectedAt,
      lastDetectedAt: lifecycleRecord.lastDetectedAt,
      lastDetectedSnapshotId: lifecycleRecord.lastDetectedSnapshotId,
    },
    attackPath: attackPath ? copyPath(attackPath) : null,
    evidence: focusedEvidence(current, objectIds, edgeIds),
    review: review ? { ...review } : null,
  };
}

export function buildAttackPathEvidencePacket(history: TenantSnapshot[], pathId: string, review: EvidencePacketReviewContext | null = null): AttackPathEvidencePacket {
  const current = history[0];
  if (!current) throw new Error("At least one snapshot is required for an attack-path evidence packet.");
  const path = analyzeTenantIntelligenceHistory(history).paths.find((item) => item.id === pathId);
  if (!path) throw new Error("Attack path is not detected in the current snapshot.");
  const edgeIds = path.steps.map((item) => item.edgeId);
  const objectIds = path.steps.flatMap((item) => [item.source.id, item.target.id]);
  return {
    schemaVersion: EVIDENCE_PACKET_SCHEMA,
    packetType: "attack-path",
    snapshot: snapshotIdentity(current),
    attackPath: copyPath(path),
    evidence: focusedEvidence(current, objectIds, edgeIds),
    review: review ? { ...review } : null,
  };
}

export function renderEvidencePacketMarkdown(packet: EvidencePacket): string {
  const subject = packet.packetType === "finding" ? packet.finding.title : packet.attackPath.title;
  const lines = [
    `# ${markdown(subject)}`,
    "",
    `- Packet: ${code(packet.packetType)}`,
    `- Schema: ${code(packet.schemaVersion)}`,
    `- Snapshot: ${code(packet.snapshot.id)}`,
    `- Collected: ${markdown(packet.snapshot.scannedAt)}`,
    `- Tenant: ${markdown(packet.snapshot.tenantLabel)} (${code(packet.snapshot.tenantId)})`,
    `- Coverage: ${markdown(packet.snapshot.completion.status)}; ${packet.snapshot.completion.collectedEndpoints.length} endpoint patterns collected; ${packet.snapshot.completion.skippedEndpoints.length} skipped`,
    "",
  ];
  if (packet.packetType === "finding") appendFinding(lines, packet);
  else appendPath(lines, packet.attackPath);
  appendEvidence(lines, packet.evidence);
  appendReview(lines, packet.review);
  lines.push("## Interpretation boundary", "", "This packet preserves configured, observed, inferred, and missing evidence as labeled. It does not prove exploitation, remediation, or use of configured access.", "");
  return lines.join("\n");
}

function appendFinding(lines: string[], packet: FindingEvidencePacket): void {
  const finding = packet.finding;
  lines.push("## Finding", "", `- ID: ${code(finding.id)}`, `- Severity: ${markdown(finding.severity)}`, `- Evidence class: ${markdown(finding.evidenceClass)}`, `- Lifecycle: ${markdown(packet.lifecycle.status)}`);
  if (finding.rule) lines.push(`- Rule: ${code(finding.rule.id)} v${finding.rule.version} — ${markdown(finding.rule.title)}`);
  lines.push("", markdown(finding.summary), "", "### Why it matters", "", markdown(finding.whyItMatters), "");
  appendList(lines, "Prerequisites", finding.prerequisites ?? []);
  appendList(lines, "Required coverage", finding.requiredCoverage ?? []);
  appendList(lines, "Recommended action", finding.remediation);
  appendList(lines, "Residual uncertainty", finding.uncertainty);
  if (packet.attackPath) appendPath(lines, packet.attackPath);
}

function appendPath(lines: string[], path: AttackPath): void {
  lines.push("## Attack path", "", `- ID: ${code(path.id)}`, `- Severity: ${markdown(path.severity)}`, `- Confidence: ${markdown(path.confidence)}`, `- Source: ${markdown(path.source.label)} (${code(path.source.id)})`, `- Target: ${markdown(path.target.label)} (${code(path.target.id)})`, "", "### Evidence-backed steps", "");
  for (const item of path.steps) lines.push(`${item.index + 1}. ${markdown(item.explanation)} — edge ${code(item.edgeId)}; endpoint ${code(item.sourceEndpoint)}`);
  lines.push("");
}

function appendEvidence(lines: string[], evidence: PacketEvidence): void {
  lines.push("## Focused evidence", "", "### Objects", "");
  for (const object of evidence.objects) lines.push(`- ${markdown(object.label)} — ${code(object.kind)} ${code(object.id)}`);
  if (evidence.objects.length === 0) lines.push("- None");
  lines.push("", "### Relationships", "");
  for (const edge of evidence.relationships) lines.push(`- ${code(edge.id)}: ${code(edge.sourceId)} → ${code(edge.targetId)}; ${markdown(edge.type)}; endpoint ${code(edge.evidence.sourceEndpoint)}; ${edge.evidence.observed ? "observed" : edge.evidence.configured ? "configured" : "unresolved"} evidence`);
  if (evidence.relationships.length === 0) lines.push("- None");
  lines.push("");
}

function appendReview(lines: string[], review: EvidencePacketReviewContext | null): void {
  lines.push("## Decision context", "");
  if (!review) { lines.push("No snapshot-scoped analyst decision was included.", ""); return; }
  lines.push(`- Status: ${markdown(review.disposition)}`, `- Owner: ${markdown(review.owner || "Unassigned")}`, `- Expiry: ${markdown(review.expiresAt ?? "None")}`, `- Source snapshot: ${code(review.sourceSnapshotId)}`, `- Updated: ${markdown(review.updatedAt)}`, "", markdown(review.assumption || "No assumptions or notes recorded."), "");
}

function appendList(lines: string[], heading: string, values: string[]): void {
  if (values.length === 0) return;
  lines.push(`### ${heading}`, "", ...values.map((value) => `- ${markdown(value)}`), "");
}

function snapshotIdentity(snapshot: TenantSnapshot): PacketSnapshotIdentity {
  return { id: snapshot.id, scannedAt: snapshot.scannedAt, tenantId: snapshot.tenant.tenantId, tenantLabel: snapshot.tenant.tenantLabel, completion: { ...snapshot.completion, collectedEndpoints: [...snapshot.completion.collectedEndpoints], skippedEndpoints: [...snapshot.completion.skippedEndpoints], errors: [...snapshot.completion.errors] } };
}

function focusedEvidence(snapshot: TenantSnapshot, objectIds: string[], edgeIds: string[]): PacketEvidence {
  const wantedObjects = new Set(objectIds);
  const wantedEdges = new Set(edgeIds);
  return {
    objects: snapshot.nodes.filter((node) => wantedObjects.has(node.id)).map((node) => ({ id: node.id, kind: node.kind, label: node.label, appId: node.appId ?? null, ownerIds: [...node.ownerIds], isExternal: node.isExternal ?? false, risk: { ...node.risk } })).sort((a, b) => a.id.localeCompare(b.id)),
    relationships: snapshot.edges.filter((edge) => wantedEdges.has(edge.id)).map((edge) => ({ id: edge.id, type: edge.type, sourceId: edge.sourceId, targetId: edge.targetId, permissions: [...edge.permissions], ...(edge.scope ? { scope: { ...edge.scope } } : {}), evidence: { ...edge.evidence, sourceRecordIds: [...edge.evidence.sourceRecordIds], observed: edge.evidence.observed ? { ...edge.evidence.observed } : null } })).sort((a, b) => a.id.localeCompare(b.id)),
  };
}

function copyFinding(finding: IamFinding): IamFinding {
  return { ...finding, remediation: [...finding.remediation], affectedObjectIds: [...finding.affectedObjectIds], edgeIds: [...finding.edgeIds], sourceEndpoints: [...finding.sourceEndpoints], uncertainty: [...finding.uncertainty], prerequisites: finding.prerequisites ? [...finding.prerequisites] : undefined, requiredCoverage: finding.requiredCoverage ? [...finding.requiredCoverage] : undefined, rule: finding.rule ? { ...finding.rule, requiredCoverage: [...finding.rule.requiredCoverage], references: [...finding.rule.references] } : undefined };
}

function copyPath(path: AttackPath): AttackPath {
  return { ...path, source: { ...path.source }, target: { ...path.target }, prerequisites: [...path.prerequisites], mitigations: [...path.mitigations], uncertainty: [...path.uncertainty], attackMappings: path.attackMappings.map((item) => ({ ...item })), steps: path.steps.map((item) => ({ ...item, source: { ...item.source }, target: { ...item.target }, permissions: [...item.permissions], scope: item.scope ? { ...item.scope } : undefined })) };
}

function markdown(value: string): string {
  const markdownPunctuation = new Set("\\`*_{}[]()#+.!|>~-");
  return [...stripControls(value)].map((character) => markdownPunctuation.has(character) ? `\\${character}` : character).join("").trim();
}

function code(value: string): string {
  return `\`${stripControls(value).replaceAll("`", " ").trim()}\``;
}

function unique(values: string[]): string[] { return [...new Set(values)]; }

function stripControls(value: string): string {
  return [...value].map((character) => { const point = character.codePointAt(0)!; return point < 32 || point === 127 ? " " : character; }).join("");
}
