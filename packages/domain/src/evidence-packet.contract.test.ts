import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { cleanProjectFixture } from "./fixtures";
import { analyzeTenantIntelligenceHistory } from "./intelligence";
import { buildAttackPathEvidencePacket, buildFindingEvidencePacket, EVIDENCE_PACKET_SCHEMA, renderEvidencePacketMarkdown } from "./evidence-packet";
import type { TenantSnapshot } from "./types";

function fixture(): TenantSnapshot {
  return structuredClone(cleanProjectFixture);
}

function digest(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
}

describe("focused evidence packets", () => {
  it("exports one current finding and only the evidence it references", () => {
    const snapshot = fixture();
    const finding = analyzeTenantIntelligenceHistory([snapshot]).findings.find((item) => item.edgeIds.length > 0)!;
    const packet = buildFindingEvidencePacket([snapshot], finding.id);

    expect(packet.schemaVersion).toBe(EVIDENCE_PACKET_SCHEMA);
    expect(packet.packetType).toBe("finding");
    expect(packet.finding.id).toBe(finding.id);
    expect(packet.lifecycle.status).toBe("new");
    expect(packet.snapshot).toMatchObject({ id: snapshot.id, tenantId: snapshot.tenant.tenantId, completion: snapshot.completion });
    expect(packet.evidence.relationships.map((edge) => edge.id)).toEqual([...packet.evidence.relationships.map((edge) => edge.id)].sort());
    expect(packet.evidence.relationships.length).toBeLessThan(snapshot.edges.length);
    expect(packet.evidence.objects.length).toBeLessThan(snapshot.nodes.length);
    expect(JSON.stringify(packet)).not.toContain("metadata");
    expect(packet.review).toBeNull();
  });

  it("includes a copied snapshot-scoped review without retaining caller mutations", () => {
    const snapshot = fixture();
    const finding = analyzeTenantIntelligenceHistory([snapshot]).findings[0]!;
    const review = { disposition: "accepted" as const, owner: "IAM team", expiresAt: "2026-09-30", assumption: "Owner remains accountable.", updatedAt: "2026-08-27T12:00:00.000Z", sourceSnapshotId: snapshot.id };
    const packet = buildFindingEvidencePacket([snapshot], finding.id, review);
    review.owner = "Changed later";

    expect(packet.review).toMatchObject({ disposition: "accepted", owner: "IAM team", sourceSnapshotId: snapshot.id });
    expect(packet.finding).not.toBe(finding);
    expect(packet.finding.remediation).not.toBe(finding.remediation);
  });

  it("keeps an evidence-gap finding focused even when it references no objects or relationships", () => {
    const snapshot = fixture();
    const finding = analyzeTenantIntelligenceHistory([snapshot]).findings.find((item) => item.category === "coverage")!;
    const packet = buildFindingEvidencePacket([snapshot], finding.id);
    const markdown = renderEvidencePacketMarkdown(packet);

    expect(packet.attackPath).toBeNull();
    expect(packet.evidence).toEqual({ objects: [], relationships: [] });
    expect(markdown).toContain("### Objects\n\n- None");
    expect(markdown).toContain("### Relationships\n\n- None");
    expect(markdown).not.toContain("## Attack path");
  });

  it("exports one attack path without exporting unrelated tenant inventory", () => {
    const snapshot = fixture();
    const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
    const packet = buildAttackPathEvidencePacket([snapshot], path.id);

    expect(packet.packetType).toBe("attack-path");
    expect(packet.attackPath.id).toBe(path.id);
    expect(packet.attackPath).not.toBe(path);
    expect(packet.evidence.relationships.map((edge) => edge.id).sort()).toEqual(path.steps.map((step) => step.edgeId).sort());
    expect(packet.evidence.objects.every((node) => path.steps.some((step) => step.source.id === node.id || step.target.id === node.id))).toBe(true);
  });

  it("rejects empty history and subjects absent from the current snapshot", () => {
    const snapshot = fixture();
    expect(() => buildFindingEvidencePacket([], "finding-x")).toThrow("At least one snapshot is required for a finding evidence packet.");
    expect(() => buildAttackPathEvidencePacket([], "path-x")).toThrow("At least one snapshot is required for an attack-path evidence packet.");
    expect(() => buildFindingEvidencePacket([snapshot], "finding-x")).toThrow("not detected in the current snapshot");
    expect(() => buildAttackPathEvidencePacket([snapshot], "path-x")).toThrow("not detected in the current snapshot");
  });

  it("inherits ordered same-tenant history validation", () => {
    const current = fixture();
    const wrongTenant = fixture();
    wrongTenant.tenant.tenantId = "another-tenant";
    wrongTenant.nodes = wrongTenant.nodes.map((node) => ({ ...node, tenantId: "another-tenant" }));
    wrongTenant.edges = wrongTenant.edges.map((edge) => ({ ...edge, tenantId: "another-tenant" }));
    const findingId = analyzeTenantIntelligenceHistory([current]).findings[0]!.id;
    expect(() => buildFindingEvidencePacket([current, wrongTenant], findingId)).toThrow("same tenant");
  });
});

describe("evidence packet Markdown", () => {
  it("renders rule, lifecycle, path, review, evidence, and interpretation boundaries", () => {
    const snapshot = fixture();
    const finding = analyzeTenantIntelligenceHistory([snapshot]).findings.find((item) => item.rule && item.attackPathId)!;
    const packet = buildFindingEvidencePacket([snapshot], finding.id, { disposition: "mitigating", owner: "Platform", expiresAt: null, assumption: "Rotation is scheduled.", updatedAt: snapshot.scannedAt, sourceSnapshotId: snapshot.id });
    const markdown = renderEvidencePacketMarkdown(packet);

    expect(markdown).toContain(`# ${finding.title}`);
    expect(markdown).toContain(`Rule: \`${finding.rule!.id}\``);
    expect(markdown).toContain("## Attack path");
    expect(markdown).toContain("## Focused evidence");
    expect(markdown).toContain("Status: mitigating");
    expect(markdown).toContain("does not prove exploitation");
  });

  it("renders a standalone path and the absence of review context", () => {
    const snapshot = fixture();
    const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
    const markdown = renderEvidencePacketMarkdown(buildAttackPathEvidencePacket([snapshot], path.id));
    expect(markdown).toContain("Packet: `attack-path`");
    expect(markdown).toContain("No snapshot-scoped analyst decision was included.");
  });

  it("escapes tenant-controlled Markdown and strips control characters", () => {
    const snapshot = fixture();
    snapshot.tenant.tenantLabel = "[Tenant](https://invalid)\u0000\u007f";
    snapshot.tenant.tenantId = "tenant`id";
    snapshot.nodes = snapshot.nodes.map((node) => ({ ...node, tenantId: "tenant`id" }));
    snapshot.edges = snapshot.edges.map((edge) => ({ ...edge, tenantId: "tenant`id" }));
    const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
    const markdown = renderEvidencePacketMarkdown(buildAttackPathEvidencePacket([snapshot], path.id, { disposition: "open", owner: "", expiresAt: null, assumption: "", updatedAt: snapshot.scannedAt, sourceSnapshotId: snapshot.id }));
    expect(markdown).toContain("\\[Tenant\\]\\(https://invalid\\)");
    expect(markdown).not.toContain("\u0000");
    expect(markdown).not.toContain("\u007f");
    expect(markdown).toContain("`tenant id`");
    expect(markdown).toContain("Owner: Unassigned");
    expect(markdown).toContain("Expiry: None");
    expect(markdown).toContain("No assumptions or notes recorded\\.");
  });

  it("labels observed and unresolved relationship evidence without changing its meaning", () => {
    const snapshot = fixture();
    const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
    const evidenceEdge = snapshot.edges.find((edge) => edge.id === path.steps[0]!.edgeId)!;
    evidenceEdge.evidence.observed = { lastSeenAt: snapshot.scannedAt, windowStartsAt: snapshot.scannedAt };
    const observed = buildAttackPathEvidencePacket([snapshot], path.id);
    expect(renderEvidencePacketMarkdown(observed)).toContain("observed evidence");

    observed.evidence.relationships[0]!.evidence.observed = null;
    observed.evidence.relationships[0]!.evidence.configured = false;
    expect(renderEvidencePacketMarkdown(observed)).toContain("unresolved evidence");
  });

  it("copies scoped observed evidence and scan errors without retaining source objects", () => {
    const snapshot = fixture();
    snapshot.completion.errors = ["permissionGrantPolicies: denied"];
    const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
    const sourceEdge = snapshot.edges.find((edge) => edge.id === path.steps[0]!.edgeId)!;
    sourceEdge.scope = { directoryScopeId: "/administrativeUnits/unit-1", objectId: "unit-1" };
    sourceEdge.evidence.observed = { lastSeenAt: snapshot.scannedAt, windowStartsAt: "2026-07-27T00:00:00Z" };
    const packet = buildAttackPathEvidencePacket([snapshot], path.id);
    const copiedEdge = packet.evidence.relationships.find((edge) => edge.id === sourceEdge.id)!;

    expect(packet.snapshot.completion.errors).toEqual(["permissionGrantPolicies: denied"]);
    expect(copiedEdge.scope).toEqual(sourceEdge.scope);
    expect(copiedEdge.evidence.observed).toEqual(sourceEdge.evidence.observed);
    expect(packet.attackPath.steps[0]!.scope).toEqual(sourceEdge.scope);
    sourceEdge.scope.objectId = "changed";
    sourceEdge.evidence.observed.lastSeenAt = "changed";
    snapshot.completion.errors[0] = "changed";
    expect(copiedEdge.scope?.objectId).toBe("unit-1");
    expect(copiedEdge.evidence.observed?.lastSeenAt).not.toBe("changed");
    expect(packet.snapshot.completion.errors[0]).not.toBe("changed");
  });
});

describe("evidence packet archival contract", () => {
  it("keeps versioned JSON and Markdown representations reviewably stable", () => {
    const snapshot = fixture();
    snapshot.nodes.reverse();
    snapshot.edges.reverse();
    const intelligence = analyzeTenantIntelligenceHistory([snapshot]);
    const finding = intelligence.findings.find((item) => item.rule && item.attackPathId)!;
    const coverage = intelligence.findings.find((item) => item.category === "coverage")!;
    const review = { disposition: "accepted" as const, owner: "IAM", expiresAt: "2026-09-30", assumption: "Approved while migration completes.", updatedAt: snapshot.scannedAt, sourceSnapshotId: snapshot.id };
    const findingPacket = buildFindingEvidencePacket([snapshot], finding.id, review);
    const coveragePacket = buildFindingEvidencePacket([snapshot], coverage.id);
    const pathPacket = buildAttackPathEvidencePacket([snapshot], finding.attackPathId!, review);
    expect({ finding: digest(findingPacket), coverage: digest(coveragePacket), path: digest(pathPacket), findingMarkdown: digest(renderEvidencePacketMarkdown(findingPacket)), coverageMarkdown: digest(renderEvidencePacketMarkdown(coveragePacket)), pathMarkdown: digest(renderEvidencePacketMarkdown(pathPacket)) }).toEqual({
      finding: "e1cdb79ce7b2b059d41633cc5f72f0c5ba1321281b5524ed079bd6100f6eee77",
      coverage: "d3c90c9ce45750b10fc0b203c8756783384ad9ec35b837d3f906ce275d5c56bd",
      path: "e4378070b9fa0ecd041ceb702a296ff2ed1267f5647efe5d0bc95fd07f276735",
      findingMarkdown: "39c7dfcb57d9a294686a81b83cca940a92f733bfa11c3825f591d4acfd951d19",
      coverageMarkdown: "6c6868b1fa608eeb8ac7c2ef1f4c5cdcf7ff3ebd49f80f138bffdc7c0488a603",
      pathMarkdown: "ec663150cdfb54c75d630b83d244432b515b290d0483d439ce8b702b8607a472",
    });
  });
});
