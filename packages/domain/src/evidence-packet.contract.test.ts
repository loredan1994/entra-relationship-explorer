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
    // Reviewed additive fixture scope: the precise resource assignment endpoint now establishes missing-grant coverage.
    expect({ finding: digest(findingPacket), coverage: digest(coveragePacket), path: digest(pathPacket), findingMarkdown: digest(renderEvidencePacketMarkdown(findingPacket)), coverageMarkdown: digest(renderEvidencePacketMarkdown(coveragePacket)), pathMarkdown: digest(renderEvidencePacketMarkdown(pathPacket)) }).toEqual({
      finding: "5fb6a6ca05c1ee02556369b424ee4d025fed5a33d1ea6c261ef53941fd6cdc19",
      coverage: "c98e627424b3bfdcfe2d6cce41ba7c2c4f14bd4928fe6d3ef6cbfbc0f8f6b4e2",
      path: "0c61df363b73dc029160e3dabf49321bcc80d05e4d6db36efc325540ce304e0b",
      findingMarkdown: "c9ad9b6028f776e135808d1a10190789b358bd54c4ca38856827d44ac35aaf48",
      coverageMarkdown: "39c9bb40554810e1f0b887a1f361a684249f9e9e971bebd339a8bc99c2734403",
      pathMarkdown: "f38abe8f5ddf5eee177d961653c59c93a47cf5cd2001dbfef155699a0fd65f29",
    });
  });
});

it("preserves delegated consent audience and principal in focused Markdown", () => {
  const snapshot = fixture();
  const delegated = snapshot.edges.find(edge => edge.type === "CAN_CALL_DELEGATED")!;
  const finding = analyzeTenantIntelligenceHistory([snapshot]).findings.find(finding => finding.edgeIds.includes(delegated.id))!;
  expect(finding).toBeDefined();
  const packet = buildFindingEvidencePacket([snapshot], finding.id);
  const relationship = packet.evidence.relationships.find(edge => edge.id === delegated.id)!;
  relationship.consent = { audience: "single-user", principalId: "synthetic-person-id" };
  const singleUser = renderEvidencePacketMarkdown(packet);
  expect(singleUser).toContain("single\\-user");
  expect(singleUser).toContain("synthetic-person-id");
  relationship.consent = { audience: "all-users", principalId: null };
  const allUsers = renderEvidencePacketMarkdown(packet);
  expect(allUsers).toContain("all\\-users");
  expect(allUsers).not.toContain("synthetic-person-id");
});

it("copies detailed coverage and consent fields rather than sharing mutable nested objects", () => {
  const snapshot = fixture();
  snapshot.completion.collectors = [{ id: "activity", state: "partial", reason: "User activity only", collectedAt: snapshot.scannedAt, endpoints: ["/auditLogs/signIns"], failedEndpoints: [], itemCount: 1, scope: "AuditLog.Read.All", window: { startsAt: "2026-07-27", endsAt: snapshot.scannedAt, eventClasses: ["interactiveUser"] } }];
  const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
  const first = snapshot.edges.find(e => e.id === path.steps[0]!.edgeId)!;
  first.consent = { audience: "single-user", principalId: null };
  const packet = buildAttackPathEvidencePacket([snapshot], path.id);
  expect(packet.evidence.relationships.find(e => e.id === first.id)!.consent).toEqual({ audience: "single-user", principalId: null });
  expect(renderEvidencePacketMarkdown(packet)).toContain("consent principal `Not specified`");
  snapshot.completion.collectors[0]!.window!.eventClasses.push("changed-after-export");
  first.consent.audience = "all-users";
  expect(packet.snapshot.completion.collectors![0]!.window!.eventClasses).toEqual(["interactiveUser"]);
  expect(packet.evidence.relationships.find(e => e.id === first.id)!.consent!.audience).toBe("single-user");
});
it("trims surrounding whitespace while replacing control characters with readable separators", () => {
  const snapshot = fixture(); const path = analyzeTenantIntelligenceHistory([snapshot]).paths[0]!;
  const packet = buildAttackPathEvidencePacket([snapshot], path.id);
  packet.attackPath.title = "  Left\u001fRight\u007fEnd  ";
  packet.snapshot.id = "  before`after  ";
  const rendered = renderEvidencePacketMarkdown(packet);
  expect(rendered.split("\n")[0]).toBe("# Left Right End");
  expect(rendered).toContain("- Snapshot: `before after`");
});

it("rejects a retained finding that is absent from the current snapshot", async () => {
  const { node, snapshot } = await import("./test-support");
  const app = node({ id: "orphan", kind: "application", label: "Orphan" });
  const before = snapshot([app], [], { id: "before", scannedAt: "2026-08-25T00:00:00Z" });
  const after = snapshot([{ ...app, ownerIds: ["owner"] }], [], { id: "after", scannedAt: "2026-08-26T00:00:00Z" });
  const finding = analyzeTenantIntelligenceHistory([before]).findings.find(f => f.category === "ownership")!;
  expect(() => buildFindingEvidencePacket([after, before], finding.id)).toThrow("Finding is not detected in the current snapshot.");
});
