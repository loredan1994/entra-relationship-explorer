import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { evaluateAuthorization } from "./authorization";
import { canonical } from "./canonical";
import { compileSnapshot } from "./model";
import { exportInvestigation, verifyInvestigation } from "./portable";
import { node, policy, query, snapshot, TIME } from "./test-support";

it.each(["false", "true", 0, 1, [], {}, null, undefined])("rejects non-boolean configuration evidence %j before it can certify access", configured => {
  const source = snapshot();
  Object.assign(source.edges[0]!.evidence, { configured });
  expect(() => compileSnapshot(source)).toThrow("Invalid engine evidence");
});

it.each(["sourceObjectId", "targetObjectId"] as const)("rejects a claim whose %s contradicts its graph endpoints", field => {
  const source = snapshot();
  source.edges[0]!.evidence[field] = "unrelated-object";
  expect(() => compileSnapshot(source)).toThrow("Evidence object IDs must match relationship endpoints");
});

it.each(["configured", "sourceObjectId", "targetObjectId", "sourceRecordIds", "sourceEndpoint"] as const)("rejects attacker-rehashed portable %s evidence before replay", async field => {
  const { package: packet } = await exportInvestigation(compileSnapshot(snapshot()), query);
  const malformed = { configured: "false", sourceObjectId: "other", targetObjectId: "blueprint", sourceRecordIds: [false], sourceEndpoint: true };
  Object.assign(packet.snapshot.edges[0]!.evidence, { [field]: malformed[field] });
  const { manifest, ...body } = packet;
  manifest.digest = createHash("sha256").update(canonical(body)).digest("hex");
  await expect(verifyInvestigation(canonical(packet))).rejects.toThrow(/Invalid engine evidence|Evidence object IDs must match/);
});

it.each(["endpoint", "record"])("does not certify access using whitespace-only source %s", field => {
  const source = snapshot();
  if (field === "endpoint") source.edges[0]!.evidence.sourceEndpoint = "   ";
  else source.edges[0]!.evidence.sourceRecordIds = [" "];
  const proof = evaluateAuthorization(compileSnapshot(source), query);
  expect(proof.verdict).toBe("unknown");
  expect(proof.missing).toContain("relationship:grant:complete-source");
});

it("preserves valid absent historical fields and incomplete source evidence as unknown", () => {
  const source = snapshot();
  delete source.edges[0]!.permissionIds;
  source.edges[0]!.evidence.sourceEndpoint = "";
  source.edges[0]!.evidence.sourceRecordIds = [];
  source.completion.collectors = undefined;
  source.nodes[0]!.applicationProfile = { signInAudience: null, verifiedPublisherId: null, verifiedPublisherName: null };
  const proof = evaluateAuthorization(compileSnapshot(source), query);
  expect(proof.verdict).toBe("unknown");
  expect(proof.missing).toContain("relationship:grant:complete-source");
  expect(proof.missing).toContain("relationship:grant:permission-ids");
});

function richSnapshot() {
  const source = snapshot();
  source.nodes[0]!.applicationProfile = { signInAudience: "AzureADMyOrg", accountEnabled: false, assignmentRequired: true, verifiedPublisherId: null, verifiedPublisherName: null };
  source.nodes[0]!.credentials = [{ id: "credential", kind: "certificate", label: null, startsAt: TIME, expiresAt: null, sourceEndpoint: "/applications/client" }];
  source.nodes.push({ ...node("federated", "federatedCredential"), federationTrust: { issuer: "https://issuer.example", subject: "subject", audiences: ["exchange"], unsupported: [] } }, policy());
  source.edges[0]!.consent = { audience: "single-user", principalId: "person" };
  source.edges[0]!.scope = { directoryScopeId: "/", objectId: null };
  source.edges[0]!.validity = { startsAt: TIME, endsAt: null };
  source.edges[0]!.evidence.observed = { lastSeenAt: TIME, windowStartsAt: TIME };
  source.completion.collectors![0]!.limits = { maxItemsPerEndpoint: 10, maxPagesPerEndpoint: 1 };
  source.completion.collectors![0]!.window = { startsAt: TIME, endsAt: TIME, eventClasses: ["user"] };
  return source;
}

const malformedFields: Array<[string, unknown]> = [
  ["id", 0], ["tenant", null], ["tenant.tenantId", false], ["scannedAt", true], ["nodes", false], ["edges", {}], ["completion", null],
  ["nodes.0", false], ["nodes.0.kind", "future"], ["nodes.0.appId", true], ["nodes.0.sourceEndpoint", true],
  ["nodes.0.applicationProfile", false], ["nodes.0.applicationProfile.signInAudience", 0], ["nodes.0.applicationProfile.accountEnabled", "false"], ["nodes.0.applicationProfile.assignmentRequired", "true"],
  ["nodes.0.credentials", false], ["nodes.0.credentials.0.kind", "secret"], ["nodes.0.credentials.0.startsAt", false],
  ["nodes.9.federationTrust", false], ["nodes.9.federationTrust.issuer", true], ["nodes.9.federationTrust.subject", false], ["nodes.9.federationTrust.audiences", "exchange"], ["nodes.9.federationTrust.unsupported", [false]],
  ["nodes.10.conditionalAccess", false], ["nodes.10.conditionalAccess.state", true], ["nodes.10.conditionalAccess.users.include", "All"], ["nodes.10.conditionalAccess.users.exclude", [false]],
  ["nodes.10.conditionalAccess.platforms", false], ["nodes.10.conditionalAccess.locations", []], ["nodes.10.conditionalAccess.clientAppTypes", false], ["nodes.10.conditionalAccess.grant.controls", "block"], ["nodes.10.conditionalAccess.grant.operator", true],
  ["edges.0.type", "future"], ["edges.0.permissions", "Read"], ["edges.0.permissionIds", [false]], ["edges.0.sourceId", false], ["edges.0.targetId", 42],
  ["edges.0.consent", false], ["edges.0.consent.audience", "future"], ["edges.0.consent.principalId", false], ["edges.0.scope", false], ["edges.0.scope.directoryScopeId", 0], ["edges.0.scope.objectId", true],
  ["edges.0.validity", false], ["edges.0.validity.startsAt", 0], ["edges.0.validity.endsAt", true], ["edges.0.evidence.observed", false], ["edges.0.evidence.observed.lastSeenAt", true], ["edges.0.evidence.observed.windowStartsAt", []],
  ["edges.0.evidence.scannedAt", false], ["edges.0.evidence.sourceEndpoint", true], ["edges.0.evidence.sourceRecordIds", "grant"], ["edges.0.evidence.sourceRecordIds", [false]], ["edges.0.evidence.completeness", true],
  ["completion.collectors", false], ["completion.collectors.0.state", "future"], ["completion.collectors.0.collectedAt", false], ["completion.collectors.0.endpoints", "/applications"], ["completion.collectors.0.failedEndpoints", [false]],
  ["completion.collectors.0.itemCount", -1], ["completion.collectors.0.itemCount", "1"], ["completion.collectors.0.scope", true], ["completion.collectors.0.limits", false], ["completion.collectors.0.limits.maxItemsPerEndpoint", 0], ["completion.collectors.0.limits.maxPagesPerEndpoint", 1.5], ["completion.collectors.0.window.eventClasses", [false]],
];

it.each(malformedFields)("rejects interpreted field %s with malformed value %j", (path, value) => {
  const source = richSnapshot();
  const keys = path.split(".");
  const owner = keys.slice(0, -1).reduce<unknown>((value, key) => (value as Record<string, unknown>)[key], source) as Record<string, unknown>;
  owner[keys.at(-1)!] = value;
  expect(() => compileSnapshot(source)).toThrow("Invalid engine evidence");
});

it("accepts structured interpreted values without restricting or retaining arbitrary metadata", () => {
  const source = richSnapshot();
  source.nodes[0]!.metadata = { arbitrary: true };
  const model = compileSnapshot(source);
  expect(model.nodes.find(n => n.id === "client")!.applicationProfile).toMatchObject({ accountEnabled: false, assignmentRequired: true });
  expect(model.nodes.find(n => n.id === "client")!.metadata).toBeUndefined();
  expect(evaluateAuthorization(model, query).verdict).toBe("supported");
});

it("rejects a configured grant with an unparseable collection timestamp", () => {
  const source = snapshot();
  source.edges[0]!.evidence.scannedAt = "not-a-date";
  expect(() => compileSnapshot(source)).toThrow("Invalid engine timestamp");
});

it.each([null, true, [], 1, "snapshot"])("rejects malformed root input %j with a boundary error", value => {
  expect(() => compileSnapshot(value as unknown as ReturnType<typeof snapshot>)).toThrow("Invalid engine evidence");
});

it.each(["nodes", "edges"] as const)("rejects oversized %s before visiting any inventory element", field => {
  const source = snapshot();
  source[field].length = field === "nodes" ? 100_001 : 500_001;
  Object.defineProperty(source[field], "0", { get() { throw new Error("An oversized inventory element was visited."); } });
  expect(() => compileSnapshot(source)).toThrow("Snapshot exceeds engine input limits");
});
