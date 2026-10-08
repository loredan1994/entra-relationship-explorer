import { expect, it } from "vitest";
import { analyzeTenantIntelligence, analyzeTenantIntelligenceHistory, controlTransition } from "./intelligence";
import { edge, node, snapshot, syntheticWorkloadActivity } from "./test-support";
import type { NodeKind, RelationshipType } from "./types";
function view(type: RelationshipType, from: NodeKind, to: NodeKind) {
  const source = node({ kind: from, label: "Source" }); const target = node({ kind: to, label: "Target" });
  return { source, target, edge: edge(type, source, target) };
}
it.each([
  ["MEMBER_OF", "user", "group", "continue"], ["MEMBER_OF", "user", "application", "stop"],
  ["OWNS", "user", "application", "continue"], ["OWNS", "user", "servicePrincipal", "continue"], ["OWNS", "user", "group", "stop"],
  ["INSTANTIATES_AS", "application", "servicePrincipal", "continue"], ["INSTANTIATES_AS", "user", "servicePrincipal", "stop"], ["INSTANTIATES_AS", "application", "application", "stop"],
  ["FEDERATES_AS", "federatedCredential", "application", "continue"], ["FEDERATES_AS", "federatedCredential", "managedIdentity", "continue"], ["FEDERATES_AS", "user", "application", "stop"], ["FEDERATES_AS", "federatedCredential", "servicePrincipal", "stop"],
  ["GOVERNED_BY", "user", "policy", "stop"], ["CAN_CALL_AS_APP", "servicePrincipal", "servicePrincipal", "terminal"], ["CAN_CALL_DELEGATED", "servicePrincipal", "servicePrincipal", "terminal"], ["ACTIVE_IN_ROLE", "user", "directoryRole", "terminal"], ["ELIGIBLE_FOR_ROLE", "user", "directoryRole", "terminal"],
] as const)("allows only defensible control transitions: %s %s to %s", (type, from, to, expected) => expect(controlTransition(view(type, from, to), [])).toBe(expected));
it.each(["OWNS", "MEMBER_OF", "CAN_CALL_AS_APP", "CAN_CALL_DELEGATED", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as const)("membership continuation does not grant application credentials (%s)", type => {
  expect(controlTransition(view(type, "group", "directoryRole"), [view("MEMBER_OF", "user", "group")])).toBe(["ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"].includes(type) ? "terminal" : "stop");
});
it("reports a depth cap only when a further unvisited control transition remains", () => {
  const user = node({ id: "person", kind: "user", label: "Person" });
  const apps = Array.from({ length: 6 }, (_, i) => node({ id: `app-${i}`, kind: "application", label: `App ${i}`, ownerIds: ["owner"] }));
  const nodes = [user, ...apps]; const edges = apps.slice(0, 5).map((target, i) => edge("OWNS", nodes[i]!, target));
  const s = snapshot(nodes, edges);
  expect(analyzeTenantIntelligence(s).pathAnalysis.truncated).toBe(false);
  s.edges.push(edge("OWNS", apps[4]!, apps[0]!));
  expect(analyzeTenantIntelligence(s).pathAnalysis.truncated).toBe(false);
  s.edges.push(edge("GOVERNED_BY", apps[4]!, apps[5]!));
  expect(analyzeTenantIntelligence(s).pathAnalysis.truncated).toBe(false);
  s.edges.push(edge("OWNS", apps[4]!, apps[5]!));
  expect(analyzeTenantIntelligence(s).pathAnalysis.truncated).toBe(true);
});
it.each([",", ", ", ",  "])("matches broad legacy consent assignments with separator %j and exact relationship provenance", separator => {
  const legacy = node({ id: "microsoft-user-default-legacy", kind: "policy", label: "Legacy" });
  const custom = node({ id: "custom", kind: "policy", label: "Custom" });
  const auth = node({ id: "auth", kind: "policy", label: "Authorization", metadata: { policyType: "authorization", permissionGrantPoliciesAssigned: `custom${separator}ManagePermissionGrantsForSelf.microsoft-user-default-legacy` } });
  const other = node({ id: "other", kind: "policy", label: "Other" });
  const relationship = edge("ASSIGNS_CONSENT_POLICY", auth, legacy, { id: "match", evidence: { sourceEndpoint: "/policies/authorizationPolicy?$select=id" } });
  const s = snapshot([auth, custom, legacy, other], [edge("OWNS", auth, legacy), edge("ASSIGNS_CONSENT_POLICY", other, legacy), edge("ASSIGNS_CONSENT_POLICY", auth, custom), relationship]);
  const result = analyzeTenantIntelligence(s).findings.find(f => f.category === "consent-policy")!;
  expect(result).toMatchObject({ category: "consent-policy", affectedObjectIds: ["auth", "microsoft-user-default-legacy"], edgeIds: ["match"], sourceEndpoints: ["/policies/authorizationPolicy?$select=id"] });
  expect(result.id).toMatch(/^finding-consent-policy-/);
  expect(result.uncertainty).toEqual(["This configured policy does not prove that any user granted consent or that an application used delegated access."]);
  s.edges = [];
  expect(analyzeTenantIntelligence(s).findings.find(f => f.category === "consent-policy")).toMatchObject({ edgeIds: [], sourceEndpoints: ["/policies/authorizationPolicy"] });
});
it("does not call unavailable event classes complete activity coverage", () => {
  const client = node({ kind: "servicePrincipal", label: "Client", ownerIds: ["owner"] }); const api = node({ kind: "servicePrincipal", label: "API", ownerIds: ["owner"] });
  const s = snapshot([client, api], [edge("CAN_CALL_AS_APP", client, api)]);
  s.completion.collectedEndpoints.push("/auditLogs/signIns");
  s.completion.collectors = [{ ...syntheticWorkloadActivity[0]!, id: "other" }, { ...syntheticWorkloadActivity[0]!, window: undefined }];
  expect(analyzeTenantIntelligence(s).findings.some(f => f.category === "dormant-access")).toBe(false);
});
it("validates every historical tenant boundary and allows equal collection instants", () => {
  const valid = snapshot([node({ kind: "user", label: "Person" })], []);
  expect(() => analyzeTenantIntelligenceHistory([valid, structuredClone(valid)])).not.toThrow();
  for (const kind of ["node", "edge", "root"]) {
    const invalid = structuredClone(valid);
    if (kind === "node") invalid.nodes[0]!.tenantId = "foreign";
    if (kind === "root") invalid.tenant.tenantId = "foreign";
    if (kind === "edge") { invalid.edges.push(edge("OWNS", invalid.nodes[0]!, invalid.nodes[0]!)); invalid.edges[0]!.tenantId = "foreign"; }
    expect(() => analyzeTenantIntelligenceHistory([valid, invalid])).toThrow("Intelligence history snapshots must belong to the same tenant.");
  }
});

it("does not turn an arbitrary connection into federation or count blocked walks", () => {
  const relationship = view("OBSERVED_CALL", "federatedCredential", "application");
  expect(controlTransition(relationship, [])).toBe("stop");
  expect(analyzeTenantIntelligence(snapshot([relationship.source, relationship.target], [relationship.edge])).pathAnalysis.traversals).toBe(0);
});
it("classifies a medium federation path without pretending it is a privileged application-control rule", () => {
  const trust = node({ id: "federated-credential:trust", kind: "federatedCredential", label: "Trust" });
  const workload = node({ kind: "managedIdentity", label: "Workload" }); const api = node({ kind: "servicePrincipal", label: "API" });
  const s = snapshot([trust, workload, api], [edge("FEDERATES_AS", trust, workload), edge("CAN_CALL_AS_APP", workload, api, { permissions: ["Data.Read.All"] })]);
  const result = analyzeTenantIntelligence(s), path = result.paths.find(p => p.source.id === trust.id)!;
  expect(result.findings.find(f => f.attackPathId === path.id)).toMatchObject({ category: "federated-identity", severity: "medium" });
});
it("keeps policy findings distinct and ignores policy-like metadata on non-policy objects", () => {
  const metadata = { policyType: "authorization", permissionGrantPoliciesAssigned: "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" };
  const a = node({ kind: "policy", label: "A", metadata }), b = node({ kind: "policy", label: "B", metadata });
  const fake = node({ kind: "user", label: "Not a policy", metadata });
  const findings = analyzeTenantIntelligence(snapshot([a, b, fake], [])).findings.filter(f => f.category === "consent-policy");
  expect(findings).toHaveLength(2); expect(new Set(findings.map(f => f.id)).size).toBe(2);
});
it("keeps generic paths alongside the separate ownership finding", () => {
  const sp = node({ kind: "servicePrincipal", label: "Ownerless workload", metadata: { ownershipExpected: true } }); const role = node({ kind: "directoryRole", label: "Global Administrator" });
  const result = analyzeTenantIntelligence(snapshot([sp, role], [edge("ACTIVE_IN_ROLE", sp, role)]));
  expect(result.findings.filter(f => f.attackPathId === result.paths[0]!.id)).toHaveLength(2);
});

it.each([null, 1, true, undefined])("does not interpret malformed policy assignments as consent (%s)", assignments => {
  const policy = node({ kind: "policy", label: "Policy", metadata: { policyType: "authorization", ...(assignments === undefined ? {} : { permissionGrantPoliciesAssigned: assignments }) } });
  expect(analyzeTenantIntelligence(snapshot([policy], [])).findings.filter(f => f.category === "consent-policy")).toEqual([]);
});

it("does not suppress a distinct tenant-identity ownership gap merely because that identity controls another workload", () => {
  const app = node({ kind: "application", label: "Owned registration", ownerIds: ["owner"] });
  const controller = node({ kind: "servicePrincipal", label: "Unowned tenant identity", metadata: { ownershipExpected: true } });
  const target = node({ kind: "servicePrincipal", label: "Controlled", ownerIds: ["owner"] });
  const role = node({ kind: "directoryRole", label: "Global Administrator" });
  const s = snapshot([app, controller, target, role], [edge("INSTANTIATES_AS", app, controller), edge("OWNS", controller, target), edge("ACTIVE_IN_ROLE", target, role)]);
  const findings = analyzeTenantIntelligence(s).findings;
  expect(findings.some(f => f.rule?.id === "ERE-IAM-001")).toBe(true);
  expect(findings.filter(f => f.category === "ownership").map(f => f.affectedObjectIds[0])).toEqual([controller.id]);
});

it("requires an authorization policy before interpreting an assigned legacy consent policy", () => {
  const policy = node({ kind: "policy", label: "Other policy", metadata: { policyType: "conditionalAccess", permissionGrantPoliciesAssigned: "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" } });
  expect(analyzeTenantIntelligence(snapshot([policy], [])).findings.filter(f => f.category === "consent-policy")).toEqual([]);
});
