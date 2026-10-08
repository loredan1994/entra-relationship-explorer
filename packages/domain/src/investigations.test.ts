import { describe, expect, it } from "vitest";
import { coverageMatrix, credentialWorkbench, permissionLedger, simulateRemoval, snapshotTimeline, replayRuleLabCase, parseRuleLabCase, cleanProjectFixture, credentialStateAt } from "./index";
import { edge, node, snapshot, TENANT } from "./test-support";

function ledgerFixture() {
  const app = node({ id: "app", kind: "application", label: "Client blueprint", appId: "client-app", requestedPermissions: [{ resourceAppId: "api-app", permissionId: "read-id", kind: "application" }, { resourceAppId: "api-app", permissionId: "scope-id", kind: "delegated" }] });
  const client = node({ id: "client", kind: "servicePrincipal", label: "Client", appId: "client-app" });
  const api = node({ id: "api", kind: "servicePrincipal", label: "Resource", appId: "api-app", permissionDefinitions: [{ id: "read-id", value: "Data.Read", kind: "application" }, { id: "write-id", value: "Data.Write", kind: "application" }, { id: "scope-id", value: "Data.Read", kind: "delegated" }] });
  const grant = { ...edge("CAN_CALL_AS_APP", client, api, { permissions: ["Data.Read", "Data.Write"] }), permissionIds: ["read-id", "write-id"] };
  const delegated = { ...edge("CAN_CALL_DELEGATED", client, api, { permissions: ["Data.Read"] }), consent: { audience: "single-user" as const, principalId: "user-a" } };
  return snapshot([app, client, api], [grant, delegated]);
}

describe("permission reconciliation", () => {
  it("distinguishes requested/granted, undeclared grants and one-user consent without confusing same-name scopes and roles", () => {
    const rows = permissionLedger(ledgerFixture());
    expect(rows.find(r => r.permissionId === "read-id")?.status).toBe("requested-and-granted");
    expect(rows.find(r => r.permissionId === "write-id")?.status).toBe("granted-not-requested");
    expect(rows.find(r => r.kind === "delegated")).toMatchObject({ status: "requested-and-granted", audience: "One user", principalId: "user-a" });
  });
  it("cannot call an absent grant missing until its endpoint was collected", () => {
    const s = ledgerFixture(); s.edges = [];
    expect(permissionLedger(s).every(r => r.status === "unknown")).toBe(true);
    s.completion.collectedEndpoints.push("/servicePrincipals/api/appRoleAssignedTo", "/oauth2PermissionGrants");
    expect(permissionLedger(s).every(r => r.status === "requested-not-granted")).toBe(true);
    expect(permissionLedger(s).find(r => r.kind === "application")!.sourceEndpoints).toContain("/servicePrincipals/api/appRoleAssignedTo");
    expect(permissionLedger(s).find(r => r.kind === "delegated")!.sourceEndpoints).toContain("/oauth2PermissionGrants");
    s.completion.skippedEndpoints.push("/oauth2PermissionGrants");
    expect(permissionLedger(s).find(r => r.kind === "delegated")?.status).toBe("unknown");
  });
  it("never interprets an external or legacy missing manifest as an empty manifest", () => {
    const s = ledgerFixture(); delete s.nodes[0]!.requestedPermissions;
    expect(permissionLedger(s).every(r => r.status === "unknown")).toBe(true);
    s.nodes = s.nodes.filter(n => n.kind !== "application");
    expect(permissionLedger(s).every(r => r.status === "unknown")).toBe(true);
  });
  it("retains an audience-widening field diff with unchanged scope values", () => {
    const before = ledgerFixture(); const after = structuredClone(before);
    after.edges[1]!.consent = { audience: "all-users", principalId: null };
    expect(snapshotTimeline(before, after).changes[0]).toMatchObject({ subject: "relationship", kind: "changed", fields: [expect.objectContaining({ field: "consent" })] });
  });
});

describe("credential lifecycle", () => {
  const key = { id: "old", kind: "password" as const, label: null, startsAt: "2025-01-01T00:00:00Z", expiresAt: "2026-01-01T00:00:00Z", sourceEndpoint: "/applications" };
  it("keeps the expired credential while recognizing a valid replacement and overlap", () => {
    const app = node({ kind: "application", label: "Rotating app", credentials: [key, { ...key, id: "new", expiresAt: "2027-01-01T00:00:00Z" }, { ...key, id: "overlap", expiresAt: "2028-01-01T00:00:00Z" }] });
    const [row] = credentialWorkbench(snapshot([app], []));
    expect(row).toMatchObject({ usableCount: 2, expiredWithReplacement: true, rotationOverlap: true });
    expect(row!.credentials[0]!.state).toBe("expired");
  });
  it("does not call missing or future validity usable; handles exact expiry and 30-day boundary", () => {
    const at = "2026-08-26T10:00:00Z";
    expect(credentialStateAt({ ...key, expiresAt: at }, at)).toBe("expired");
    expect(credentialStateAt({ ...key, expiresAt: "2026-09-25T10:00:00Z" }, at)).toBe("expires-soon");
    expect(credentialStateAt({ ...key, startsAt: null }, at)).toBe("unknown");
    expect(credentialStateAt({ ...key, startsAt: "2027-01-01", expiresAt: "2028-01-01" }, at)).toBe("not-yet-valid");
    expect(credentialWorkbench(snapshot([node({ kind: "application", label: "Legacy" })], []))[0]!.inventoryKnown).toBe(false);
  });
});

describe("local access scenarios", () => {
  it("removes direct group-to-role reachability without inventing inherited application control", () => {
    const user = node({ kind: "user", label: "Person" });
    const group = node({ kind: "group", label: "Role group" });
    const role = node({ kind: "directoryRole", label: "Global Administrator" });
    const membership = edge("MEMBER_OF", user, group);
    const s = snapshot([user, group, role], [membership, edge("ACTIVE_IN_ROLE", group, role)]);
    const result = simulateRemoval(s, [membership.id]);
    expect(result.removedPaths.map(p => p.source.id)).toEqual([user.id]);
    expect(result.remainingPaths.map(p => p.source.id)).toEqual([group.id]);
  });
  it("removes one owner path while preserving another and never mutates the snapshot", () => {
    const s = structuredClone(cleanProjectFixture); const serialized = JSON.stringify(s);
    const ownership = s.edges.find(e => e.type === "OWNS")!;
    const result = simulateRemoval(s, [ownership.id]);
    expect(result.removedPaths.some(p => p.steps.some(step => step.edgeId === ownership.id))).toBe(true);
    expect(result.remainingPaths.some(p => p.steps.some(step => step.relationship === "FEDERATES_AS"))).toBe(true);
    expect(JSON.stringify(s)).toBe(serialized);
    expect(simulateRemoval(s, []).removedPaths).toEqual([]);
  });
  it("rejects unknown exclusions and cross-tenant objects; partial snapshots never imply complete elimination", () => {
    const s = structuredClone(cleanProjectFixture);
    expect(() => simulateRemoval(s, ["not-in-snapshot"])).toThrow();
    s.completion.status = "partial";
    expect(simulateRemoval(s, []).complete).toBe(false);
    s.nodes[0]!.tenantId = "other";
    expect(() => simulateRemoval(s, [])).toThrow();
  });
});

describe("timeline evidence and coverage", () => {
  it("correlates only successful same-object events inside the selected window, without asserting attribution", () => {
    const before = ledgerFixture(); before.scannedAt = "2026-08-25T10:00:00Z";
    const after = structuredClone(before); after.scannedAt = "2026-08-26T10:00:00Z"; after.nodes[0]!.label = "Renamed";
    const event = { id: "event", tenantId: TENANT, occurredAt: "2026-08-26T09:00:00Z", activity: "Update app", result: "success", actor: { id: "actor", kind: "user" as const }, targetIds: ["app"], sourceEndpoint: "/auditLogs/directoryAudits" };
    after.auditEvents = [event, { ...event, id: "failed", result: "failure" }, { ...event, id: "old", occurredAt: before.scannedAt }, { ...event, id: "unrelated", targetIds: ["other"] }];
    const row = snapshotTimeline(before, after).changes[0]!;
    expect(row.auditCandidates.map(e => e.id)).toEqual(["event"]);
    expect(row.attribution).toContain("do not prove");
    after.auditEvents = [];
    expect(snapshotTimeline(before, after).changes[0]!.attribution).toContain("Actor unknown");
    after.auditEvents = [{ ...event, tenantId: "other" }];
    expect(() => snapshotTimeline(before, after)).toThrow("one tenant");
  });
  it("legacy coverage remains unknown, even when an endpoint was recorded", () => {
    expect(coverageMatrix(ledgerFixture()).every(c => c.state === "unknown")).toBe(true);
  });
});

describe("synthetic rule lab", () => {
  const base = { schemaVersion: 1, fixture: "clean-project-v1", name: "Control paths", removeEdgeIds: [], expectations: [{ ruleId: "ERE-IAM-001", version: 1, minimum: 1, maximum: 100 }] };
  it("replays a positive case and nearby negative control case with inspectable evidence", () => {
    const positive = replayRuleLabCase(base); expect(positive.passed).toBe(true);
    expect(positive.results[0]!.findings[0]!.sourceEndpoints.length).toBeGreaterThan(0);
    const removeEdgeIds = cleanProjectFixture.edges.filter(e => ["OWNS", "FEDERATES_AS"].includes(e.type)).map(e => e.id);
    expect(replayRuleLabCase({ ...base, removeEdgeIds, expectations: [{ ruleId: "ERE-IAM-001", version: 1, minimum: 0, maximum: 0 }] }).passed).toBe(true);
    expect(replayRuleLabCase({ ...base, removeEdgeIds }).passed).toBe(false);
  });
  it("rejects version drift, tenant data, unknown edges and executable fields", () => {
    for (const patch of [{ tenantId: TENANT }, { code: "process.exit()" }, { removeEdgeIds: ["unknown"] }, { expectations: [{ ruleId: "ERE-IAM-001", version: 99, minimum: 0, maximum: 1 }] }]) expect(() => parseRuleLabCase({ ...base, ...patch })).toThrow();
  });
});

it("correlates federation changes with native credential and parent IDs, never an unrelated parent", () => {
  const before = structuredClone(cleanProjectFixture);
  before.scannedAt = "2026-08-25T10:00:00Z";
  const after = structuredClone(before); after.scannedAt = "2026-08-26T10:00:00Z";
  const trust = after.nodes.find(n => n.kind === "federatedCredential")!;
  trust.metadata!.subject = "repo:synthetic/changed";
  const event = { id: "parent-event", tenantId: TENANT, occurredAt: "2026-08-26T09:00:00Z", activity: "Update trust", result: "success", actor: { id: "actor", kind: "user" as const }, targetIds: [String(trust.metadata!.parentId)], sourceEndpoint: "/auditLogs/directoryAudits" };
  after.auditEvents = [event, { ...event, id: "credential-event", targetIds: [String(trust.metadata!.credentialId)] }, { ...event, id: "unrelated", targetIds: ["different-parent"] }].map(e => ({ ...e, tenantId: after.tenant.tenantId }));
  const change = snapshotTimeline(before, after).changes.find(c => c.id === trust.id)!;
  expect(change.auditCandidates.map(e => e.id)).toEqual(["parent-event", "credential-event"]);
  expect(change.attribution).toContain("do not prove");
});
