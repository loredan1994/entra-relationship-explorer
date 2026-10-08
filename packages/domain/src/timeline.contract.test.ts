import { expect, it } from "vitest";
import { snapshotTimeline } from "./timeline";
import { node, edge, snapshot, TENANT } from "./test-support";
function pair() {
  const person = node({ id: "person", kind: "user", label: "Person" }); const app = node({ id: "app", kind: "application", label: "App" });
  const before = snapshot([person, app], [edge("OWNS", person, app, { id: "ownership" })], { scannedAt: "2026-08-25T10:00:00Z" });
  const after = structuredClone(before); after.scannedAt = "2026-08-26T10:00:00Z"; after.edges = [];
  return { before, after };
}
it("correlates removed relationship endpoints in an open-start, closed-end time window", () => {
  const { before, after } = pair();
  const event = { id: "event", tenantId: TENANT, occurredAt: after.scannedAt, activity: "Change", result: "SUCCESS", actor: { id: "actor", kind: "user" as const }, targetIds: ["unrelated", "person"], sourceEndpoint: "/auditLogs/directoryAudits" };
  after.auditEvents = [event, { ...event, id: "start", occurredAt: before.scannedAt }, { ...event, id: "after", occurredAt: "2026-08-26T10:00:00.001Z" }, { ...event, id: "invalid", occurredAt: "invalid" }, { ...event, id: "app", targetIds: ["app"] }, { ...event, id: "no-target", targetIds: [] }, { ...event, id: "failed", result: "failure" }];
  const row = snapshotTimeline(before, after).changes[0]!;
  expect(row.auditCandidates.map(e => e.id)).toEqual(["event", "app"]);
  expect(row.attribution).toBe("Related events share an object and time window; they do not prove the cause of this change.");
  delete after.auditEvents;
  expect(snapshotTimeline(before, after).changes[0]).toMatchObject({ auditCandidates: [], attribution: "Actor unknown: no matching directory audit evidence was collected." });
});
it("expands only valid federation identifiers on the changed object", () => {
  const { before, after } = pair(); before.edges = []; after.edges = [];
  const trust = node({ id: "trust", kind: "federatedCredential", label: "Trust", metadata: { parentId: "app", credentialId: "native" } });
  before.nodes.push(trust); after.nodes.push({ ...trust, label: "Changed", metadata: { parentId: "new-parent", credentialId: null } });
  before.nodes[0]!.metadata = { parentId: "not-federation" };
  const event = { id: "event", tenantId: TENANT, occurredAt: after.scannedAt, activity: "Change", result: "success", actor: { id: null, kind: "unknown" as const }, targetIds: ["native"], sourceEndpoint: "/auditLogs/directoryAudits" };
  after.auditEvents = [event, { ...event, id: "new-parent", targetIds: ["new-parent"] }, { ...event, id: "not-federation", targetIds: ["not-federation"] }];
  expect(snapshotTimeline(before, after).changes.find(c => c.id === "trust")!.auditCandidates.map(e => e.id)).toEqual(["event", "new-parent"]);
  trust.metadata = { parentId: "", credentialId: 1 }; delete after.nodes.at(-1)!.metadata;
  expect(snapshotTimeline(before, after).changes.find(c => c.id === "trust")!.auditCandidates).toEqual([]);
});

it("matches the exact relationship, keeps object/relationship IDs separate, and limits federation metadata to changed trusts", () => {
  const { before, after } = pair();
  const trust = node({ id: "unused-trust", kind: "federatedCredential", label: "Unchanged", metadata: { parentId: "unrelated-parent" } });
  before.nodes.push(trust); after.nodes.push(trust);
  const extra = edge("OWNS", before.nodes[0]!, before.nodes[1]!, { id: "person" }); before.edges.unshift(extra); after.edges = [extra];
  before.nodes[0]!.metadata = { parentId: "non-federation-parent" }; after.nodes[0]!.label = "Changed";
  const event = (id: string) => ({ id, tenantId: TENANT, occurredAt: after.scannedAt, activity: "Change", result: "success", actor: { id: null, kind: "unknown" as const }, targetIds: [id], sourceEndpoint: "/auditLogs/directoryAudits" });
  after.auditEvents = ["person", "app", "unrelated-parent", "non-federation-parent"].map(event);
  const result = snapshotTimeline(before, after);
  expect(result.changes.find(c => c.subject === "object")!.auditCandidates.map(e => e.id)).toEqual(["person"]);
  expect(result.changes.find(c => c.subject === "relationship")!.auditCandidates.map(e => e.id)).toEqual(["person", "app"]);
});

it("ignores empty federation metadata when audit records contain an empty target", () => {
  const trust = node({ id: "trust-empty", kind: "federatedCredential", label: "Trust", metadata: { parentId: "", credentialId: null } });
  const before = snapshot([trust], [], { scannedAt: "2026-08-25T00:00:00Z" }); const after = structuredClone(before); after.scannedAt = "2026-08-26T00:00:00Z"; after.nodes[0]!.label = "Changed";
  after.auditEvents = [{ id: "empty-target", tenantId: TENANT, occurredAt: after.scannedAt, activity: "Change", result: "success", actor: { id: null, kind: "unknown" }, targetIds: [""], sourceEndpoint: "/auditLogs/directoryAudits" }];
  expect(snapshotTimeline(before, after).changes[0]!.auditCandidates).toEqual([]);
});

it("does not attribute events from an unchanged relationship to a different changed relationship", () => {
  const { before, after } = pair();
  const other = node({ kind: "user", label: "Other" }); before.nodes.push(other); after.nodes.push(other);
  const unrelated = edge("OWNS", other, before.nodes[1]!, { id: "unchanged" }); before.edges.unshift(unrelated); after.edges = [unrelated];
  after.auditEvents = [{ id: "person-event", tenantId: TENANT, occurredAt: after.scannedAt, activity: "Change", result: "success", actor: { id: null, kind: "unknown" }, targetIds: ["person"], sourceEndpoint: "/auditLogs/directoryAudits" }];
  expect(snapshotTimeline(before, after).changes[0]!.auditCandidates.map(e => e.id)).toEqual(["person-event"]);
});
