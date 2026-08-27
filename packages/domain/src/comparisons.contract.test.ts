import { describe, expect, it } from "vitest";
import { compareSnapshots } from "./comparisons";
import { TENANT, edge, node, snapshot, type EdgeOverrides } from "./test-support";
import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "./types";

const BEFORE_AT = "2026-08-01T00:00:00.000Z";
const AFTER_AT = "2026-08-02T00:00:00.000Z";

const person = () => node({ id: "user-1", kind: "user", label: "Avery Analyst", ownerIds: [] });
const app = () => node({ id: "sp-1", kind: "servicePrincipal", label: "Expense Reporter" });
const link = (overrides = {}) => edge("CAN_CALL_AS_APP", person(), app(), { id: "edge-1", evidence: { sourceRecordIds: ["rec-1"] }, ...overrides });

const before = (nodes: DirectoryNode[], edges: RelationshipEdge[]): TenantSnapshot =>
  snapshot(nodes, edges, { id: "before", scannedAt: BEFORE_AT });
const after = (nodes: DirectoryNode[], edges: RelationshipEdge[]): TenantSnapshot =>
  snapshot(nodes, edges, { id: "after", scannedAt: AFTER_AT });

describe("comparison guards", () => {
  it("validates the tenant boundary of the older snapshot as well as the newer one", () => {
    const tainted = snapshot([{ ...person(), tenantId: "other" }], [], { id: "before", scannedAt: BEFORE_AT });
    expect(() => compareSnapshots(tainted, after([person()], []))).toThrow(/exactly one tenant/);
  });

  it("validates the tenant boundary of the newer snapshot", () => {
    const tainted = snapshot([{ ...person(), tenantId: "other" }], [], { id: "after", scannedAt: AFTER_AT });
    expect(() => compareSnapshots(before([person()], []), tainted)).toThrow(/exactly one tenant/);
  });

  it("rejects a tainted edge on either side", () => {
    const taintedEdge = { ...link(), tenantId: "other" };
    expect(() => compareSnapshots(before([person(), app()], [taintedEdge]), after([person(), app()], []))).toThrow(/exactly one tenant/);
    expect(() => compareSnapshots(before([person(), app()], []), after([person(), app()], [taintedEdge]))).toThrow(/exactly one tenant/);
  });

  it("carries the tenant and both snapshot envelopes onto the diff", () => {
    const diff = compareSnapshots(before([person()], []), after([person()], []));
    expect(diff).toMatchObject({
      tenantId: TENANT, beforeSnapshotId: "before", afterSnapshotId: "after",
      beforeScannedAt: BEFORE_AT, afterScannedAt: AFTER_AT,
    });
  });
});

describe("change wording", () => {
  it("describes an added object and an added relationship distinctly", () => {
    const diff = compareSnapshots(before([], []), after([person(), app()], [link()]));
    const object = diff.changes.find((change) => change.subject === "object")!;
    const relationship = diff.changes.find((change) => change.subject === "relationship")!;
    expect(object.detail).toBe("Object appeared in the newer snapshot.");
    expect(relationship.detail).toBe("Relationship appeared in the newer snapshot.");
    expect(object.kind).toBe("added");
    expect(relationship.kind).toBe("added");
  });

  it("describes a removed object and a removed relationship distinctly", () => {
    const diff = compareSnapshots(before([person(), app()], [link()]), after([], []));
    expect(diff.changes.find((change) => change.subject === "object")!.detail).toBe("Object is absent from the newer snapshot.");
    expect(diff.changes.find((change) => change.subject === "relationship")!.detail).toBe("Relationship is absent from the newer snapshot.");
    expect(diff.changes.every((change) => change.kind === "removed")).toBe(true);
  });

  it("describes a changed object and a changed relationship distinctly", () => {
    const diff = compareSnapshots(
      before([person(), app()], [link({ permissions: ["A"] })]),
      after([{ ...person(), label: "Renamed" }, app()], [link({ permissions: ["A", "B"] })]),
    );
    expect(diff.changes.find((change) => change.subject === "object")!.detail).toBe("Object metadata changed.");
    expect(diff.changes.find((change) => change.subject === "relationship")!.detail).toBe("Configured relationship data changed.");
  });

  it("labels an object change by its display name and a relationship change by its endpoints", () => {
    const diff = compareSnapshots(before([], []), after([person(), app()], [link()]));
    expect(diff.changes.find((change) => change.subject === "object")!.label).toBe("Avery Analyst");
    expect(diff.changes.find((change) => change.subject === "relationship")!.label).toBe("CAN_CALL_AS_APP: user-1 → sp-1");
  });

  it("carries the record identifier onto every change", () => {
    const diff = compareSnapshots(before([], []), after([person()], []));
    expect(diff.changes[0]!.id).toBe("user-1");
  });
});

describe("what counts as a change", () => {
  const compareNodes = (change: Partial<DirectoryNode>) =>
    compareSnapshots(before([person()], []), after([{ ...person(), ...change }], [])).counts.changed;

  it.each([
    ["label", { label: "Renamed" }],
    ["kind", { kind: "group" as const }],
    ["description", { description: "Different" }],
    ["appId", { appId: "new-app-id" }],
    ["publisher", { publisher: "Contoso" }],
    ["owner list", { ownerIds: ["owner-1"] }],
    ["credential", { credential: { status: "expired" as const, expiresAt: "2020-01-01T00:00:00.000Z" } }],
    ["risk", { risk: { level: "high" as const, reason: "Escalated." } }],
  ])("notices a changed %s", (_field, change) => {
    expect(compareNodes(change)).toBe(1);
  });

  it("ignores an owner list that only changed order", () => {
    const withOwners = { ...person(), ownerIds: ["a", "b"] };
    expect(compareSnapshots(before([withOwners], []), after([{ ...withOwners, ownerIds: ["b", "a"] }], [])).counts.changed).toBe(0);
  });

  it("notices an owner that was actually added or removed", () => {
    const withOwners = { ...person(), ownerIds: ["a", "b"] };
    expect(compareSnapshots(before([withOwners], []), after([{ ...withOwners, ownerIds: ["a"] }], [])).counts.changed).toBe(1);
    expect(compareSnapshots(before([withOwners], []), after([{ ...withOwners, ownerIds: ["a", "b", "c"] }], [])).counts.changed).toBe(1);
  });

  const compareEdges = (change: EdgeOverrides) =>
    compareSnapshots(before([person(), app()], [link()]), after([person(), app()], [link(change)])).counts.changed;

  it("notices a changed relationship type", () => {
    const records = { sourceRecordIds: ["rec-1"] };
    const asApp = edge("CAN_CALL_AS_APP", person(), app(), { id: "edge-1", evidence: records });
    const delegated = edge("CAN_CALL_DELEGATED", person(), app(), { id: "edge-1", evidence: records });
    expect(compareSnapshots(before([person(), app()], [asApp]), after([person(), app()], [delegated])).counts.changed).toBe(1);
  });

  it.each([
    ["permission list", { permissions: ["Directory.Read.All"] }],
    ["evidence endpoint", { evidence: { sourceRecordIds: ["rec-1"], sourceEndpoint: "/different" } }],
    ["source record list", { evidence: { sourceRecordIds: ["rec-2"] } }],
    ["completeness", { evidence: { sourceRecordIds: ["rec-1"], completeness: "unresolved" as const } }],
    ["configured flag", { evidence: { sourceRecordIds: ["rec-1"], configured: false } }],
  ])("notices a changed %s", (_field, change) => {
    expect(compareEdges(change)).toBe(1);
  });

  it("ignores permission and record ordering, which Graph does not guarantee", () => {
    const diff = compareSnapshots(
      before([person(), app()], [link({ permissions: ["A", "B"], evidence: { sourceRecordIds: ["r1", "r2"] } })]),
      after([person(), app()], [link({ permissions: ["B", "A"], evidence: { sourceRecordIds: ["r2", "r1"] } })]),
    );
    expect(diff.changes).toEqual([]);
  });

  it("ignores the scan timestamp, which changes on every scan", () => {
    const diff = compareSnapshots(
      before([person(), app()], [link({ evidence: { sourceRecordIds: ["rec-1"], scannedAt: BEFORE_AT } })]),
      after([person(), app()], [link({ evidence: { sourceRecordIds: ["rec-1"], scannedAt: AFTER_AT } })]),
    );
    expect(diff.changes).toEqual([]);
  });
});

describe("counts and ordering", () => {
  it("counts each kind of change separately and totals the change list", () => {
    const gone = node({ id: "sp-gone", kind: "servicePrincipal", label: "Retired" });
    const fresh = node({ id: "sp-new", kind: "servicePrincipal", label: "Arrived" });
    const diff = compareSnapshots(
      before([person(), gone], []),
      after([{ ...person(), label: "Renamed" }, fresh], []),
    );
    expect(diff.counts).toEqual({ added: 1, removed: 1, changed: 1 });
    expect(diff.changes).toHaveLength(3);
  });

  it("reports no change and zero counts for an unchanged snapshot", () => {
    const diff = compareSnapshots(before([person(), app()], [link()]), after([person(), app()], [link()]));
    expect(diff.changes).toEqual([]);
    expect(diff.counts).toEqual({ added: 0, removed: 0, changed: 0 });
  });

  it("groups objects before relationships and sorts within each group", () => {
    const zed = node({ id: "z", kind: "user", label: "Zed" });
    const abe = node({ id: "a", kind: "user", label: "Abe" });
    const diff = compareSnapshots(before([], []), after([zed, abe, app()], [link()]));
    const subjects = diff.changes.map((change) => change.subject);
    expect(subjects.lastIndexOf("object")).toBeLessThan(subjects.indexOf("relationship"));
    const objectLabels = diff.changes.filter((change) => change.subject === "object").map((change) => change.label);
    expect(objectLabels).toEqual([...objectLabels].sort());
  });

  it("compares both objects and relationships, not just one of them", () => {
    const diff = compareSnapshots(before([], []), after([person(), app()], [link()]));
    expect(diff.changes.filter((change) => change.subject === "object")).toHaveLength(2);
    expect(diff.changes.filter((change) => change.subject === "relationship")).toHaveLength(1);
  });
});
