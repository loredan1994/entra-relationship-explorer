import { describe, expect, it } from "vitest";
import { toAttackFlow } from "./attack-flow";
import { compareSnapshots } from "./comparisons";
import { analyzeTenantIntelligence } from "./intelligence";
import { assertTenantBoundary, boundedNeighborhood, connectedNodes, filterRelationships, nodeById, relationships } from "./queries";
import { TENANT, edge, node, snapshot } from "./test-support";

const person = () => node({ id: "user-1", kind: "user", label: "Avery Analyst" });
const app = () => node({ id: "sp-1", kind: "servicePrincipal", label: "Expense Reporter" });
const api = () => node({ id: "sp-2", kind: "servicePrincipal", label: "Microsoft Graph" });

describe("relationship resolution", () => {
  it("drops an edge whose source or target is missing from the node list", () => {
    const a = person();
    const b = app();
    const orphanSource = edge("OWNS", { ...a, id: "ghost" }, b);
    const orphanTarget = edge("OWNS", a, { ...b, id: "ghost-target" });
    const resolved = edge("OWNS", a, b);
    expect(relationships(snapshot([a, b], [orphanSource, orphanTarget, resolved]))).toHaveLength(1);
  });

  it("pairs each edge with its resolved source and target objects", () => {
    const a = person();
    const b = app();
    const view = relationships(snapshot([a, b], [edge("OWNS", a, b)]))[0]!;
    expect(view.source.label).toBe("Avery Analyst");
    expect(view.target.label).toBe("Expense Reporter");
  });
});

describe("filtering", () => {
  const a = person();
  const b = app();
  const c = api();
  const owns = edge("OWNS", a, b, { plainLabel: "Owns" });
  const calls = edge("CAN_CALL_AS_APP", b, c, { permissions: ["Directory.Read.All"], plainLabel: "Can call" });
  const snap = () => snapshot([a, b, c], [owns, calls]);

  it("returns everything when no filter is supplied", () => {
    expect(filterRelationships(snap(), {})).toHaveLength(2);
  });

  it("keeps an edge when either endpoint matches a requested kind", () => {
    expect(filterRelationships(snap(), { nodeKinds: ["user"] }).map((view) => view.edge.id)).toEqual([owns.id]);
    expect(filterRelationships(snap(), { nodeKinds: ["servicePrincipal"] })).toHaveLength(2);
  });

  it("ignores an empty kind list rather than filtering everything out", () => {
    expect(filterRelationships(snap(), { nodeKinds: [] })).toHaveLength(2);
    expect(filterRelationships(snap(), { relationshipTypes: [] })).toHaveLength(2);
  });

  it("keeps only the requested relationship types", () => {
    expect(filterRelationships(snap(), { relationshipTypes: ["CAN_CALL_AS_APP"] }).map((view) => view.edge.id)).toEqual([calls.id]);
  });

  it("matches a free-text query against labels, relationship wording, and permissions", () => {
    expect(filterRelationships(snap(), { query: "avery" })).toHaveLength(1);
    expect(filterRelationships(snap(), { query: "can call" })).toHaveLength(1);
    expect(filterRelationships(snap(), { query: "directory.read.all" })).toHaveLength(1);
    expect(filterRelationships(snap(), { query: "nothing here" })).toHaveLength(0);
  });

  it("keeps each searchable field a separate word rather than running them together", () => {
    // "Avery Analyst" ends one field and "Expense Reporter" starts the next; a query that
    // spans the two must not match, or search would invent phrases nobody typed.
    expect(filterRelationships(snap(), { query: "analystexpense" })).toEqual([]);
    expect(filterRelationships(snap(), { query: "analyst expense" })).toHaveLength(1);
  });

  it("ignores case and surrounding whitespace in the query", () => {
    expect(filterRelationships(snap(), { query: "  AVERY  " })).toHaveLength(1);
  });

  it("treats a whitespace-only query as no query at all", () => {
    expect(filterRelationships(snap(), { query: "   " })).toHaveLength(2);
  });

  it("requires every supplied filter to match at once", () => {
    expect(filterRelationships(snap(), { query: "avery", relationshipTypes: ["CAN_CALL_AS_APP"] })).toHaveLength(0);
    expect(filterRelationships(snap(), { query: "avery", relationshipTypes: ["OWNS"] })).toHaveLength(1);
  });
});

describe("node lookup and collection", () => {
  it("collects each distinct endpoint of the supplied views exactly once", () => {
    const a = person();
    const b = app();
    const c = api();
    const views = relationships(snapshot([a, b, c], [edge("OWNS", a, b), edge("CAN_CALL_AS_APP", b, c)]));
    expect(connectedNodes(views).map((item) => item.id)).toEqual([a.id, b.id, c.id]);
  });

  it("returns nothing for an empty view list", () => {
    expect(connectedNodes([])).toEqual([]);
  });

  it("finds a node by id and reports nothing for an unknown one", () => {
    const a = person();
    const snap = snapshot([a], []);
    expect(nodeById(snap, a.id)?.label).toBe("Avery Analyst");
    expect(nodeById(snap, "absent")).toBeUndefined();
  });
});

describe("bounded neighborhood", () => {
  const a = person();
  const b = app();
  const c = api();
  const snap = () => snapshot([a, b, c], [edge("OWNS", a, b), edge("CAN_CALL_AS_APP", b, c)]);

  it("returns the focus node with the relationships on either side of it", () => {
    const result = boundedNeighborhood(snap(), b.id);
    expect(result.nodes.map((item) => item.id).sort()).toEqual([a.id, b.id, c.id].sort());
    expect(result.edges).toHaveLength(2);
    expect(result.truncated).toBe(false);
  });

  it("returns an empty neighborhood for an unknown focus node", () => {
    expect(boundedNeighborhood(snap(), "absent")).toEqual({ nodes: [], edges: [], truncated: false });
  });

  it("returns just the focus node when it has no relationships", () => {
    const lonely = node({ id: "lonely", kind: "user", label: "Nobody" });
    const result = boundedNeighborhood(snapshot([lonely], []), lonely.id);
    expect(result.nodes.map((item) => item.id)).toEqual([lonely.id]);
    expect(result.edges).toEqual([]);
  });

  it("stops adding neighbors at the node budget and says it truncated", () => {
    const result = boundedNeighborhood(snap(), b.id, 2);
    expect(result.nodes).toHaveLength(2);
    expect(result.truncated).toBe(true);
  });

  it("leaves out a relationship that does not touch the focus node", () => {
    const outsider = node({ id: "outsider-1", kind: "user", label: "Outsider" });
    const other = node({ id: "outsider-2", kind: "application", label: "Elsewhere", ownerIds: [] });
    const wide = snapshot([a, b, c, outsider, other], [
      edge("OWNS", a, b),
      edge("CAN_CALL_AS_APP", b, c),
      edge("OWNS", outsider, other),
    ]);
    const result = boundedNeighborhood(wide, b.id);
    expect(result.nodes.map((item) => item.id).sort()).toEqual([a.id, b.id, c.id].sort());
    expect(result.edges).toHaveLength(2);
  });

  it("returns only nodes it could actually resolve", () => {
    const result = boundedNeighborhood(snap(), b.id);
    expect(result.nodes.every(Boolean)).toBe(true);
    for (const item of result.nodes) expect(typeof item.id).toBe("string");
  });

  it("rejects a node budget outside the supported range", () => {
    for (const limit of [0, -1, 501, 2.5, Number.NaN]) {
      expect(() => boundedNeighborhood(snap(), b.id, limit), String(limit))
        .toThrow("Visible graph node limit must be between 1 and 500.");
    }
    expect(() => boundedNeighborhood(snap(), b.id, 1)).not.toThrow();
    expect(() => boundedNeighborhood(snap(), b.id, 500)).not.toThrow();
  });
});

describe("tenant boundary", () => {
  it("rejects a node or an edge stamped with a different tenant", () => {
    const a = person();
    const b = app();
    expect(() => assertTenantBoundary(snapshot([{ ...a, tenantId: "other" }, b], []))).toThrow(/exactly one tenant/);
    expect(() => assertTenantBoundary(snapshot([a, b], [{ ...edge("OWNS", a, b), tenantId: "other" }]))).toThrow(/exactly one tenant/);
  });

  it("accepts a snapshot whose records all carry the declared tenant", () => {
    const a = person();
    const b = app();
    expect(() => assertTenantBoundary(snapshot([a, b], [edge("OWNS", a, b)]))).not.toThrow();
  });
});

describe("snapshot comparison", () => {
  const a = person();
  const b = app();
  const base = () => snapshot([a, b], [edge("OWNS", a, b, { id: "edge-1" })], { id: "before", scannedAt: "2026-08-01T00:00:00.000Z" });

  it("refuses to compare snapshots from different tenants", () => {
    const other = snapshot([{ ...a, tenantId: "22222222-2222-4222-8222-222222222222" }], [], {
      id: "after",
      scannedAt: "2026-08-02T00:00:00.000Z",
      tenant: { tenantId: "22222222-2222-4222-8222-222222222222", tenantLabel: "Other" },
    });
    expect(() => compareSnapshots(base(), other)).toThrow(/different tenants/);
  });

  it("refuses a comparison ordered from newer to older", () => {
    const older = snapshot([a, b], [], { id: "older", scannedAt: "2026-07-01T00:00:00.000Z" });
    expect(() => compareSnapshots(base(), older)).toThrow(/ordered from older to newer/);
  });

  it("accepts two snapshots captured at the same instant", () => {
    const same = snapshot([a, b], [], { id: "same", scannedAt: "2026-08-01T00:00:00.000Z" });
    expect(() => compareSnapshots(base(), same)).not.toThrow();
  });

  it("validates the tenant boundary of both sides before comparing", () => {
    const tainted = snapshot([{ ...a, tenantId: "other" }], [], { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" });
    expect(() => compareSnapshots(base(), tainted)).toThrow(/exactly one tenant/);
  });

  it("reports added, removed, and changed objects and relationships", () => {
    const c = api();
    const after = snapshot(
      [{ ...a, label: "Avery Renamed" }, c],
      [edge("OWNS", a, c, { id: "edge-2" })],
      { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" },
    );
    const diff = compareSnapshots(base(), after);
    expect(diff.counts).toEqual({ added: 2, removed: 2, changed: 1 });
    expect(diff.beforeSnapshotId).toBe("before");
    expect(diff.afterSnapshotId).toBe("after");
    expect(diff.tenantId).toBe(TENANT);
  });

  it("reports no change between two identical snapshots", () => {
    // Provenance is part of the fingerprint, so both sides must cite the same records.
    const same = { id: "edge-1", evidence: { sourceRecordIds: ["rec-1"] } };
    const before = snapshot([a, b], [edge("OWNS", a, b, same)], { id: "before", scannedAt: "2026-08-01T00:00:00.000Z" });
    const after = snapshot([a, b], [edge("OWNS", a, b, same)], { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" });
    const diff = compareSnapshots(before, after);
    expect(diff.changes).toEqual([]);
    expect(diff.counts).toEqual({ added: 0, removed: 0, changed: 0 });
  });

  it("ignores owner and permission ordering, which Graph does not guarantee", () => {
    const records = { sourceRecordIds: ["rec-1"] };
    const before = snapshot([{ ...a, ownerIds: ["x", "y"] }], [edge("CAN_CALL_AS_APP", a, b, { id: "e", permissions: ["A", "B"], evidence: records })], { id: "before", scannedAt: "2026-08-01T00:00:00.000Z" });
    const after = snapshot([{ ...a, ownerIds: ["y", "x"] }], [edge("CAN_CALL_AS_APP", a, b, { id: "e", permissions: ["B", "A"], evidence: records })], { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" });
    expect(compareSnapshots(before, after).changes).toEqual([]);
  });

  it("notices a permission that was actually added", () => {
    const records = { sourceRecordIds: ["rec-1"] };
    const before = snapshot([a, b], [edge("CAN_CALL_AS_APP", a, b, { id: "e", permissions: ["A"], evidence: records })], { id: "before", scannedAt: "2026-08-01T00:00:00.000Z" });
    const after = snapshot([a, b], [edge("CAN_CALL_AS_APP", a, b, { id: "e", permissions: ["A", "B"], evidence: records })], { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" });
    const [change] = compareSnapshots(before, after).changes;
    expect(change).toMatchObject({ kind: "changed", subject: "relationship" });
    expect(change?.detail).toContain("Configured relationship data changed");
  });

  it("sorts changes deterministically", () => {
    const c = api();
    const after = snapshot([a, c], [], { id: "after", scannedAt: "2026-08-02T00:00:00.000Z" });
    const first = compareSnapshots(base(), after).changes.map((change) => change.id);
    const second = compareSnapshots(base(), after).changes.map((change) => change.id);
    expect(first).toEqual(second);
  });
});

describe("Attack Flow export", () => {
  function pathFrom() {
    const origin = node({ id: "user-1", kind: "user", label: "Avery" });
    const worker = node({ id: "sp-1", kind: "servicePrincipal", label: "Worker", metadata: { ownershipExpected: true } });
    const graph = node({ id: "sp-2", kind: "servicePrincipal", label: "Microsoft Graph" });
    const snap = snapshot([origin, worker, graph], [
      edge("OWNS", origin, worker),
      edge("CAN_CALL_AS_APP", worker, graph, { permissions: ["Directory.ReadWrite.All"] }),
    ], { id: "snapshot-export" });
    const path = analyzeTenantIntelligence(snap).paths.find((item) => item.steps.length === 2)!;
    return { snap, path };
  }

  it("refuses to export a path with no steps", () => {
    const { snap, path } = pathFrom();
    expect(() => toAttackFlow(snap, { ...path, steps: [] })).toThrow(/at least one attack step/);
  });

  it("emits a STIX bundle whose actions chain in order", () => {
    const { snap, path } = pathFrom();
    const bundle = toAttackFlow(snap, path);
    expect(bundle.type).toBe("bundle");
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);
    const actions = bundle.objects.filter((item) => item.type === "attack-action");
    expect(actions).toHaveLength(2);
    expect(actions[0]!.effect_refs).toEqual([actions[1]!.id]);
    expect(actions[1]!.effect_refs).toBeUndefined();
  });

  it("starts the flow at the first action and carries the MITRE references", () => {
    const { snap, path } = pathFrom();
    const flow = toAttackFlow(snap, path).objects.find((item) => item.type === "attack-flow")!;
    const actions = toAttackFlow(snap, path).objects.filter((item) => item.type === "attack-action");
    expect(flow.start_refs).toEqual([actions[0]!.id]);
    expect(flow.external_references).toEqual([
      { source_name: "MITRE ATT&CK", external_id: "T1098", description: "Account Manipulation" },
      { source_name: "MITRE ATT&CK", external_id: "T1078.004", description: "Valid Accounts: Cloud Accounts" },
    ]);
  });

  it("states plainly that the export is an inference, not observed exploitation", () => {
    const { snap, path } = pathFrom();
    const flow = toAttackFlow(snap, path).objects.find((item) => item.type === "attack-flow")!;
    expect(String(flow.description)).toContain("not evidence that exploitation occurred");
    expect(String(flow.description)).toContain(`Confidence: ${path.confidence}`);
  });

  it("keeps each action explainable with its evidence endpoint and object ids", () => {
    const { snap, path } = pathFrom();
    const action = toAttackFlow(snap, path).objects.find((item) => item.type === "attack-action")!;
    expect(String(action.description)).toContain("Evidence endpoint:");
    expect(String(action.description)).toContain(`Source object: ${path.steps[0]!.source.id}`);
    expect(String(action.description)).toContain(`Target object: ${path.steps[0]!.target.id}`);
    expect(String(action.description)).toContain("Evidence class: configured");
  });

  it("derives identifiers deterministically from the snapshot and path", () => {
    const { snap, path } = pathFrom();
    expect(toAttackFlow(snap, path)).toEqual(toAttackFlow(snap, path));
  });

  it("emits RFC 4122 version 4 variant identifiers", () => {
    const { snap, path } = pathFrom();
    for (const object of toAttackFlow(snap, path).objects) {
      expect(String(object.id)).toMatch(/^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    }
  });

  it("stamps every object with the snapshot scan time", () => {
    const { snap, path } = pathFrom();
    const timestamp = new Date(snap.scannedAt).toISOString();
    for (const object of toAttackFlow(snap, path).objects) {
      expect(object.created).toBe(timestamp);
      expect(object.modified).toBe(timestamp);
    }
  });
});
