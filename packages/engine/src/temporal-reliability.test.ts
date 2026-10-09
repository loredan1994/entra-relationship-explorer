import { expect, it } from "vitest";
import { compileSnapshot } from "./model";
import { intersectWindows, reconstructPaths } from "./temporal";
import { edge, query, snapshot } from "./test-support";

const instant = (hour: number) => `2026-10-08T${String(hour).padStart(2, "0")}:00:00.000Z`;
const q = { tenantId: query.tenantId, kind: "control-path" as const, principalId: "person", resourceId: "resource" };
function source() { return snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")]); }

it.each([9, 10])("disproves coexistence when a partial start at %i meets or exceeds another exclusive end", start => {
  const s = source();
  s.edges[0]!.validity = { startsAt: instant(start), endsAt: null };
  s.edges[1]!.validity = { startsAt: null, endsAt: instant(9) };
  expect(reconstructPaths([compileSnapshot(s)], q)).toMatchObject({ verdict: "refuted", paths: [{ validity: "disjoint", sourceValidity: null }] });
});

it("combines partial bounds without claiming that the complete validity window is known", () => {
  const s = source();
  s.edges[0]!.validity = { startsAt: instant(8), endsAt: null };
  s.edges[1]!.validity = { startsAt: null, endsAt: instant(9) };
  expect(reconstructPaths([compileSnapshot(s)], q).paths).toMatchObject([{ validity: "unknown", sourceValidity: { startsAt: instant(8), endsAt: instant(9) } }]);
  s.edges[1]!.validity = { startsAt: instant(9), endsAt: null };
  expect(reconstructPaths([compileSnapshot(s)], q).paths).toMatchObject([{ validity: "unknown", sourceValidity: null }]);
  s.edges[0]!.validity = { startsAt: null, endsAt: instant(8) };
  s.edges[1]!.validity = { startsAt: null, endsAt: instant(9) };
  expect(reconstructPaths([compileSnapshot(s)], q).paths).toMatchObject([{ validity: "unknown", sourceValidity: null }]);
});

it("applies the tightest bound from every edge, including partial records beside a full interval", () => {
  const s = snapshot([edge("owner", "person", "blueprint", "OWNS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"), edge("grant", "client", "resource")]);
  s.edges[0]!.validity = { startsAt: instant(1), endsAt: instant(12) };
  s.edges[1]!.validity = { startsAt: instant(5), endsAt: null };
  s.edges[2]!.validity = { startsAt: null, endsAt: instant(8) };
  expect(reconstructPaths([compileSnapshot(s)], q).paths).toMatchObject([{ validity: "unknown", sourceValidity: { startsAt: instant(5), endsAt: instant(8) } }]);
  s.edges[2]!.validity!.endsAt = instant(4);
  expect(reconstructPaths([compileSnapshot(s)], q).verdict).toBe("refuted");
});

it.each(["startsAt", "endsAt"] as const)("rejects an invalid one-sided %s rather than discarding it", field => {
  const s = source();
  s.edges[0]!.validity = { startsAt: null, endsAt: null, [field]: "invalid-date" };
  expect(() => reconstructPaths([compileSnapshot(s)], q)).toThrow("Invalid engine timestamp.");
});

it("rejects an invalid complete interval before combining it with other evidence", () => {
  const s = source(); s.edges[0]!.validity = { startsAt: instant(9), endsAt: instant(9) };
  expect(() => reconstructPaths([compileSnapshot(s)], q)).toThrow("Intervals must have a start before their exclusive end.");
});

it("orders collection instants by time and merges equivalent timezone representations", () => {
  const first = source(); first.id = "first"; first.scannedAt = "2026-10-08T12:00:00+05:00";
  const later = source(); later.id = "later"; later.scannedAt = "2026-10-08T08:00:00Z";
  const equivalent = source(); equivalent.id = "equivalent"; equivalent.scannedAt = "2026-10-08T10:00:00+03:00";
  const result = reconstructPaths([later, equivalent, first].map(compileSnapshot), q);
  expect(result.paths).toHaveLength(1);
  expect(result.paths[0]).toMatchObject({
    snapshots: ["equivalent", "first", "later"],
    collectedInstants: [instant(7), instant(8)],
    uncertainIntervals: [{ startsAt: instant(7), endsAt: instant(8) }],
  });
});

it("rejects one invalid interval among otherwise valid intervals", () => {
  expect(() => intersectWindows([
    { startsAt: instant(1), endsAt: instant(5) },
    { startsAt: instant(4), endsAt: instant(3) },
  ])).toThrow("Intervals must have a start before their exclusive end.");
});

it("reports exhausted temporal path search even when it found some witnesses", () => {
  const s = snapshot(Array.from({ length: 129 }, (_, i) => edge(`grant-${i}`, "client", "resource")));
  const result = reconstructPaths([compileSnapshot(s)], query);
  expect(result).toMatchObject({ verdict: "unknown", missing: ["budget:search"], limits: { exhausted: true, steps: 129, maxSteps: 50_000 } });
  expect(result.paths).toHaveLength(128);
});

it("retains a complete collected witness while disclosing partial inventory coverage", () => {
  const s = source(); s.completion.collectors!.find(c => c.id === "federatedIdentityCredentials")!.state = "partial";
  expect(reconstructPaths([compileSnapshot(s)], q)).toMatchObject({ verdict: "supported", missing: ["coverage:federatedIdentityCredentials"] });
});

it("sorts distinct paths independently of which retained snapshot first records them", () => {
  const first = snapshot([edge("z-path", "client", "resource")]); first.id = "first"; first.scannedAt = instant(7);
  const second = snapshot([edge("a-path", "client", "resource")]); second.id = "second"; second.scannedAt = instant(8);
  const result = reconstructPaths([compileSnapshot(second), compileSnapshot(first)], query);
  expect(result.paths.map(path => path.edges)).toEqual([["a-path"], ["z-path"]]);
});

it("explains why observations without a path cannot establish coexistence between scans", () => {
  expect(reconstructPaths([compileSnapshot(snapshot([]))], query)).toMatchObject({ verdict: "unknown", paths: [], missing: ["path-coexistence-between-observations"] });
});
