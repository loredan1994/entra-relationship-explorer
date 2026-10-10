import { expect, it } from "vitest";
import { analyzeTenantIntelligence } from "./intelligence";
import { edge, node, snapshot } from "./test-support";

it("keeps relationship-list iteration linear for a large ownership fan-out", () => {
  const owner = node({ id: "owner", kind: "user", label: "Synthetic owner" });
  const targets = Array.from({ length: 1_000 }, (_, i) => node({ id: `workload-${i}`, kind: "servicePrincipal", label: `Workload ${i}`, ownerIds: [owner.id] }));
  const source = snapshot([owner, ...targets], targets.map((target, i) => edge("OWNS", owner, target, { id: `ownership-${i}` })));
  const sourceBefore = structuredClone(source);
  const ids = new Set(source.edges.map(item => item.id));
  // Count relationship references crossing array iterators rather than wall time:
  // rebuilding every prefix must fail on both slow CI runners and fast laptops.
  const original = Array.prototype[Symbol.iterator];
  let visits = 0;
  Array.prototype[Symbol.iterator] = function (this: unknown[]) {
    const iterator = original.call(this);
    const next = iterator.next.bind(iterator);
    iterator.next = () => {
      const result = next();
      const item = result.value as { edge?: { id?: string } } | undefined;
      if (item?.edge?.id && ids.has(item.edge.id)) visits++;
      return result;
    };
    return iterator;
  };
  let result;
  try { result = analyzeTenantIntelligence(source); }
  finally { Array.prototype[Symbol.iterator] = original; }
  expect(result.paths).toEqual([]);
  expect(result.pathAnalysis).toMatchObject({ traversals: 1_000, truncated: false });
  expect(source).toEqual(sourceBefore);
  expect(visits).toBeLessThan(20 * source.edges.length);
});

it("retains distinct branches and exact edge evidence when indexing repeated sources", () => {
  const owner = node({ id: "owner", kind: "user", label: "Owner" });
  const left = node({ id: "left", kind: "servicePrincipal", label: "Left", ownerIds: [owner.id] });
  const right = node({ id: "right", kind: "servicePrincipal", label: "Right", ownerIds: [owner.id] });
  const resource = node({ id: "resource", kind: "servicePrincipal", label: "Resource", ownerIds: [owner.id] });
  const source = snapshot([owner, left, right, resource], [
    edge("OWNS", owner, left, { id: "own-left" }),
    edge("CAN_CALL_AS_APP", left, resource, { id: "grant-left", permissions: ["Mail.ReadWrite"] }),
    edge("OWNS", owner, right, { id: "own-right" }),
    edge("CAN_CALL_AS_APP", right, resource, { id: "grant-right", permissions: ["Mail.ReadWrite"] }),
  ]);
  const result = analyzeTenantIntelligence(source);
  expect(result.pathAnalysis).toMatchObject({ traversals: 4, truncated: false });
  expect(result.paths.map(path => path.steps.map(step => step.edgeId))).toEqual([
    ["own-left", "grant-left"], ["own-right", "grant-right"],
  ]);
  expect(result.paths.every(path => path.steps.every(step => step.sourceEndpoint === "/test-endpoint"))).toBe(true);
});
