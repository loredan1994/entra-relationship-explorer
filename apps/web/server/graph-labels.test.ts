import { expect, it } from "vitest";
import { cleanProjectFixture, relationships, type RelationshipType } from "@entra-explorer/domain";
import { layoutGraph } from "../components/graph-layout";

it.each<[RelationshipType, string]>([["OBSERVED_CALL", "successful sign-in"], ["GOVERNED_BY", "policy includes"]])("the canvas labels %s without claiming more than its evidence", (type, expected) => {
  const snapshot = structuredClone(cleanProjectFixture);
  snapshot.edges = [{ ...snapshot.edges[0]!, type, permissions: [] }];
  const views = relationships(snapshot);
  const graph = layoutGraph([views[0]!.source, views[0]!.target], views);
  expect(graph.edges[0]!.label.text).toBe(expected);
});
