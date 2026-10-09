import { expect, it } from "vitest";
import type { NodeKind, RelationshipType } from "@entra-explorer/domain";
import { compileSnapshot, createEvaluator, evaluateAuthorization, type AuthorizationQuery } from "./index";
import { validateQuery } from "./authorization";
import { edge, node, query, snapshot, TIME } from "./test-support";

// Declarative endpoint truth table: object names cannot replace directory types.
const kinds: NodeKind[] = ["application", "servicePrincipal", "managedIdentity", "user", "group", "directoryRole", "federatedCredential"];
it.each(kinds.flatMap(source => kinds.map(target => [source, target] as const)))("application grant types %s → %s", (source, target) => {
  const s = snapshot(); s.nodes.find(n => n.id === "client")!.kind = source; s.nodes.find(n => n.id === "resource")!.kind = target;
  const allowed = ["servicePrincipal", "managedIdentity"].includes(source) && target === "servicePrincipal";
  for (const kind of ["application-permission", "delegated-permission", "control-path"] as const) {
    s.edges[0]!.type = kind === "delegated-permission" ? "CAN_CALL_DELEGATED" : "CAN_CALL_AS_APP";
    s.edges[0]!.consent = { audience: "all-users", principalId: null };
    expect(evaluateAuthorization(compileSnapshot(s), { ...query, kind, userId: "person" }).verdict).toBe(allowed ? "supported" : "refuted");
  }
});
it.each(kinds.flatMap(source => kinds.map(target => [source, target] as const)))("ownership types %s → %s", (source, target) => {
  const s = snapshot([edge("owner", "client", "resource", "OWNS")]); s.nodes[0]!.kind = source; s.nodes[1]!.kind = target;
  const allowed = ["user", "servicePrincipal", "managedIdentity"].includes(source) && ["application", "servicePrincipal"].includes(target);
  expect(evaluateAuthorization(compileSnapshot(s), { ...query, kind: "ownership", permissionId: undefined }).verdict).toBe(allowed ? "supported" : "refuted");
});
it.each(["FEDERATES_AS", "INSTANTIATES_AS"] as const)("composes only typed %s control hops", type => {
  for (const source of kinds) for (const target of kinds) {
    const s = snapshot([edge("hop", "a", "b", type), edge("grant", "b", "resource")]); s.nodes.push(node("a", source), node("b", target));
    // A blueprint needs an instantiation step before a permission grant.
    if (target === "application") { s.edges[1] = edge("grant", "client", "resource"); s.edges.push(edge("instance", "b", "client", "INSTANTIATES_AS")); }
    const allowed = type === "FEDERATES_AS" ? source === "federatedCredential" && ["application", "managedIdentity"].includes(target) : source === "application" && ["servicePrincipal", "managedIdentity"].includes(target);
    expect(evaluateAuthorization(compileSnapshot(s), { ...query, principalId: "a", kind: "control-path" }).verdict).toBe(allowed ? "supported" : "refuted");
  }
});
it("assignment accepts a person or direct group, never a service identity or a non-app target", () => {
  for (const source of kinds) for (const target of kinds) {
    const s = snapshot([edge("assigned", "client", "resource", "ASSIGNED_TO")]); s.nodes[0]!.kind = source; s.nodes[1]!.kind = target;
    expect(evaluateAuthorization(compileSnapshot(s), { ...query, kind: "assignment", permissionId: undefined }).verdict).toBe(["user", "group"].includes(source) && target === "servicePrincipal" ? "supported" : "refuted");
  }
});
it("a recorded observation or unconfigured link never substitutes for a grant", () => {
  for (const type of ["CAN_CALL_AS_APP", "OWNS", "MEMBER_OF", "ASSIGNED_TO", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as RelationshipType[]) {
    const e = edge("observed", "client", "resource", type); e.evidence.configured = false;
    expect(evaluateAuthorization(compileSnapshot(snapshot([e])), query).paths).toEqual([]);
  }
});
it("bounds alternatives exactly and distinguishes paths, work and depth", () => {
  const m = compileSnapshot(snapshot([edge("a", "client", "resource"), edge("b", "client", "resource")]));
  expect(evaluateAuthorization(m, query, { maxPaths: 2, maxSteps: 2, maxDepth: 1 }).limits).toEqual({ maxPaths: 2, maxSteps: 2, maxDepth: 1, steps: 2, exhausted: false });
  const bounded = evaluateAuthorization(m, query, { maxPaths: 1, maxSteps: 10, maxDepth: 1 });
  expect(bounded.verdict).toBe("unknown"); expect(bounded.paths).toEqual([["a"]]); expect(bounded.missing).toEqual(["budget:search"]);
  expect(evaluateAuthorization(m, query, { maxPaths: 2, maxSteps: 1, maxDepth: 1 }).limits).toEqual({ maxPaths: 2, maxSteps: 1, maxDepth: 1, steps: 1, exhausted: true });
  const s = snapshot([edge("m1", "person", "team", "MEMBER_OF"), edge("m2", "team", "nested", "MEMBER_OF"), edge("cycle", "nested", "person", "MEMBER_OF")]);
  const q: AuthorizationQuery = { ...query, kind: "membership", principalId: "person", resourceId: "nested", permissionId: undefined };
  expect(evaluateAuthorization(compileSnapshot(s), q, { maxPaths: 2, maxSteps: 20, maxDepth: 2 }).paths).toEqual([["m1", "m2"]]);
  expect(evaluateAuthorization(compileSnapshot(s), q, { maxPaths: 2, maxSteps: 20, maxDepth: 1 }).verdict).toBe("unknown");
  s.edges = [s.edges[0]!]; q.resourceId = "team";
  expect(evaluateAuthorization(compileSnapshot(s), q, { maxPaths: 2, maxSteps: 20, maxDepth: 1 }).limits.exhausted).toBe(false);
});
it("does not use membership alone as a terminal app or role assignment", () => {
  const s = snapshot([edge("member", "person", "team", "MEMBER_OF")]);
  for (const kind of ["assignment", "active-role", "eligible-role"] as const) expect(evaluateAuthorization(compileSnapshot(s), { ...query, kind, principalId: "person", resourceId: "team", permissionId: undefined, directoryScopeId: "/" }).paths).toEqual([]);
});
it.each(["active-role", "eligible-role"] as const)("requires exact source scope for %s and permits direct group expansion", kind => {
  const e = edge("role", "team", "role", kind === "active-role" ? "ACTIVE_IN_ROLE" : "ELIGIBLE_FOR_ROLE");
  const s = snapshot([edge("member", "person", "team", "MEMBER_OF"), e]);
  const q = { ...query, kind, principalId: "person", resourceId: "role", permissionId: undefined, directoryScopeId: "/" };
  expect(evaluateAuthorization(compileSnapshot(s), q).missing).toEqual(["relationship:role:directory-scope"]);
  e.scope = { directoryScopeId: "/", objectId: null };
  expect(evaluateAuthorization(compileSnapshot(s), q).verdict).toBe("supported");
  s.nodes.find(n => n.id === "role")!.kind = "application";
  expect(evaluateAuthorization(compileSnapshot(s), q).verdict).toBe("refuted");
});
it("missing delegated audience and missing single-user identity are distinct unknowns", () => {
  const e = edge("consent", "client", "resource", "CAN_CALL_DELEGATED");
  const q = { ...query, kind: "delegated-permission" as const, userId: "person" };
  for (const consent of [undefined, { audience: "single-user" as const, principalId: null }, { audience: "unknown" as const, principalId: null }]) {
    e.consent = consent;
    const result = evaluateAuthorization(compileSnapshot(snapshot([e])), q);
    expect(result.verdict).toBe("unknown"); expect(result.missing).toContain("relationship:consent:consent-audience");
  }
});
it("cache replacement updates source provenance and collection times without leaking mutable state", () => {
  const s = snapshot(), cache = createEvaluator(compileSnapshot(s));
  const first = cache.evaluate(query).proof;
  expect(() => first.paths.push(["forged"])).toThrow();
  s.nodes[0]!.sourceEndpoint = "/servicePrincipals/client";
  expect(cache.replace(compileSnapshot(s))).toEqual({ invalidated: 1, retained: 0 });
  expect(cache.evaluate(query).proof).toEqual(evaluateAuthorization(compileSnapshot(s), query));
  s.scannedAt = "2026-10-09T12:00:00.000Z";
  expect(cache.replace(compileSnapshot(s)).invalidated).toBe(1);
  expect(cache.evaluate(query).proof.facts.find(f => f.id === "object:client")!.collectedAt).not.toBe(TIME);
  const b = { maxSteps: 1, maxDepth: 1, maxPaths: 1 };
  expect(cache.evaluate(query, b).reused).toBe(false); expect(cache.evaluate(query).reused).toBe(true);
  s.id = "new-snapshot-same-time"; s.nodes[0]!.label = "Cosmetic rename";
  expect(cache.replace(compileSnapshot(s))).toEqual({ invalidated: 0, retained: 2 });
  expect(cache.evaluate(query).proof.snapshotIds).toEqual([s.id]);
  delete s.nodes[0]!.sourceEndpoint;
  cache.replace(compileSnapshot(s)); expect(cache.evaluate(query).proof.facts.find(f => f.id === "object:client")!.sourceEndpoint).toBe("");
});
it("query schema enforces required identities and accepts exact identifier bounds", () => {
  for (const q of [null, false, 12, "query", { ...query, tenantId: "" }, { ...query, principalId: "" }, { ...query, kind: "other" }]) expect(() => validateQuery(q as AuthorizationQuery)).toThrow();
  expect(() => validateQuery({ ...query, resourceId: "r".repeat(500) })).not.toThrow();
  for (const key of ["permissionId", "userId", "directoryScopeId"]) expect(() => validateQuery({ ...query, [key]: "r".repeat(501) })).toThrow("Unknown or invalid authorization query fields.");
});
it("indexes derivation steps against the displayed canonical path order", () => {
  const s = snapshot([edge("a-long", "person", "blueprint", "OWNS"), edge("z-short", "person", "client", "OWNS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"), edge("grant", "client", "resource")]);
  const p = evaluateAuthorization(compileSnapshot(s), { ...query, principalId: "person", kind: "control-path" });
  expect(p.paths).toEqual([["a-long", "instance", "grant"], ["z-short", "grant"]]);
  for (const [i, path] of p.paths.entries()) for (const [j, id] of path.entries()) expect(p.derivation.find(step => step.id === `path:${i}:step:${j}`)!.inputs[0]).toBe(`relationship:${id}`);
});
it("ownership of the requested object is not itself a terminal API control grant", () => {
  const s = snapshot([edge("owner", "person", "blueprint", "OWNS")]);
  expect(evaluateAuthorization(compileSnapshot(s), { ...query, principalId: "person", resourceId: "blueprint", kind: "control-path", permissionId: undefined }).verdict).toBe("refuted");
});
it("cycles and a downstream API grant cannot extend a terminal permission or assignment", () => {
  const s = snapshot([edge("grant1", "client", "resource"), edge("grant2", "resource", "blueprint"), edge("return", "resource", "client")]);
  s.nodes.find(n => n.id === "blueprint")!.kind = "servicePrincipal";
  const m = compileSnapshot(s);
  for (const kind of ["application-permission", "control-path"] as const) {
    const proof = evaluateAuthorization(m, { ...query, kind, resourceId: "blueprint" });
    expect(proof.paths).toEqual([]); expect(proof.limits.steps).toBe(kind === "control-path" ? 1 : 0);
  }
  const membership = snapshot([edge("bad-target", "person", "client", "MEMBER_OF"), edge("self", "person", "person", "MEMBER_OF")]);
  expect(evaluateAuthorization(compileSnapshot(membership), { ...query, kind: "membership", principalId: "person", resourceId: "client", permissionId: undefined }).paths).toEqual([]);
});
it("matches a conflicting noncanonical source variant and ignores unrelated object conflicts", () => {
  const s = snapshot([edge("conflict", "client", "resource"), edge("conflict", "resource", "client")]);
  s.nodes.push(node("unrelated"), { ...node("unrelated"), kind: "group" });
  const p = evaluateAuthorization(compileSnapshot(s), { ...query, principalId: "resource", resourceId: "client" });
  expect(p.verdict).toBe("conflicting"); expect(p.conflicts.map(c => c.factId)).toEqual(["relationship:conflict"]);
});
it("reports exact missing facts and collection requirements for ownership and membership", () => {
  const s = snapshot(); s.completion.collectors = [];
  for (const [kind, collectors] of [["ownership", ["applications", "owners", "servicePrincipals"]], ["membership", ["groupMemberships", "usersAndGroups"]]] as const) {
    const result = evaluateAuthorization(compileSnapshot(s), { ...query, kind, principalId: "person", resourceId: "team", permissionId: undefined });
    expect(result.missing).toEqual(collectors.map(c => `coverage:${c}`));
  }
  const m = compileSnapshot(snapshot());
  expect(evaluateAuthorization(m, { ...query, principalId: "absent" }).missing).toEqual(["object:absent"]);
  const source = snapshot(); source.edges[0]!.evidence.sourceRecordIds = [];
  expect(evaluateAuthorization(compileSnapshot(source), query).missing).toEqual(["relationship:grant:complete-source"]);
  source.edges[0]!.evidence.sourceRecordIds = ["grant"]; delete source.edges[0]!.permissionIds;
  expect(evaluateAuthorization(compileSnapshot(source), query).missing).toEqual(["relationship:grant:permission-ids"]);
  const consent = edge("consent", "client", "resource", "CAN_CALL_DELEGATED"); consent.consent = { audience: "all-users", principalId: null };
  expect(evaluateAuthorization(compileSnapshot(snapshot([consent])), { ...query, kind: "delegated-permission" }).missing).toEqual(["query:user-context"]);
  const role = edge("role", "person", "role", "ACTIVE_IN_ROLE"); role.scope = { directoryScopeId: "/", objectId: null };
  expect(evaluateAuthorization(compileSnapshot(snapshot([role])), { ...query, kind: "active-role", principalId: "person", resourceId: "role", permissionId: undefined }).missing).toEqual(["query:directory-scope"]);
});
it("invalidates cached intermediate object types and relevant coverage, retaining unrelated changes", () => {
  const s = snapshot([edge("owner", "person", "client", "OWNS"), edge("grant", "client", "resource")]);
  const q = { ...query, principalId: "person", kind: "control-path" as const };
  const cache = createEvaluator(compileSnapshot(s)); cache.evaluate(q);
  s.nodes[0]!.kind = "application"; expect(cache.replace(compileSnapshot(s)).invalidated).toBe(1);
  expect(cache.evaluate(q).proof.verdict).toBe("refuted");
  s.completion.collectors!.find(c => c.id === "devices")!.state = "denied";
  expect(cache.replace(compileSnapshot(s))).toEqual({ invalidated: 0, retained: 1 });
  s.completion.collectors!.find(c => c.id === "owners")!.state = "denied";
  expect(cache.replace(compileSnapshot(s)).invalidated).toBe(1); expect(cache.evaluate(q).proof.verdict).toBe("unknown");
  expect(() => cache.evaluate({ ...q, tenantId: "foreign" })).toThrow("Cross-tenant query rejected.");
  expect(() => cache.evaluate({ ...q, kind: "invalid" } as unknown as AuthorizationQuery)).toThrow("Invalid authorization query.");
});
it("enforces resource-specific IDs and each named budget's maximum", () => {
  const m = compileSnapshot(snapshot());
  for (const kind of ["application-permission", "delegated-permission"] as const) expect(() => evaluateAuthorization(m, { ...query, kind, permissionId: "" })).toThrow("A resource-specific permission ID is required.");
  const maximum = { maxSteps: 1_000_000, maxPaths: 10_000, maxDepth: 32 };
  expect(evaluateAuthorization(m, query, maximum).limits.exhausted).toBe(false);
  for (const [key, label] of [["maxSteps", "steps"], ["maxPaths", "paths"], ["maxDepth", "depth"]] as const) for (const value of [0, maximum[key] + 1]) expect(() => evaluateAuthorization(m, query, { ...maximum, [key]: value })).toThrow(`Invalid ${label} budget.`);
});
it("administrative roles require a recorded user, group or service identity as principal", () => {
  for (const source of kinds) for (const target of kinds) for (const kind of ["active-role", "eligible-role"] as const) {
    const e = edge("assigned", "client", "resource", kind === "active-role" ? "ACTIVE_IN_ROLE" : "ELIGIBLE_FOR_ROLE"); e.scope = { directoryScopeId: "/", objectId: null };
    const s = snapshot([e]); s.nodes[0]!.kind = source; s.nodes[1]!.kind = target;
    expect(evaluateAuthorization(compileSnapshot(s), { ...query, kind, permissionId: undefined, directoryScopeId: "/" }).verdict).toBe(["user", "group", "servicePrincipal", "managedIdentity"].includes(source) && target === "directoryRole" ? "supported" : "refuted");
  }
});
it("rejects non-object values even when they expose valid query properties", () => {
  const fn = Object.assign(() => 1, query);
  expect(() => validateQuery(fn)).toThrow("Unknown or invalid authorization query fields.");
  expect(() => validateQuery(null as unknown as AuthorizationQuery)).toThrow("Unknown or invalid authorization query fields.");
});
