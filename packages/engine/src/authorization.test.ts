import { describe, expect, it } from "vitest";
import { canonical } from "./canonical";
import { compileSnapshot } from "./model";
import { createEvaluator, evaluateAuthorization } from "./authorization";
import { edge, node, query, snapshot } from "./test-support";

describe("typed authorization and reproducible proofs", () => {
  it("records a grant with exact resource-specific IDs and source provenance, never observed use", () => {
    const p = evaluateAuthorization(compileSnapshot(snapshot()), query);
    expect(p.verdict).toBe("supported"); expect(p.evidenceClass).toBe("configured");
    expect(p.paths).toEqual([["grant"]]);
    expect(p.facts.find(f => f.id === "relationship:grant")).toMatchObject({ sourceEndpoint: "/servicePrincipals/resource/appRoleAssignedTo", sourceObjectId: "client", targetObjectId: "resource", sourceRecordIds: ["grant"] });
    expect(p.derivation[0]!.inputs).toEqual(["relationship:grant"]);
    expect(p.missing).toEqual([]); expect(p.assumptions.join(" ")).toContain("not effective access");
  });
  it("canonicalizes reordered facts and deduplicates exact source records", () => {
    const s = snapshot([edge("z", "client", "resource"), edge("a", "client", "resource")]);
    const expected = canonical(evaluateAuthorization(compileSnapshot(s), query));
    s.nodes.reverse(); s.edges.reverse(); s.edges.push(structuredClone(s.edges[0]!)); s.completion.collectors!.reverse();
    expect(canonical(evaluateAuthorization(compileSnapshot(s), query))).toBe(expected);
    expect(Object.isFrozen(compileSnapshot(s).edges[0]!.evidence)).toBe(true);
  });
  it.each(["partial", "denied", "unavailable", "not-enabled", "unknown"] as const)("missing grants remain unknown with %s collection", state => {
    const s = snapshot([]); s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.state = state;
    const p = evaluateAuthorization(compileSnapshot(s), query); expect(p.verdict).toBe("unknown"); expect(p.missing).toContain("coverage:appRoleAssignments");
  });
  it("requires complete collection for refutation but a complete positive witness survives partial unrelated inventory", () => {
    expect(evaluateAuthorization(compileSnapshot(snapshot([])), query).verdict).toBe("refuted");
    const s = snapshot(); s.completion.collectors![0]!.state = "denied";
    expect(evaluateAuthorization(compileSnapshot(s), query).verdict).toBe("supported");
    s.completion.collectors!.find(c => c.id === "appRoleAssignments")!.failedEndpoints.push("/failed");
    s.edges = []; expect(evaluateAuthorization(compileSnapshot(s), query).verdict).toBe("unknown");
  });
  it.each(["sourceEndpoint", "sourceRecordIds", "completeness", "permissionIds"])("a grant missing %s cannot establish supported", field => {
    const s = snapshot(); const e = s.edges[0]!;
    if (field === "sourceEndpoint") e.evidence.sourceEndpoint = "";
    if (field === "sourceRecordIds") e.evidence.sourceRecordIds = [];
    if (field === "completeness") e.evidence.completeness = "partial";
    if (field === "permissionIds") delete e.permissionIds;
    const p = evaluateAuthorization(compileSnapshot(s), query); expect(p.verdict).toBe("unknown"); expect(p.missing.length).toBeGreaterThan(0);
  });
  it("does not use permission display names or another resource's permission IDs", () => {
    const s = snapshot(); s.edges[0]!.permissionIds = ["different-id"];
    expect(evaluateAuthorization(compileSnapshot(s), query).verdict).toBe("refuted");
    expect(evaluateAuthorization(compileSnapshot(s), { ...query, resourceId: "client" }).verdict).toBe("refuted");
  });
  it("preserves contradictory grant variants instead of choosing a winner", () => {
    const s = snapshot(); const conflicting = structuredClone(s.edges[0]!); conflicting.evidence.configured = false; s.edges.push(conflicting);
    const p = evaluateAuthorization(compileSnapshot(s), query); expect(p.verdict).toBe("conflicting"); expect(p.conflicts[0]!.variants).toHaveLength(2);
  });
  it("rejects mixed tenants, foreign queries, invalid timestamps, and missing query IDs", () => {
    const s = snapshot(); s.nodes[0]!.tenantId = "foreign"; expect(() => compileSnapshot(s)).toThrow("Cross-tenant");
    expect(() => evaluateAuthorization(compileSnapshot(snapshot()), { ...query, tenantId: "foreign" })).toThrow("Cross-tenant");
    const bad = snapshot(); bad.scannedAt = "never"; expect(() => compileSnapshot(bad)).toThrow("timestamp");
    expect(() => evaluateAuthorization(compileSnapshot(snapshot()), { ...query, permissionId: undefined })).toThrow("permission ID");
    const absent = snapshot(); absent.nodes = absent.nodes.filter(n => n.id !== "client"); expect(evaluateAuthorization(compileSnapshot(absent), query).verdict).toBe("unknown");
  });
  it("separates delegated consent and requires the correct user context", () => {
    const grant = edge("consent", "client", "resource", "CAN_CALL_DELEGATED"); grant.consent = { audience: "single-user", principalId: "person" };
    const model = compileSnapshot(snapshot([grant]));
    const q = { ...query, kind: "delegated-permission" as const };
    expect(evaluateAuthorization(model, q).verdict).toBe("unknown");
    expect(evaluateAuthorization(model, { ...q, userId: "person" }).verdict).toBe("supported");
    expect(evaluateAuthorization(model, { ...q, userId: "other" }).verdict).toBe("refuted");
    expect(evaluateAuthorization(model, query).verdict).toBe("refuted");
    grant.consent = { audience: "all-users", principalId: null };
    expect(evaluateAuthorization(compileSnapshot(snapshot([grant])), { ...q, userId: "other" }).verdict).toBe("supported");
    grant.consent.audience = "unknown"; expect(evaluateAuthorization(compileSnapshot(snapshot([grant])), { ...q, userId: "other" }).verdict).toBe("unknown");
  });
  it("supports transitive membership but does not inherit nested application assignments", () => {
    const s = snapshot([edge("member", "person", "nested", "MEMBER_OF"), edge("nest", "nested", "team", "MEMBER_OF"), edge("assign", "team", "resource", "ASSIGNED_TO")]);
    const q = { tenantId: query.tenantId, kind: "membership" as const, principalId: "person", resourceId: "team" };
    expect(evaluateAuthorization(compileSnapshot(s), q).paths).toEqual([["member", "nest"]]);
    expect(evaluateAuthorization(compileSnapshot(s), { ...q, kind: "assignment", resourceId: "resource" }).verdict).toBe("refuted");
    s.edges.push(edge("direct", "person", "team", "MEMBER_OF"));
    expect(evaluateAuthorization(compileSnapshot(s), { ...q, kind: "assignment", resourceId: "resource" }).paths).toEqual([["direct", "assign"]]);
  });
  it("eligible roles do not imply active roles and scopes are explicit", () => {
    const role = edge("eligible", "person", "role", "ELIGIBLE_FOR_ROLE"); role.scope = { directoryScopeId: "/administrativeUnits/unit", objectId: "unit" };
    const model = compileSnapshot(snapshot([role])); const q = { tenantId: query.tenantId, kind: "eligible-role" as const, principalId: "person", resourceId: "role", directoryScopeId: "/administrativeUnits/unit" };
    expect(evaluateAuthorization(model, q).verdict).toBe("supported");
    expect(evaluateAuthorization(model, { ...q, kind: "active-role" }).verdict).toBe("refuted");
    expect(evaluateAuthorization(model, { ...q, directoryScopeId: "/" }).verdict).toBe("refuted");
    expect(evaluateAuthorization(model, { ...q, directoryScopeId: undefined }).verdict).toBe("unknown");
  });
  it("only composes declared control rules and reports alternatives and search limits", () => {
    const s = snapshot([edge("owner", "person", "blueprint", "OWNS"), edge("instance", "blueprint", "client", "INSTANTIATES_AS"), edge("grant", "client", "resource"), edge("unrelated", "person", "resource", "OBSERVED_CALL")]);
    const q = { tenantId: query.tenantId, kind: "control-path" as const, principalId: "person", resourceId: "resource" };
    const p = evaluateAuthorization(compileSnapshot(s), q); expect(p.paths).toEqual([["owner", "instance", "grant"]]); expect(p.evidenceClass).toBe("inferred");
    s.edges.push(edge("owner2", "person", "client", "OWNS"));
    expect(evaluateAuthorization(compileSnapshot(s), q).paths).toHaveLength(2);
    expect(evaluateAuthorization(compileSnapshot(s), q, { maxDepth: 1, maxPaths: 1, maxSteps: 1 }).limits.exhausted).toBe(true);
    s.edges = [edge("not-control", "person", "client", "MEMBER_OF"), edge("grant", "client", "resource")]; expect(evaluateAuthorization(compileSnapshot(s), q).verdict).toBe("refuted");
  });
});

describe("incremental query dependency index", () => {
  it("matches fresh full evaluation after mutations and invalidates rule versions", () => {
    const s = snapshot(); const engine = createEvaluator(compileSnapshot(s));
    expect(engine.evaluate(query).reused).toBe(false); expect(engine.evaluate(query).reused).toBe(true);
    s.nodes.push(node("unrelated")); expect(engine.replace(compileSnapshot(s))).toEqual({ invalidated: 0, retained: 1 });
    s.edges.push(edge("alternative", "client", "resource")); expect(engine.replace(compileSnapshot(s)).invalidated).toBe(1);
    expect(engine.evaluate(query).proof).toEqual(evaluateAuthorization(compileSnapshot(s), query));
    const version = { ...compileSnapshot(s), ruleVersion: "entra-configured/2" }; expect(engine.replace(version).invalidated).toBe(1);
    expect(engine.evaluate(query).proof.ruleVersion).toBe("entra-configured/2");
    expect(() => engine.replace({ ...version, tenantId: "other" })).toThrow("Cross-tenant");
  });
  it("a newly added grant invalidates a cached absence", () => {
    const s = snapshot([]); const engine = createEvaluator(compileSnapshot(s)); expect(engine.evaluate(query).proof.verdict).toBe("refuted");
    s.edges.push(edge("grant", "client", "resource")); engine.replace(compileSnapshot(s)); expect(engine.evaluate(query).proof.verdict).toBe("supported");
  });
});
