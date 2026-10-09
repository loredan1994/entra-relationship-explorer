import { describe, expect, it } from "vitest";
import { normalizeTenantScan } from "./normalize";
import { rawScan, SCANNED_AT, servicePrincipal, signIn, sourced } from "./test-support";
import type { GraphSignIn } from "./types";

function principal(id: string, appId: string) {
  return sourced(servicePrincipal({ id, appId, displayName: id }), "/servicePrincipals");
}

function observed(principals: ReturnType<typeof principal>[], fields: Partial<GraphSignIn> = {}) {
  return normalizeTenantScan(rawScan({
    servicePrincipals: principals,
    signIns: [sourced(signIn({ id: "event", createdDateTime: SCANNED_AT, appId: "caller-app", resourceId: "resource-app", ...fields }), "/auditLogs/signIns")],
  }), { snapshotId: "activity-index" }).edges.filter(edge => edge.type === "OBSERVED_CALL");
}

describe("activity identity lookup", () => {
  it("keeps the first matching application ID for both ends of a successful sign-in", () => {
    const edges = observed([
      principal("caller-first", "caller-app"), principal("caller-later", "caller-app"),
      principal("resource-first", "resource-app"), principal("resource-later", "resource-app"),
    ]);
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({
      sourceId: "caller-first", targetId: "resource-first", permissions: [],
      evidence: {
        configured: false, observed: { lastSeenAt: SCANNED_AT },
        sourceEndpoint: "/auditLogs/signIns", sourceRecordIds: ["event"],
        sourceObjectId: "caller-first", targetObjectId: "resource-first",
      },
    });
  });

  it.each([
    { resources: [principal("application-match", "collision"), principal("collision", "other-app")], expected: "application-match" },
    { resources: [principal("collision", "other-app"), principal("application-match", "collision")], expected: "collision" },
  ])("preserves original record order when resource application and object IDs collide: $expected", ({ resources, expected }) => {
    expect(observed([principal("caller", "caller-app"), ...resources], { resourceId: "collision" })).toMatchObject([
      { sourceId: "caller", targetId: expected },
    ]);
  });

  it("resolves resources by object ID while source fallback uses application IDs only", () => {
    const principals = [principal("caller", "caller-app"), principal("resource", "resource-app")];
    expect(observed(principals, { resourceId: "resource" })).toMatchObject([{ sourceId: "caller", targetId: "resource" }]);
    expect(observed(principals, { appId: "caller" })).toEqual([]);
  });

  it("keeps explicit principal IDs ahead of inventory fallback", () => {
    expect(observed([principal("caller", "caller-app"), principal("resource", "resource-app")], {
      servicePrincipalId: "explicit-caller", resourceServicePrincipalId: "explicit-resource",
    })).toMatchObject([{ sourceId: "explicit-caller", targetId: "explicit-resource" }]);
  });

  it.each(["servicePrincipalId", "resourceServicePrincipalId"] as const)("does not replace an explicitly empty %s with a fallback match", (field) => {
    expect(observed([principal("caller", "caller-app"), principal("resource", "resource-app")], { [field]: "" })).toEqual([]);
  });

  it("falls back for null explicit IDs and drops unresolved records", () => {
    const principals = [principal("caller", "caller-app"), principal("resource", "resource-app")];
    expect(observed(principals, { servicePrincipalId: null, resourceServicePrincipalId: null })).toMatchObject([{ sourceId: "caller", targetId: "resource" }]);
    expect(observed(principals, { appId: null })).toEqual([]);
    expect(observed(principals, { resourceId: undefined })).toEqual([]);
    expect(observed(principals, { resourceId: "missing" })).toEqual([]);
  });

  it("does not emit activity edges for failed or unknown sign-in outcomes", () => {
    const principals = [principal("caller", "caller-app"), principal("resource", "resource-app")];
    expect(observed(principals, { status: { errorCode: 5 } })).toEqual([]);
    expect(observed(principals, { status: null })).toEqual([]);
  });
});
