import { cleanProjectFixture, type DirectoryNode } from "@entra-explorer/domain";
import { describe, expect, it } from "vitest";
import { applicationIdentityPair } from "../components/application-identity";

const blueprint = cleanProjectFixture.nodes.find(node => node.kind === "application")!;
const identity = cleanProjectFixture.nodes.find(node => node.kind === "servicePrincipal" && node.appId === blueprint.appId)!;

describe("application detail identity pairing", () => {
  it("shows the same unique pair when opened from either object", () => {
    for (const selected of [blueprint, identity]) {
      expect(applicationIdentityPair({ ...cleanProjectFixture, nodes: [blueprint, identity] }, selected)).toMatchObject({ blueprint, tenantIdentity: identity, status: "matched" });
    }
  });

  it.each([undefined, "", "   "])("does not associate unrelated objects with a missing application ID %s", appId => {
    const selected = { ...blueprint, appId };
    const unrelated = { ...identity, appId };
    const result = applicationIdentityPair({ ...cleanProjectFixture, nodes: [selected, unrelated] }, selected);
    expect(result.nodes).toEqual([selected]);
    expect(result.tenantIdentity).toBeUndefined();
    expect(result.status).toBe("missing-app-id");
  });

  it.each(["application", "servicePrincipal"] as const)("does not choose an arbitrary candidate when %s records conflict", kind => {
    const duplicate: DirectoryNode = { ...(kind === "application" ? blueprint : identity), id: "duplicate-object" };
    const result = applicationIdentityPair({ ...cleanProjectFixture, nodes: [blueprint, identity, duplicate] }, identity);
    expect(result.nodes).toEqual([identity]);
    expect(result.blueprint).toBeUndefined();
    expect(result.status).toBe("ambiguous");
  });

  it("ignores foreign-tenant and non-application records even when their application IDs match", () => {
    const foreign = { ...identity, tenantId: "another-tenant" };
    const role = { ...identity, id: "role-id", kind: "appRole" as const };
    expect(applicationIdentityPair({ ...cleanProjectFixture, nodes: [blueprint, foreign, role] }, blueprint)).toMatchObject({ nodes: [blueprint], tenantIdentity: undefined, status: "not-recorded" });
  });
});
