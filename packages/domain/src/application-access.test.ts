import { describe, expect, it } from "vitest";
import { applicationAccessReviews, signInAudienceLabel } from "./application-access";
import { compareSnapshots } from "./comparisons";
import { edge, node, snapshot } from "./test-support";

describe("application access review", () => {
  it("links registrations by app ID and keeps direct assignments, consent, owners and observations separate", () => {
    const app = node({ kind: "application", label: "Different registration name", appId: "api", id: "app" });
    const api = node({ kind: "servicePrincipal", label: "API", appId: "api", id: "api" });
    const caller = node({ kind: "managedIdentity", label: "Worker" });
    const person = node({ kind: "user", label: "Owner" });
    const group = node({ kind: "group", label: "Operators" });
    const role = node({ kind: "appRole", label: "Reader" });
    const assignment = edge("ASSIGNED_TO", group, api);
    const grant = edge("CAN_CALL_AS_APP", caller, api);
    const consent = { ...edge("CAN_CALL_DELEGATED", caller, api), consent: { audience: "single-user" as const, principalId: person.id } };
    const ownership = edge("OWNS", person, api);
    const observed = edge("OBSERVED_CALL", caller, api, { evidence: { configured: false, observed: { lastSeenAt: "2026-08-26T09:00:00Z", windowStartsAt: "2026-07-26T09:00:00Z" } } });
    const s = snapshot([api, caller, app, person, group, role], [assignment, grant, consent, ownership, observed, edge("OWNS", person, app), edge("GRANTED_APP_ROLE", group, role), edge("MEMBER_OF", person, group), edge("CAN_CALL_AS_APP", caller, api, { evidence: { configured: false } }), edge("OBSERVED_CALL", caller, api)]);
    const original = structuredClone(s);
    const review = applicationAccessReviews(s).find(r => r.identity.id === api.id)!;
    expect(review.registration?.id).toBe("app");
    expect(review.incoming.map(e => e.id)).toEqual([assignment.id, grant.id, consent.id]);
    expect(review.incoming[2]!.consent).toEqual({ audience: "single-user", principalId: person.id });
    expect(review.owners).toEqual([ownership]);
    expect(review.observations).toEqual([observed]);
    expect(applicationAccessReviews(s).map(r => r.identity.kind)).toEqual(["servicePrincipal", "managedIdentity"]);
    expect(s).toEqual(original);
  });
  it("requires successful endpoint evidence before declaring an assignment, consent or owner read complete", () => {
    const api = node({ kind: "servicePrincipal", label: "API", id: "api" });
    const s = snapshot([api], []);
    s.completion.collectedEndpoints = ["/servicePrincipals/api/appRoleAssignedTo?$select=id", "/servicePrincipals/api/owners?$select=id", "/oauth2PermissionGrants?$select=id"];
    expect(applicationAccessReviews(s)[0]).toMatchObject({ assignmentsCollected: true, ownersCollected: true, consentCollected: true, incoming: [], registration: null });
    s.completion.skippedEndpoints = ["/servicePrincipals/api/appRoleAssignedTo", "/oauth2PermissionGrants", "/servicePrincipals/api/owners"];
    expect(applicationAccessReviews(s)[0]).toMatchObject({ assignmentsCollected: false, ownersCollected: false, consentCollected: false });
    s.completion.collectedEndpoints = ["/servicePrincipals/other/appRoleAssignedTo", "/servicePrincipals"];
    s.completion.skippedEndpoints = [];
    expect(applicationAccessReviews(s)[0]?.assignmentsCollected).toBe(false);
  });
  it("does not link identities merely because names match or both app IDs are missing", () => {
    const a = node({ kind: "application", label: "Duplicate" });
    const b = node({ kind: "servicePrincipal", label: "Duplicate" });
    expect(applicationAccessReviews(snapshot([a, b], []))[0]?.registration).toBeNull();
  });
  it("sorts duplicate labels by object ID and never mistakes a tenant identity for its registration", () => {
    const registration = node({ kind: "application", label: "Registration", appId: "shared", id: "registration" });
    const z = node({ kind: "servicePrincipal", label: "Zebra", appId: "shared", id: "a" });
    const b = node({ kind: "servicePrincipal", label: "Alpha", appId: "other", id: "b" });
    const a = node({ kind: "managedIdentity", label: "Alpha", id: "a2" });
    const reviews = applicationAccessReviews(snapshot([registration, z, b, a], []));
    expect(reviews.map(r => r.identity.id)).toEqual(["a2", "b", "a"]);
    expect(reviews.find(r => r.identity.id === z.id)?.registration?.id).toBe("registration");
    expect(reviews.find(r => r.identity.id === b.id)?.registration).toBeNull();
  });
  it("does not treat activity attached to a configured grant as a separate sign-in record", () => {
    const source = node({ kind: "servicePrincipal", label: "Caller" });
    const target = node({ kind: "servicePrincipal", label: "API" });
    const grant = edge("CAN_CALL_AS_APP", source, target, { evidence: { observed: { lastSeenAt: "2026-08-26T09:00:00Z", windowStartsAt: "2026-07-26T09:00:00Z" } } });
    const review = applicationAccessReviews(snapshot([source, target], [grant])).find(r => r.identity.id === target.id)!;
    expect(review.observations).toEqual([]);
    expect(review.incoming).toEqual([grant]);
  });
  it("rejects foreign objects and edges at the tenant boundary", () => {
    const a = node({ kind: "servicePrincipal", label: "API" });
    expect(() => applicationAccessReviews(snapshot([{ ...a, tenantId: "foreign" }], []))).toThrow();
    const foreign = { ...edge("CAN_CALL_AS_APP", a, a), tenantId: "foreign" };
    expect(() => applicationAccessReviews(snapshot([a], [foreign]))).toThrow();
  });
  it.each([
    ["AzureADMyOrg", "This organization (single tenant)"],
    ["AzureADMultipleOrgs", "Any organization (multiple tenants)"],
    ["AzureADandPersonalMicrosoftAccount", "Any organization and personal Microsoft accounts"],
    ["PersonalMicrosoftAccount", "Personal Microsoft accounts"],
    [null, "Unknown — not recorded"], [undefined, "Unknown — not recorded"],
    ["FutureAudience", "Unrecognized audience (FutureAudience)"],
  ])("explains audience %s without guessing", (value, label) => {
    expect(signInAudienceLabel(value)).toBe(label);
  });
  it("confirms a disabled account change but leaves newly collected historical fields unconfirmed", () => {
    const a = node({ id: "api", kind: "servicePrincipal", label: "API", sourceEndpoint: "/servicePrincipals", applicationProfile: { signInAudience: null, accountEnabled: true, verifiedPublisherId: null, verifiedPublisherName: null } });
    const before = snapshot([a], []);
    const after = structuredClone(before);
    after.nodes[0]!.applicationProfile!.accountEnabled = false;
    after.nodes[0]!.applicationProfile!.signInAudience = "AzureADMultipleOrgs";
    const fields = compareSnapshots(before, after).changes[0]!.fields!;
    expect(fields.find(f => f.field === "applicationProfile.accountEnabled")).toMatchObject({ before: "true", after: "false" });
    expect(fields.find(f => f.field === "applicationProfile.accountEnabled")?.state).not.toBe("unconfirmed");
    expect(fields.find(f => f.field === "applicationProfile.signInAudience")?.state).toBe("unconfirmed");
    delete before.nodes[0]!.applicationProfile;
    expect(compareSnapshots(before, after).changes[0]?.kind).toBe("unconfirmed");
    before.nodes[0]!.applicationProfile = { ...after.nodes[0]!.applicationProfile!, accountEnabled: true };
    after.completion.skippedEndpoints = ["/servicePrincipals"];
    expect(compareSnapshots(before, after).changes[0]?.kind).toBe("unconfirmed");
  });
});
