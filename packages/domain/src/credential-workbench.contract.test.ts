import { expect, it } from "vitest";
import { credentialStateAt, credentialWorkbench } from "./credential-workbench";
import { node, edge, snapshot } from "./test-support";
import type { CredentialMetadata, RelationshipType } from "./types";
const AT = "2026-08-26T10:00:00.000Z";
const NOW = Date.parse(AT);
const DAY = 86400000;
const key: CredentialMetadata = { id: "key", kind: "password", label: "Deployment", startsAt: "2026-01-01", expiresAt: "2027-01-01", sourceEndpoint: "/applications" };
const date = (offset: number) => new Date(NOW + offset).toISOString();
it.each([
  [-DAY, -1, "expired"], [-DAY, 0, "expired"], [-DAY, 1, "expires-soon"],
  [-DAY, DAY * 30, "expires-soon"], [-DAY, DAY * 30 + 1, "valid"],
  [0, DAY * 60, "valid"], [1, DAY * 60, "not-yet-valid"],
  [0, 0, "unknown"], [1, 0, "unknown"], [null, DAY, "unknown"], [-DAY, null, "unknown"],
] as const)("classifies validity at start=%s end=%s as %s", (start, end, expected) => {
  expect(credentialStateAt({ ...key, startsAt: start === null ? null : date(start), expiresAt: end === null ? null : date(end) }, AT)).toBe(expected);
});
it("rejects an invalid reference instant and treats malformed credential dates as unknown", () => {
  expect(() => credentialStateAt(key, "invalid")).toThrow("A valid reference time is required.");
  expect(credentialStateAt({ ...key, startsAt: "invalid" }, AT)).toBe("unknown");
  expect(credentialStateAt({ ...key, expiresAt: "invalid" }, AT)).toBe("unknown");
});
it.each([
  [undefined, false, 0, false, false], [[], true, 0, false, false],
  [[key], true, 1, false, false], [[{ ...key, expiresAt: AT }], true, 0, false, false],
  [[key, { ...key, id: "old", expiresAt: AT }], true, 1, false, true],
  [[key, { ...key, id: "soon", expiresAt: date(1) }], true, 2, true, false],
  [[{ ...key, startsAt: date(1) }, { ...key, id: "unknown", expiresAt: null }], true, 0, false, false],
] as const)("distinguishes inventory, usable keys, overlap and replacement (%#)", (credentials, inventoryKnown, usableCount, rotationOverlap, expiredWithReplacement) => {
  const identity = node({ kind: "application", label: "Client", credentials: credentials ? [...credentials] : undefined });
  const [row] = credentialWorkbench(snapshot([identity], [], { scannedAt: AT }));
  expect(row).toMatchObject({ identity, inventoryKnown, usableCount, rotationOverlap, expiredWithReplacement, federation: [], grants: [] });
  expect(row!.credentials).toHaveLength(credentials?.length ?? 0);
  if (credentials?.length) expect(row!.credentials[0]).toMatchObject(credentials[0]!);
});
it("returns only workload identities and associates their exact trusts and direct or instantiated grants", () => {
  const app = node({ kind: "application", label: "Blueprint" });
  const sp = node({ kind: "servicePrincipal", label: "Instance" });
  const mi = node({ kind: "managedIdentity", label: "Managed" });
  const user = node({ kind: "user", label: "Owner" });
  const trust = node({ kind: "federatedCredential", label: "Trust" });
  const api = node({ kind: "servicePrincipal", label: "Resource" });
  const federation = edge("FEDERATES_AS", trust, app);
  const direct = (["CAN_CALL_AS_APP", "CAN_CALL_DELEGATED", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"] as RelationshipType[]).map(type => edge(type, app, api));
  const inherited = edge("CAN_CALL_AS_APP", sp, api);
  const edges = [edge("OWNS", user, app), edge("INSTANTIATES_AS", app, sp), federation, ...direct, inherited, edge("CAN_CALL_AS_APP", mi, api), edge("OWNS", app, mi), edge("FEDERATES_AS", trust, mi), edge("INSTANTIATES_AS", mi, api)];
  const s = snapshot([user, app, sp, mi, trust, api], edges);
  const rows = credentialWorkbench(s);
  expect(rows.map(r => r.identity.id)).toEqual([app.id, sp.id, mi.id, api.id]);
  expect(rows[0]!.federation).toEqual([{ edge: federation, trust }]);
  expect(rows[0]!.grants).toEqual([...direct, inherited]);
  expect(rows[1]!.federation).toEqual([]);
  expect(rows[1]!.grants).toEqual([inherited]);
  s.nodes[0]!.tenantId = "other";
  expect(() => credentialWorkbench(s)).toThrow();
});

it("does not inherit grants through another registration's instantiation", () => {
  const own = node({ kind: "application", label: "Own" }); const other = node({ kind: "application", label: "Other" }); const identity = node({ kind: "servicePrincipal", label: "Other identity" }); const api = node({ kind: "servicePrincipal", label: "API" });
  const s = snapshot([own, other, identity, api], [edge("INSTANTIATES_AS", other, identity), edge("CAN_CALL_AS_APP", identity, api)]);
  expect(credentialWorkbench(s)[0]!.grants).toEqual([]);
});
