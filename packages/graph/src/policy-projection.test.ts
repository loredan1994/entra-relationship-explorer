import { describe, expect, it } from "vitest";
import { projectConditionalAccess } from "./policy-projection";

describe("structured policy evidence projection", () => {
  it("preserves exclusions, controls and supported condition boundaries", () => {
    const result = projectConditionalAccess({ state: "enabled", conditions: { users: { includeUsers: ["All"], excludeUsers: ["break-glass"], includeGroups: ["staff"], excludeGroups: ["emergency"] }, applications: { includeApplications: ["api"], excludeApplications: ["public"] }, clientAppTypes: ["browser"], platforms: { includePlatforms: ["windows"], excludePlatforms: ["linux"] }, locations: { includeLocations: ["All"], excludeLocations: ["AllTrusted"] } }, grantControls: { operator: "OR", builtInControls: ["mfa", "compliantDevice"] }, sessionControls: null });
    expect(result.users.exclude).toEqual(["break-glass"]); expect(result.users.excludeGroups).toEqual(["emergency"]); expect(result.applications.exclude).toEqual(["public"]);
    expect(result.platforms).toEqual({ include: ["windows"], exclude: ["linux"] }); expect(result.locations).toEqual({ include: ["All"], exclude: ["AllTrusted"] });
    expect(result.grant).toEqual({ operator: "OR", controls: ["compliantDevice", "mfa"] }); expect(result.unsupported).toEqual([]);
  });
  it("keeps unsupported field names while discarding their arbitrary contents", () => {
    const result = projectConditionalAccess({ state: "enabled", conditions: { users: { includeUsers: ["All"], includeRoles: ["private-role"] }, applications: { includeApplications: ["All"] }, devices: { deviceFilter: { rule: "sensitive arbitrary rule" } } }, grantControls: { authenticationStrength: { id: "strength" } }, sessionControls: { signInFrequency: { value: 1 } } });
    expect(result.unsupported).toEqual(["conditions.devices", "conditions.users.includeRoles", "grantControls.authenticationStrength", "sessionControls.signInFrequency"]);
    expect(JSON.stringify(result)).not.toContain("sensitive arbitrary rule"); expect(JSON.stringify(result)).not.toContain("private-role");
  });
  it("missing and malformed inputs do not silently become unconstrained policies", () => {
    expect(projectConditionalAccess(null).unsupported).toContain("conditions.required-targets");
    const p = projectConditionalAccess({ state: "future", conditions: { users: { includeUsers: "All" }, applications: { includeApplications: [4] } } });
    expect(p.users.include).toEqual([]); expect(p.unsupported).toContain("users.include"); expect(p.unsupported).toContain("applications.include"); expect(p.unsupported).toContain("sessionControls.not-collected");
  });
});
it.each([[], ["invalid"], "invalid", 0, false, null, undefined])("malformed required containers stay unsupported: %j", value => {
  for (const key of ["users", "applications"]) {
    const result = projectConditionalAccess({ state: "enabled", conditions: { users: {}, applications: {}, [key]: value }, sessionControls: null });
    expect(result.unsupported).toContain("conditions.required-targets");
  }
  expect(projectConditionalAccess({ conditions: value }).unsupported).toContain("conditions.required-targets");
});
it.each([[], ["invalid"], "invalid", 0, false])("malformed optional selectors and session controls stay unsupported: %j", value => {
  for (const key of ["platforms", "locations"]) expect(projectConditionalAccess({ conditions: { users: {}, applications: {}, [key]: value }, sessionControls: null }).unsupported).toEqual([`conditions.${key}`]);
  expect(projectConditionalAccess({ conditions: { users: {}, applications: {} }, sessionControls: value }).unsupported).toEqual(["sessionControls.malformed"]);
});
it("projects empty and missing optional values without inventing constraints", () => {
  const result = projectConditionalAccess({ conditions: { users: {}, applications: {}, platforms: null, locations: undefined, clientAppTypes: null }, grantControls: null, sessionControls: null });
  expect(result).toEqual({ state: "unknown", users: { include: [], exclude: [], includeGroups: [], excludeGroups: [] }, applications: { include: [], exclude: [] }, platforms: null, locations: null, clientAppTypes: [], grant: null, unsupported: [] });
  expect(projectConditionalAccess({ state: 4, conditions: { users: {}, applications: {} }, grantControls: { operator: 4, builtInControls: null }, sessionControls: {} }).grant).toEqual({ operator: "unknown", controls: [] });
});
it("sorts and deduplicates selector IDs while rejecting mixed-type arrays", () => {
  const result = projectConditionalAccess({ state: "enabled", conditions: { users: { includeUsers: ["z", "a", "z"], excludeUsers: ["safe", 4] }, applications: {} }, sessionControls: null });
  expect(result.users.include).toEqual(["a", "z"]); expect(result.users.exclude).toEqual([]); expect(result.unsupported).toEqual(["users.exclude"]);
});
it("ignores absent unknown fields but records populated selectors, grant and session field names", () => {
  const result = projectConditionalAccess({ state: "enabled", conditions: { users: {}, applications: { applicationFilter: { rule: "private-value" } }, signInRiskLevels: [], empty: null, platforms: { includePlatforms: ["windows"], future: true }, locations: { includeLocations: ["All"], future: "private-value" } }, grantControls: { operator: "AND", builtInControls: ["mfa"], customAuthenticationFactors: [] }, sessionControls: { absent: null, empty: [], present: { isEnabled: false } } });
  expect(result.unsupported).toEqual(["conditions.applications.applicationFilter", "conditions.locations.future", "conditions.platforms.future", "sessionControls.present"]);
  expect(JSON.stringify(result)).not.toContain("private-value");
});
