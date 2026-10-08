import type { ConditionalAccessDefinition } from "@entra-explorer/domain";

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const record = (value: unknown): Record<string, unknown> => isRecord(value) ? value : {};
const present = (value: unknown): boolean => value !== undefined && value !== null && (!Array.isArray(value) || value.length > 0);

/** Keep supported inputs and unsupported field names, never arbitrary policy bodies. */
export function projectConditionalAccess(value: unknown): ConditionalAccessDefinition {
  const policy = record(value), conditions = record(policy.conditions), users = record(conditions.users), applications = record(conditions.applications);
  const unsupported: string[] = [];
  function strings(parent: Record<string, unknown>, key: string, path: string): string[] {
    const v = parent[key];
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v) || v.some(i => typeof i !== "string")) { unsupported.push(path); return []; }
    return [...new Set(v as string[])].sort();
  }
  function unknownFields(parent: Record<string, unknown>, allowed: string[], path: string) {
    for (const [key, v] of Object.entries(parent)) if (!allowed.includes(key) && present(v)) unsupported.push(`${path}.${key}`);
  }
  function selector(key: string, include: string, exclude: string) {
    if (conditions[key] === undefined || conditions[key] === null) return null;
    const source = record(conditions[key]);
    if (!Object.keys(source).length) unsupported.push(`conditions.${key}`);
    unknownFields(source, [include, exclude], `conditions.${key}`);
    return { include: strings(source, include, `conditions.${key}.${include}`), exclude: strings(source, exclude, `conditions.${key}.${exclude}`) };
  }
  if (!isRecord(policy.conditions) || !isRecord(conditions.users) || !isRecord(conditions.applications)) unsupported.push("conditions.required-targets");
  unknownFields(conditions, ["users", "applications", "platforms", "locations", "clientAppTypes"], "conditions");
  unknownFields(users, ["includeUsers", "excludeUsers", "includeGroups", "excludeGroups"], "conditions.users");
  unknownFields(applications, ["includeApplications", "excludeApplications"], "conditions.applications");
  const grant = present(policy.grantControls) ? record(policy.grantControls) : null;
  if (grant) unknownFields(grant, ["operator", "builtInControls"], "grantControls");
  const sessions = record(policy.sessionControls);
  for (const [key, v] of Object.entries(sessions)) if (present(v)) unsupported.push(`sessionControls.${key}`);
  if (policy.sessionControls !== undefined && policy.sessionControls !== null && !isRecord(policy.sessionControls)) unsupported.push("sessionControls.malformed");
  if (policy.sessionControls === undefined) unsupported.push("sessionControls.not-collected");
  return {
    state: typeof policy.state === "string" ? policy.state : "unknown",
    users: { include: strings(users, "includeUsers", "users.include"), exclude: strings(users, "excludeUsers", "users.exclude"), includeGroups: strings(users, "includeGroups", "users.includeGroups"), excludeGroups: strings(users, "excludeGroups", "users.excludeGroups") },
    applications: { include: strings(applications, "includeApplications", "applications.include"), exclude: strings(applications, "excludeApplications", "applications.exclude") },
    platforms: selector("platforms", "includePlatforms", "excludePlatforms"), locations: selector("locations", "includeLocations", "excludeLocations"),
    clientAppTypes: strings(conditions, "clientAppTypes", "clientAppTypes"),
    grant: grant ? { operator: typeof grant.operator === "string" ? grant.operator : "unknown", controls: strings(grant, "builtInControls", "grantControls.builtInControls") } : null,
    unsupported: [...new Set(unsupported)].sort(),
  };
}
