export const CORE_GRAPH_SCOPES = [
  "https://graph.microsoft.com/Application.Read.All",
  "https://graph.microsoft.com/Directory.Read.All",
] as const;

export const IDENTITY_SCOPES = ["openid", "profile", "offline_access"] as const;
export const OPTIONAL_GRAPH_SCOPES = [
  "https://graph.microsoft.com/RoleManagement.Read.Directory",
  "https://graph.microsoft.com/Policy.Read.All",
  "https://graph.microsoft.com/Policy.Read.PermissionGrant",
  "https://graph.microsoft.com/AuditLog.Read.All",
] as const;

const ALLOWED_SCOPES = new Set<string>([...CORE_GRAPH_SCOPES, ...OPTIONAL_GRAPH_SCOPES, ...IDENTITY_SCOPES]);

export function assertReadOnlyScopes(scopes: readonly string[]): void {
  if (scopes.length === 0) throw new Error("At least one scope is required.");
  for (const scope of scopes) {
    if (!ALLOWED_SCOPES.has(scope)) throw new Error(`Scope is outside the approved read-only set: ${scope}`);
    /* c8 ignore next 3 -- defense in depth: no approved scope is write-capable today, so this
       second layer is unreachable until the allow-list above grows one. */
    // Stryker disable next-line all: unreachable while every approved scope is read-only.
    if (/readwrite|\.write\b/i.test(scope)) throw new Error(`Write-capable scope is forbidden: ${scope}`);
  }
}
