const WRITE_PATTERN = /\.(readwrite|write|send|manage|fullcontrol)\b/i;
const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-/i;

export function isWritePermission(permission: string): boolean {
  return WRITE_PATTERN.test(permission);
}

/** Unresolved app-role IDs surface as raw GUIDs when a scan could not resolve the role name. */
export function isUnresolvedPermission(permission: string): boolean {
  return GUID_PATTERN.test(permission);
}

/**
 * Order permissions by how much they matter to a reviewer: write-capable first,
 * then tenant-wide reads, then named reads, with unresolved GUIDs last. Used to
 * decide which few pills to show when a grant carries a dozen permissions.
 */
export function rankPermissions(permissions: string[]): string[] {
  return [...permissions].sort((a, b) => weight(b) - weight(a) || a.localeCompare(b));
}

function weight(permission: string): number {
  let value = 0;
  if (WRITE_PATTERN.test(permission)) value += 4;
  if (permission.toLowerCase().endsWith(".all")) value += 2;
  if (!GUID_PATTERN.test(permission)) value += 1;
  return value;
}

/** A short human phrase for a permission list that may be very long. */
export function permissionPhrase(permissions: string[]): string {
  if (permissions.length === 0) return "configured access";
  if (permissions.length <= 3) return permissions.join(" and ");
  const ranked = rankPermissions(permissions);
  return `${permissions.length} permissions, most notably ${ranked.slice(0, 2).join(" and ")}`;
}
