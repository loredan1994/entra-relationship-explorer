/** Database UUID keys have one spelling for lookups and authenticated encryption. */
export function canonicalOpaqueId(value: string | undefined): string | null {
  // The length check also rejects a trailing newline, which `$` permits in JavaScript.
  if (value?.length !== 36 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return null;
  return value.toLowerCase();
}
