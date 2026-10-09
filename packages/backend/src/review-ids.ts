/** Keep a bulk read bounded without silently dropping reviewed findings. */
export function canonicalReviewIds(findingIds: readonly string[]): string[] {
  const unique = new Set<string>();
  for (const id of findingIds) {
    if (id === "") continue;
    unique.add(id);
    if (unique.size > 10_000) throw new RangeError("A review read supports at most 10,000 distinct finding IDs.");
  }
  return [...unique];
}
