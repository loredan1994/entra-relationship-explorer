/** JSON-only canonicalization. Array order is significant; callers sort mathematical sets. */
export function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => compare(a, b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  throw new Error("Engine inputs must contain finite JSON values.");
}
export function compare(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
export function unique(values: readonly string[]): string[] { return [...new Set(values)].sort(compare); }
export function timestamp(value: string): number {
  const n = Date.parse(value);
  if (!Number.isFinite(n)) throw new Error("Invalid engine timestamp.");
  return n;
}
export function bound(value: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error(`Invalid ${label} budget.`);
  return value;
}
export function immutable<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.values(value).forEach(immutable);
    Object.freeze(value);
  }
  return value;
}
