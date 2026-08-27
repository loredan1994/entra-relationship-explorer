const FORMULA_PREFIX = /^[=+\-@\t\0\r\n]/;

export function csvCell(value: string): string {
  const safe = FORMULA_PREFIX.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}

export function csvRow(values: readonly string[]): string {
  return values.map(csvCell).join(",");
}
