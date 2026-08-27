import { describe, expect, it } from "vitest";
import { csvCell, csvRow } from "./csv";

describe("CSV export neutralization", () => {
  it.each(["=SUM(1,1)", "+cmd", "-1+1", "@formula", "\tformula", "\0formula", "\r=FORMULA", "\n=FORMULA"])("neutralizes formula prefix %j", (value) => {
    expect(csvCell(value)).toBe(`"'${value}"`);
  });

  it("leaves a formula character that is not the first character alone", () => {
    expect(csvCell("total=SUM(1,1)")).toBe('"total=SUM(1,1)"');
    expect(csvCell("Contoso - Ltd")).toBe('"Contoso - Ltd"');
    expect(csvCell("a\tb")).toBe('"a\tb"');
  });

  it("escapes quotes according to CSV rules", () => {
    expect(csvCell('plain "quoted" value')).toBe('"plain ""quoted"" value"');
  });
});

describe("CSV rows", () => {
  it("quotes every cell and separates them with commas", () => {
    expect(csvRow(["a", "b", "c"])).toBe('"a","b","c"');
  });

  it("neutralizes a formula that appears in any column, not just the first", () => {
    expect(csvRow(["safe", "=cmd|calc"])).toBe('"safe","\'=cmd|calc"');
  });

  it("keeps an embedded comma inside its quoted cell", () => {
    expect(csvRow(["Contoso, Ltd", "ok"])).toBe('"Contoso, Ltd","ok"');
  });

  it("emits an empty string for a row with no columns", () => {
    expect(csvRow([])).toBe("");
  });

  it("preserves an empty cell as an empty quoted field", () => {
    expect(csvRow(["", "value"])).toBe('"","value"');
  });
});
