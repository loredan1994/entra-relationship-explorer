import { describe, expect, it } from "vitest";
import { csvCell } from "./csv";

describe("CSV export neutralization", () => {
  it.each(["=SUM(1,1)", "+cmd", "-1+1", "@formula", "\tformula", "\0formula"])("neutralizes formula prefix %j", (value) => {
    expect(csvCell(value)).toBe(`"'${value}"`);
  });

  it("escapes quotes according to CSV rules", () => {
    expect(csvCell('plain "quoted" value')).toBe('"plain ""quoted"" value"');
  });
});
