import { expect, it } from "vitest";

it("loads the rule catalog as a standalone module with complete rule metadata", async () => {
  // Import inside the test so module-initialization failures are test failures too.
  const { ENTRA_CONTROL_PATH_RULES } = await import("./rules");
  expect(ENTRA_CONTROL_PATH_RULES.map(r => r.reference.id)).toEqual(["ERE-IAM-001", "ERE-IAM-002", "ERE-IAM-003", "ERE-IAM-004"]);
  for (const rule of ENTRA_CONTROL_PATH_RULES) {
    expect(rule.reference.version).toBe(1);
    expect(rule.reference.title.length).toBeGreaterThan(0);
    expect(rule.reference.requiredCoverage.length).toBeGreaterThan(0);
    expect(rule.reference.references.length).toBeGreaterThan(0);
    expect(typeof rule.evaluate).toBe("function");
  }
});
