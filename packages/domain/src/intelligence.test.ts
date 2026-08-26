import { describe, expect, it } from "vitest";
import { cleanProjectFixture } from "./fixtures";
import { analyzeTenantIntelligence } from "./intelligence";

describe("tenant IAM intelligence", () => {
  it("discovers a transitive configured path without claiming observed use", () => {
    const intelligence = analyzeTenantIntelligence(cleanProjectFixture);
    const path = intelligence.paths.find((item) => item.source.label === "Maya Chen" && item.target.label === "Clean Project API");
    expect(path?.steps.map((item) => item.relationship)).toEqual(["OWNS", "INSTANTIATES_AS", "CAN_CALL_AS_APP"]);
    expect(path?.severity).toBe("high");
    expect(path?.steps.every((item) => item.evidenceClass === "configured")).toBe(true);
    expect(path?.uncertainty.join(" ")).toContain("not evidence that exploitation occurred");
  });

  it("keeps configured, inferred, observed, and missing evidence separate", () => {
    const intelligence = analyzeTenantIntelligence(cleanProjectFixture);
    expect(intelligence.evidence.configured).toBeGreaterThan(0);
    expect(intelligence.evidence.inferred).toBeGreaterThan(0);
    expect(intelligence.evidence.observed).toBe(0);
    expect(intelligence.evidence.missing).toBeGreaterThan(0);
  });

  it("turns skipped collection into a visible coverage finding", () => {
    const finding = analyzeTenantIntelligence(cleanProjectFixture).findings.find((item) => item.category === "coverage");
    expect(finding?.evidenceClass).toBe("missing");
    expect(finding?.sourceEndpoints).toContain("/auditLogs/signIns");
  });
});
