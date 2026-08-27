# Entra rule fixture template

Use this template for a repository-reviewed control-path rule. It is intentionally bounded: one normalized fixture, one expected finding, and adjacent cases that must not alert. A rule proposal is incomplete until these contracts pass alongside the full domain suite.

```ts
import { describe, expect, it } from "vitest";
import { analyzeTenantIntelligenceHistory, type TenantSnapshot } from "@entra-explorer/domain";

const current: TenantSnapshot = {
  // Synthetic IDs and labels only. Include the smallest normalized node and
  // relationship set needed to prove the rule, with exact source endpoints.
};

describe("ERE-IAM-### — short rule title", () => {
  it("emits one stable evidence-bearing finding", () => {
    const finding = analyzeTenantIntelligenceHistory([current]).findings
      .find((item) => item.rule?.id === "ERE-IAM-###");
    expect(finding).toMatchObject({
      evidenceClass: "inferred",
      prerequisites: expect.any(Array),
      requiredCoverage: expect.any(Array),
      sourceEndpoints: expect.any(Array),
      uncertainty: expect.any(Array),
    });
  });

  it.each([
    ["ordinary inventory", ordinaryFixture],
    ["missing prerequisite", withoutPrerequisite],
    ["lower-impact terminal access", lowImpactFixture],
  ])("does not alert on %s", (_name, fixture) => {
    expect(analyzeTenantIntelligenceHistory([fixture]).findings
      .some((item) => item.rule?.id === "ERE-IAM-###")).toBe(false);
  });

  it("states what a partial scan cannot establish", () => { /* assert uncertainty */ });
  it("rejects mixed-tenant history", () => { /* assert tenant boundary */ });
  it("rejects oldest-to-newest history", () => { /* assert ordering */ });
  it("keeps IDs stable across labels and ordering", () => { /* assert durable identity */ });
});
```

## Required review evidence

1. Primary Microsoft documentation for every evidence source and interpretation.
2. Exact read-only Graph scope and endpoint already collected, or a separately reviewed collector change.
3. A plain-English prerequisite explaining what an attacker must control.
4. A negative statement separating configured possibility from observed use.
5. Stable identity derived from object, relationship, scope, or change IDs—not display names.
6. Positive, adjacent-negative, partial-coverage, tenant-isolation, ordering, and deterministic fixture contracts.

Do not add runtime plugin loading, Graph writes, raw Graph bodies, real tenant identifiers, credentials, or tokens to a rule fixture.
