import { describe, expect, it } from "vitest";
import { cleanProjectFixture } from "./fixtures";
import { analyzeTenantIntelligence } from "./intelligence";
import { toAttackFlow } from "./attack-flow";

describe("Attack Flow export", () => {
  it("creates a deterministic STIX 2.1 chain with evidence language", () => {
    const path = analyzeTenantIntelligence(cleanProjectFixture).paths[0]!;
    const bundle = toAttackFlow(cleanProjectFixture, path);
    expect(bundle.type).toBe("bundle");
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);
    const flow = bundle.objects.find((item) => item.type === "attack-flow")!;
    expect(flow.start_refs).toHaveLength(1);
    expect(flow.description).toContain("not evidence");
    expect(bundle.objects.filter((item) => item.type === "attack-action")).toHaveLength(path.steps.length);
    expect(toAttackFlow(cleanProjectFixture, path).id).toBe(bundle.id);
  });
});
