import { describe, expect, it } from "vitest";
import { toAttackFlow } from "./attack-flow";
import type { AttackPath } from "./intelligence";
import { snapshot } from "./test-support";

const EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4";
const SCANNED_AT = "2026-08-26T10:00:00.000Z";

/** A fully pinned path, so generated identifiers are reproducible. */
function fixedPath(): AttackPath {
  return {
    id: "path-abcd1234",
    title: "Maya Chen can reach Microsoft Graph",
    severity: "critical",
    confidence: "medium",
    source: { id: "user-1", label: "Maya Chen" },
    target: { id: "sp-graph", label: "Microsoft Graph" },
    steps: [
      {
        index: 0, edgeId: "edge-owns", source: { id: "user-1", label: "Maya Chen" }, target: { id: "sp-1", label: "Orchestrator" },
        relationship: "OWNS", permissions: [], evidenceClass: "configured", sourceEndpoint: "/applications/app-1/owners",
        explanation: "Maya Chen owns Orchestrator.",
      },
      {
        index: 1, edgeId: "edge-call", source: { id: "sp-1", label: "Orchestrator" }, target: { id: "sp-graph", label: "Microsoft Graph" },
        relationship: "CAN_CALL_AS_APP", permissions: ["Directory.ReadWrite.All"], evidenceClass: "configured",
        sourceEndpoint: "/servicePrincipals/sp-graph/appRoleAssignedTo",
        explanation: "Orchestrator is configured to call Microsoft Graph as the application.",
      },
    ],
    prerequisites: ["An attacker first controls Maya Chen or a session/credential able to act as it."],
    attackMappings: [{ id: "T1098", name: "Account Manipulation" }, { id: "T1078.004", name: "Valid Accounts: Cloud Accounts" }],
    mitigations: ["Review and remove unnecessary Directory.ReadWrite.All access to Microsoft Graph."],
    uncertainty: ["This is an inferred possibility built from configured relationships; it is not evidence that exploitation occurred."],
  };
}

const snap = () => snapshot([], [], { id: "snapshot-fixed", scannedAt: SCANNED_AT });
const bundle = () => toAttackFlow(snap(), fixedPath());
const flowObject = () => bundle().objects.find((object) => object.type === "attack-flow")!;
const actionObjects = () => bundle().objects.filter((object) => object.type === "attack-action");

describe("STIX conformance", () => {
  it("declares the bundle and every object with the expected STIX types", () => {
    const result = bundle();
    expect(result.type).toBe("bundle");
    expect(result.objects.map((object) => object.type)).toEqual(["attack-flow", "attack-action", "attack-action"]);
  });

  it("stamps every object with STIX spec version 2.1", () => {
    for (const object of bundle().objects) expect(object.spec_version).toBe("2.1");
  });

  it("registers the Attack Flow extension on every object as a new SDO", () => {
    for (const object of bundle().objects) {
      expect(object.extensions).toEqual({ [EXTENSION_ID]: { extension_type: "new-sdo" } });
    }
  });

  it("scopes the flow as an attack tree", () => {
    expect(flowObject().scope).toBe("attack-tree");
  });

  it("prefixes each identifier with its own object type", () => {
    const result = bundle();
    expect(String(result.id).startsWith("bundle--")).toBe(true);
    expect(String(flowObject().id).startsWith("attack-flow--")).toBe(true);
    for (const action of actionObjects()) expect(String(action.id).startsWith("attack-action--")).toBe(true);
  });

  it("gives the bundle, flow, and each action distinct identifiers", () => {
    const result = bundle();
    const ids = [result.id, ...result.objects.map((object) => object.id)];
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("generated identifiers", () => {
  it("derives the same identifiers every time from the same snapshot and path", () => {
    expect(bundle()).toEqual(bundle());
  });

  it("keeps the identifiers of a known snapshot and path unchanged", () => {
    // Golden values: exported flows are archived and re-imported, so a change in how an
    // identifier is derived would orphan every bundle already exported.
    const single = { ...fixedPath(), steps: [fixedPath().steps[0]!], attackMappings: [], mitigations: [], prerequisites: [], uncertainty: [] };
    const result = toAttackFlow(snapshot([], [], { id: "snapshot-fixed", scannedAt: SCANNED_AT }), single);
    expect(result.id).toBe("bundle--8a5a819c-6aa5-4dab-ad73-4356f93fbe85");
    expect(result.objects[0]!.id).toBe("attack-flow--706bfe24-59cf-4b27-93b4-99e28c448a15");
    expect(result.objects[1]!.id).toBe("attack-action--280282f5-5ba3-4128-b0f0-9c27b5be75a2");
  });

  it("mints identifiers that are valid version 4 UUIDs", () => {
    for (const object of bundle().objects) {
      const [, uuid] = String(object.id).split("--");
      expect(uuid, String(object.id)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    }
  });

  it("changes the identifiers when the snapshot changes", () => {
    const other = toAttackFlow(snapshot([], [], { id: "snapshot-other", scannedAt: SCANNED_AT }), fixedPath());
    expect(other.id).not.toBe(bundle().id);
    expect(other.objects[0]!.id).not.toBe(flowObject().id);
  });

  it("changes the identifiers when the path changes", () => {
    const other = toAttackFlow(snap(), { ...fixedPath(), id: "path-99999999" });
    expect(other.id).not.toBe(bundle().id);
  });

  it("gives each step its own action identifier, derived from that step's edge", () => {
    const [first, second] = actionObjects();
    expect(first!.id).not.toBe(second!.id);
    const renamed = toAttackFlow(snap(), {
      ...fixedPath(),
      steps: [{ ...fixedPath().steps[0]!, edgeId: "edge-different" }, fixedPath().steps[1]!],
    });
    expect(renamed.objects[1]!.id).not.toBe(first!.id);
    // The untouched second step keeps its identifier.
    expect(renamed.objects[2]!.id).toBe(second!.id);
  });
});

describe("flow narrative", () => {
  it("names the flow after the path and starts it at the first action", () => {
    expect(flowObject().name).toBe("Maya Chen can reach Microsoft Graph");
    expect(flowObject().start_refs).toEqual([actionObjects()[0]!.id]);
  });

  it("chains each action to the next and leaves the last one terminal", () => {
    const actions = actionObjects();
    expect(actions[0]!.effect_refs).toEqual([actions[1]!.id]);
    expect(actions[1]!.effect_refs).toBeUndefined();
  });

  it("names each action after its relationship in plain lowercase words", () => {
    expect(actionObjects().map((action) => action.name)).toEqual(["owns", "can call as app"]);
  });

  it("states the snapshot, the inference caveat, and the confidence in the description", () => {
    expect(flowObject().description).toBe(
      "Inferred IAM possibility from snapshot snapshot-fixed. This is not evidence that exploitation occurred. Confidence: medium.",
    );
  });

  it("carries every MITRE mapping as an external reference", () => {
    expect(flowObject().external_references).toEqual([
      { source_name: "MITRE ATT&CK", external_id: "T1098", description: "Account Manipulation" },
      { source_name: "MITRE ATT&CK", external_id: "T1078.004", description: "Valid Accounts: Cloud Accounts" },
    ]);
  });

  it("keeps each action explainable with endpoint, both object ids, and evidence class", () => {
    expect(actionObjects()[1]!.description).toBe(
      "Orchestrator is configured to call Microsoft Graph as the application. " +
      "Evidence endpoint: /servicePrincipals/sp-graph/appRoleAssignedTo. " +
      "Source object: sp-1. Target object: sp-graph. Evidence class: configured.",
    );
  });

  it("stamps every object with the snapshot scan time", () => {
    for (const object of bundle().objects) {
      expect(object.created).toBe(SCANNED_AT);
      expect(object.modified).toBe(SCANNED_AT);
    }
  });

  it("refuses to export a path with no steps", () => {
    expect(() => toAttackFlow(snap(), { ...fixedPath(), steps: [] })).toThrow(/at least one attack step/);
  });

  it("exports a single-step path as one terminal action", () => {
    const single = toAttackFlow(snap(), { ...fixedPath(), steps: [fixedPath().steps[0]!] });
    const actions = single.objects.filter((object) => object.type === "attack-action");
    expect(actions).toHaveLength(1);
    expect(actions[0]!.effect_refs).toBeUndefined();
    expect(single.objects.find((object) => object.type === "attack-flow")!.start_refs).toEqual([actions[0]!.id]);
  });
});
