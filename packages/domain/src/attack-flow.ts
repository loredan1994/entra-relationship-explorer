import type { AttackPath } from "./intelligence";
import type { TenantSnapshot } from "./types";

const EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4";

export interface AttackFlowBundle { type: "bundle"; id: string; objects: Array<Record<string, unknown>>; }

export function toAttackFlow(snapshot: TenantSnapshot, path: AttackPath): AttackFlowBundle {
  if (path.steps.length === 0) throw new Error("An Attack Flow export requires at least one attack step.");
  const timestamp = new Date(snapshot.scannedAt).toISOString();
  const actionIds = path.steps.map((item) => `attack-action--${stableUuid(`${snapshot.id}:${path.id}:${item.edgeId}`)}`);
  const extensions = { [EXTENSION_ID]: { extension_type: "new-sdo" } };
  const actions = path.steps.map((item, index) => ({
    type: "attack-action",
    spec_version: "2.1",
    id: actionIds[index],
    created: timestamp,
    modified: timestamp,
    name: item.relationship.replaceAll("_", " ").toLocaleLowerCase(),
    description: `${item.explanation} Evidence endpoint: ${item.sourceEndpoint}. Source object: ${item.source.id}. Target object: ${item.target.id}. Evidence class: ${item.evidenceClass}.`,
    ...(actionIds[index + 1] ? { effect_refs: [actionIds[index + 1]] } : {}),
    extensions,
  }));
  const flowId = `attack-flow--${stableUuid(`${snapshot.id}:${path.id}:flow`)}`;
  return {
    type: "bundle",
    id: `bundle--${stableUuid(`${snapshot.id}:${path.id}:bundle`)}`,
    objects: [{
      type: "attack-flow",
      spec_version: "2.1",
      id: flowId,
      created: timestamp,
      modified: timestamp,
      name: path.title,
      description: `Inferred IAM possibility from snapshot ${snapshot.id}. This is not evidence that exploitation occurred. Confidence: ${path.confidence}.`,
      scope: "attack-tree",
      start_refs: [actionIds[0]],
      external_references: path.attackMappings.map((mapping) => ({ source_name: "MITRE ATT&CK", external_id: mapping.id, description: mapping.name })),
      extensions,
    }, ...actions],
  };
}

function stableUuid(value: string): string {
  const bytes = new Uint8Array(16);
  // Stryker disable next-line EqualityOperator: a fifth pass writes past the 16-byte array, which a typed array drops.
  for (let pass = 0; pass < 4; pass += 1) {
    let hash = (2166136261 ^ pass) >>> 0;
    for (let index = 0; index < value.length; index += 1) { hash ^= value.charCodeAt(index); hash = Math.imul(hash, 16777619) >>> 0; }
    bytes[pass * 4] = hash >>> 24; bytes[pass * 4 + 1] = hash >>> 16; bytes[pass * 4 + 2] = hash >>> 8; bytes[pass * 4 + 3] = hash;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
