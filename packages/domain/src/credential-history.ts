import { compareSnapshots } from "./comparisons";
import { endpointWasCollected } from "./coverage";
import { credentialStateAt } from "./credential-workbench";
import type { CredentialMetadata, DirectoryNode, TenantSnapshot } from "./types";

interface HistoryEntry {
  id: string;
  kind: "password" | "certificate" | "federation";
  details: Record<string, string | null>;
  sourceEndpoint: string;
  state?: string;
}
export interface CredentialChange {
  identityId: string;
  identityLabel: string;
  credentialId: string;
  kind: HistoryEntry["kind"];
  change: "added" | "removed" | "changed" | "validity-changed" | "unconfirmed";
  before: HistoryEntry | null;
  after: HistoryEntry | null;
  reason: string;
  sourceEndpoints: string[];
}

/** Per-key and per-trust history. Time passing is separate from configuration edits. */
export function credentialHistory(before: TenantSnapshot, after: TenantSnapshot): CredentialChange[] {
  compareSnapshots(before, after); // Enforce the same tenant and temporal boundary as the timeline.
  const identities = new Map([...before.nodes, ...after.nodes].filter(n => ["application", "servicePrincipal", "managedIdentity"].includes(n.kind)).map(n => [n.id, n]));
  const changes: CredentialChange[] = [];
  for (const identity of identities.values()) {
    const oldNode = before.nodes.find(n => n.id === identity.id);
    const newNode = after.nodes.find(n => n.id === identity.id);
    const oldEntries = entries(before, identity.id, oldNode);
    const newEntries = entries(after, identity.id, newNode);
    const keys = new Set([...oldEntries.keys(), ...newEntries.keys()]);
    for (const key of keys) {
      const old = oldEntries.get(key) ?? null, current = newEntries.get(key) ?? null;
      if (old && current && JSON.stringify(old.details) === JSON.stringify(current.details) && old.state === current.state) continue;
      const item = current ?? old!;
      const endpoint = item.sourceEndpoint;
      const known = inventoryKnown(before, oldNode, identity, item.kind, endpoint) && inventoryKnown(after, newNode, identity, item.kind, endpoint);
      const change = !known ? "unconfirmed" : !old ? "added" : !current ? "removed" : JSON.stringify(old.details) !== JSON.stringify(current.details) ? "changed" : "validity-changed";
      changes.push({ identityId: identity.id, identityLabel: identity.label, credentialId: item.id, kind: item.kind, change, before: old, after: current,
        reason: !known ? "Missing inventory or incomplete source coverage prevents confirming this difference."
          : change === "validity-changed" ? "The validity interval is unchanged; time passing changed its state. This is not a tenant configuration edit."
          : "Credential or trust metadata differs between the selected snapshots. This does not prove deployment or use.",
        sourceEndpoints: [...new Set([old?.sourceEndpoint, current?.sourceEndpoint].filter((e): e is string => Boolean(e)))] });
    }
  }
  return changes.sort((a, b) => `${a.identityLabel}:${a.kind}:${a.credentialId}`.localeCompare(`${b.identityLabel}:${b.kind}:${b.credentialId}`));
}

function entries(snapshot: TenantSnapshot, identityId: string, node: DirectoryNode | undefined): Map<string, HistoryEntry> {
  const result = new Map<string, HistoryEntry>();
  for (const c of node?.credentials ?? []) result.set(`${c.kind}:${c.id}`, credentialEntry(c, snapshot.scannedAt));
  for (const edge of snapshot.edges.filter(e => e.type === "FEDERATES_AS" && e.targetId === identityId)) {
    // compareSnapshots already validates that every edge endpoint exists.
    const trust = snapshot.nodes.find(n => n.id === edge.sourceId)!;
    result.set(`federation:${trust.id}`, { id: trust.id, kind: "federation", details: { label: trust.label, issuer: value(trust, "issuer"), subject: value(trust, "subject"), audiences: value(trust, "audiences") }, sourceEndpoint: edge.evidence.sourceEndpoint });
  }
  return result;
}
function value(node: DirectoryNode, key: string): string | null { const v = node.metadata?.[key]; return v === undefined || v === null ? null : String(v); }
function credentialEntry(c: CredentialMetadata, at: string): HistoryEntry {
  return { id: c.id, kind: c.kind, details: { label: c.label, startsAt: c.startsAt, expiresAt: c.expiresAt }, sourceEndpoint: c.sourceEndpoint, state: credentialStateAt(c, at) };
}
function inventoryKnown(snapshot: TenantSnapshot, node: DirectoryNode | undefined, identity: DirectoryNode, kind: HistoryEntry["kind"], endpoint: string): boolean {
  if (!node) return endpointWasCollected(snapshot, identity.kind === "application" ? "/applications" : "/servicePrincipals");
  if (kind === "federation" && endpoint.split("?")[0] === "/servicePrincipals") {
    // Base identity inventory does not collect the optional federation expansion.
    const isFederationRead = (value: string) => value.split("?")[0] === "/servicePrincipals" && Boolean(new URLSearchParams(value.split("?")[1]).get("$expand")?.includes("federatedIdentityCredentials"));
    return snapshot.completion.collectedEndpoints.some(isFederationRead) && !snapshot.completion.skippedEndpoints.some(isFederationRead);
  }
  if (kind !== "federation" && node.credentials === undefined) return false;
  return endpointWasCollected(snapshot, endpoint);
}
