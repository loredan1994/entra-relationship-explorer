import { assertTenantBoundary } from "./queries";
import type { CredentialMetadata, TenantSnapshot } from "./types";

export type CredentialState = "expired" | "not-yet-valid" | "expires-soon" | "valid" | "unknown";
export function credentialStateAt(credential: CredentialMetadata, at: string): CredentialState {
  const now = Date.parse(at), start = Date.parse(String(credential.startsAt)), end = Date.parse(String(credential.expiresAt));
  if (!Number.isFinite(now)) throw new Error("A valid reference time is required.");
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return "unknown";
  if (end <= now) return "expired";
  if (start > now) return "not-yet-valid";
  return end - now <= 30 * 86400000 ? "expires-soon" : "valid";
}

export function credentialWorkbench(snapshot: TenantSnapshot) {
  assertTenantBoundary(snapshot);
  return snapshot.nodes.filter(n => ["application", "servicePrincipal", "managedIdentity"].includes(n.kind)).map(identity => {
    const credentials = (identity.credentials ?? []).map(credential => ({ ...credential, state: credentialStateAt(credential, snapshot.scannedAt) }));
    const usable = credentials.filter(c => c.state === "valid" || c.state === "expires-soon");
    const federation = snapshot.edges.filter(e => e.type === "FEDERATES_AS" && e.targetId === identity.id).map(edge => ({ edge, trust: snapshot.nodes.find(n => n.id === edge.sourceId)! }));
    const identityIds = new Set([identity.id, ...snapshot.edges.filter(e => e.type === "INSTANTIATES_AS" && e.sourceId === identity.id).map(e => e.targetId)]);
    const grants = snapshot.edges.filter(e => identityIds.has(e.sourceId) && ["CAN_CALL_AS_APP", "CAN_CALL_DELEGATED", "ACTIVE_IN_ROLE", "ELIGIBLE_FOR_ROLE"].includes(e.type));
    return { identity, credentials, federation, grants, inventoryKnown: identity.credentials !== undefined, usableCount: usable.length, rotationOverlap: usable.length > 1, expiredWithReplacement: usable.length > 0 && credentials.some(c => c.state === "expired") };
  });
}
