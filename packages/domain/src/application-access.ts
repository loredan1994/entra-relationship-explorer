import { endpointWasCollected } from "./coverage";
import { assertTenantBoundary } from "./queries";
import type { DirectoryNode, RelationshipEdge, TenantSnapshot } from "./types";

export interface ApplicationAccessReview {
  identity: DirectoryNode;
  registration: DirectoryNode | null;
  incoming: RelationshipEdge[];
  owners: RelationshipEdge[];
  observations: RelationshipEdge[];
  assignmentsCollected: boolean;
  consentCollected: boolean;
  ownersCollected: boolean;
}

/** Direct configured relationships only. Group assignments do not enumerate effective users. */
export function applicationAccessReviews(snapshot: TenantSnapshot): ApplicationAccessReview[] {
  assertTenantBoundary(snapshot);
  const registrations = new Map(snapshot.nodes.filter(n => n.kind === "application" && n.appId).map(n => [n.appId!, n]));
  const reviews = new Map<string, ApplicationAccessReview>();
  for (const identity of snapshot.nodes) {
    if (identity.kind !== "servicePrincipal" && identity.kind !== "managedIdentity") continue;
    reviews.set(identity.id, {
      identity,
      registration: identity.appId ? registrations.get(identity.appId) ?? null : null,
      incoming: [], owners: [], observations: [],
      assignmentsCollected: endpointWasCollected(snapshot, `/servicePrincipals/${identity.id}/appRoleAssignedTo`),
      consentCollected: endpointWasCollected(snapshot, "/oauth2PermissionGrants"),
      ownersCollected: endpointWasCollected(snapshot, `/servicePrincipals/${identity.id}/owners`),
    });
  }
  for (const edge of snapshot.edges) {
    const review = reviews.get(edge.targetId);
    if (!review) continue;
    if (edge.type === "OBSERVED_CALL" && edge.evidence.observed) review.observations.push(edge);
    if (!edge.evidence.configured) continue;
    if (["ASSIGNED_TO", "CAN_CALL_AS_APP", "CAN_CALL_DELEGATED"].includes(edge.type)) review.incoming.push(edge);
    if (edge.type === "OWNS") review.owners.push(edge);
  }
  return [...reviews.values()].sort((a, b) => a.identity.label.localeCompare(b.identity.label) || a.identity.id.localeCompare(b.identity.id));
}

export function signInAudienceLabel(value: string | null | undefined): string {
  switch (value) {
    case "AzureADMyOrg": return "This organization (single tenant)";
    case "AzureADMultipleOrgs": return "Any organization (multiple tenants)";
    case "AzureADandPersonalMicrosoftAccount": return "Any organization and personal Microsoft accounts";
    case "PersonalMicrosoftAccount": return "Personal Microsoft accounts";
    default: return value ? `Unrecognized audience (${value})` : "Unknown — not recorded";
  }
}
