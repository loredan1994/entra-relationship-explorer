import type { DirectoryNode, TenantSnapshot } from "@entra-explorer/domain";

/** Pair only a unique blueprint and tenant identity with a recorded application ID. */
export function applicationIdentityPair(snapshot: TenantSnapshot, selected: DirectoryNode) {
  const candidates = selected.appId?.trim() ? snapshot.nodes.filter(node =>
    node.tenantId === selected.tenantId && node.appId === selected.appId &&
    (node.kind === "application" || node.kind === "servicePrincipal"),
  ) : [selected];
  const blueprints = candidates.filter(node => node.kind === "application");
  const identities = candidates.filter(node => node.kind === "servicePrincipal");
  const ambiguous = blueprints.length > 1 || identities.length > 1;
  const nodes = ambiguous ? [selected] : candidates;
  return {
    nodes,
    blueprint: nodes.find(node => node.kind === "application"),
    tenantIdentity: nodes.find(node => node.kind === "servicePrincipal"),
    status: !selected.appId?.trim() ? "missing-app-id" : ambiguous ? "ambiguous" : blueprints.length && identities.length ? "matched" : "not-recorded",
  };
}
