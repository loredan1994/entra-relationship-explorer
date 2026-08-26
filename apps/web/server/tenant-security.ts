import { relationships, type DirectoryNode, type NodeKind, type TenantSnapshot } from "@entra-explorer/domain";

/**
 * Tenant exposure analysis over a read-only snapshot.
 *
 * Everything here describes *configured* access. A grant appearing on this page means the
 * permission exists, never that it was used; the product does not collect activity.
 */

export type Exposure = "high" | "review" | "low";

/**
 * Permissions that let an application change the directory itself, including granting
 * itself more access. These are the escalation paths worth finding first.
 */
const ESCALATION_PERMISSIONS = new Set([
  "approleassignment.readwrite.all",
  "rolemanagement.readwrite.directory",
  "application.readwrite.all",
  "directory.readwrite.all",
  "privilegedaccess.readwrite.azuread",
  "user.readwrite.all",
  "group.readwrite.all",
]);

const WRITE_PATTERN = /\.(readwrite|write|send|manage|fullcontrol)\b/i;

export interface PermissionGrant {
  edgeId: string;
  caller: { id: string; label: string; kind: NodeKind };
  resource: { id: string; label: string; kind: NodeKind };
  accessType: "application" | "delegated";
  permissions: string[];
  writeCapable: string[];
  tenantWide: string[];
  escalation: string[];
  exposure: Exposure;
  reason: string;
  sourceEndpoint: string;
  scannedAt: string;
}

export interface OwnershipGap {
  id: string;
  label: string;
  kind: NodeKind;
  appId: string | null;
  grantCount: number;
}

export interface CredentialIssue {
  id: string;
  label: string;
  status: "expired" | "expiring";
  expiresAt: string | null;
  daysRemaining: number | null;
}

export interface ReviewItem {
  id: string;
  label: string;
  kind: NodeKind;
  level: "review" | "high";
  reason: string;
}

export interface TenantSecurityView {
  mode: "fixture" | "tenant";
  tenantLabel: string;
  scannedAt: string;
  completion: "complete" | "partial";
  summary: {
    applicationGrants: number;
    delegatedGrants: number;
    writeCapableGrants: number;
    escalationGrants: number;
    unowned: number;
    credentialIssues: number;
  };
  grants: PermissionGrant[];
  ownership: OwnershipGap[];
  credentials: CredentialIssue[];
  review: ReviewItem[];
}

export function isWriteCapable(permission: string): boolean {
  return WRITE_PATTERN.test(permission);
}

export function isTenantWide(permission: string): boolean {
  return permission.toLowerCase().endsWith(".all");
}

export function isEscalation(permission: string): boolean {
  return ESCALATION_PERMISSIONS.has(permission.toLowerCase());
}

/**
 * Application permissions run with no signed-in person, so the app's own identity carries
 * the access. That makes an app-only write far more exposed than the same delegated one,
 * which is still bounded by what the signed-in person may do.
 */
function assess(
  accessType: PermissionGrant["accessType"],
  writeCapable: string[],
  tenantWide: string[],
  escalation: string[],
): { exposure: Exposure; reason: string } {
  const appOnly = accessType === "application";
  if (escalation.length > 0) {
    return {
      exposure: appOnly ? "high" : "review",
      reason: appOnly
        ? `Runs as itself and can change the directory using ${escalation.join(" and ")}. An app that can assign permissions can widen its own access.`
        : `Can change the directory as the signed-in person using ${escalation.join(" and ")}.`,
    };
  }
  const broadWrite = writeCapable.filter((permission) => tenantWide.includes(permission));
  if (appOnly && broadWrite.length > 0) {
    return {
      exposure: "high",
      reason: `Runs as itself and can write across the whole tenant using ${broadWrite.join(" and ")}.`,
    };
  }
  if (writeCapable.length > 0) {
    return {
      exposure: "review",
      reason: appOnly
        ? `Runs as itself, with no signed-in person, and can write using ${writeCapable.join(" and ")}.`
        : `Can write on behalf of a signed-in person using ${writeCapable.join(" and ")}.`,
    };
  }
  if (appOnly && tenantWide.length > 0) {
    return { exposure: "review", reason: `Reads across the whole tenant as itself using ${tenantWide.join(" and ")}.` };
  }
  return { exposure: "low", reason: "Read-only access to a single resource." };
}

const EXPOSURE_ORDER: Record<Exposure, number> = { high: 0, review: 1, low: 2 };

function daysUntil(value: string | null, now: number): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : Math.round((parsed - now) / 86_400_000);
}

function isAccountable(node: DirectoryNode): boolean {
  return node.kind === "application" || node.kind === "servicePrincipal";
}

export function analyzeTenantSecurity(snapshot: TenantSnapshot, now = Date.now()): TenantSecurityView {
  const views = relationships(snapshot);

  const grants: PermissionGrant[] = views
    .filter(({ edge }) => edge.type === "CAN_CALL_AS_APP" || edge.type === "CAN_CALL_DELEGATED")
    .map(({ edge, source, target }) => {
      const accessType: PermissionGrant["accessType"] = edge.type === "CAN_CALL_AS_APP" ? "application" : "delegated";
      const writeCapable = edge.permissions.filter(isWriteCapable);
      const tenantWide = edge.permissions.filter(isTenantWide);
      const escalation = edge.permissions.filter(isEscalation);
      const { exposure, reason } = assess(accessType, writeCapable, tenantWide, escalation);
      return {
        edgeId: edge.id,
        caller: { id: source.id, label: source.label, kind: source.kind },
        resource: { id: target.id, label: target.label, kind: target.kind },
        accessType,
        permissions: edge.permissions,
        writeCapable,
        tenantWide,
        escalation,
        exposure,
        reason,
        sourceEndpoint: edge.evidence.sourceEndpoint,
        scannedAt: edge.evidence.scannedAt,
      };
    })
    .sort((a, b) => EXPOSURE_ORDER[a.exposure] - EXPOSURE_ORDER[b.exposure] || a.caller.label.localeCompare(b.caller.label));

  const grantsByCaller = grants.reduce<Map<string, number>>((totals, grant) => {
    totals.set(grant.caller.id, (totals.get(grant.caller.id) ?? 0) + 1);
    return totals;
  }, new Map());

  const ownership: OwnershipGap[] = snapshot.nodes
    .filter((node) => isAccountable(node) && node.ownerIds.length === 0)
    .map((node) => ({
      id: node.id,
      label: node.label,
      kind: node.kind,
      appId: node.appId ?? null,
      grantCount: grantsByCaller.get(node.id) ?? 0,
    }))
    .sort((a, b) => b.grantCount - a.grantCount || a.label.localeCompare(b.label));

  const credentials: CredentialIssue[] = snapshot.nodes
    .flatMap((node) => {
      const credential = node.credential;
      if (!credential || credential.status === "healthy" || credential.status === "none") return [];
      const daysRemaining = daysUntil(credential.expiresAt, now);
      return [{
        id: node.id,
        label: node.label,
        status: credential.status,
        expiresAt: credential.expiresAt,
        daysRemaining,
      }];
    })
    .sort((a, b) => (a.daysRemaining ?? Number.MAX_SAFE_INTEGER) - (b.daysRemaining ?? Number.MAX_SAFE_INTEGER));

  const review: ReviewItem[] = snapshot.nodes
    .filter((node): node is DirectoryNode & { risk: { level: "review" | "high"; reason: string } } => node.risk.level !== "low")
    .map((node) => ({ id: node.id, label: node.label, kind: node.kind, level: node.risk.level, reason: node.risk.reason }))
    .sort((a, b) => (a.level === b.level ? a.label.localeCompare(b.label) : a.level === "high" ? -1 : 1));

  return {
    mode: snapshot.mode,
    tenantLabel: snapshot.tenant.tenantLabel,
    scannedAt: snapshot.scannedAt,
    completion: snapshot.completion.status,
    summary: {
      applicationGrants: grants.filter((grant) => grant.accessType === "application").length,
      delegatedGrants: grants.filter((grant) => grant.accessType === "delegated").length,
      writeCapableGrants: grants.filter((grant) => grant.writeCapable.length > 0).length,
      escalationGrants: grants.filter((grant) => grant.escalation.length > 0).length,
      unowned: ownership.length,
      credentialIssues: credentials.length,
    },
    grants,
    ownership,
    credentials,
    review,
  };
}
