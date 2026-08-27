import { assertReadOnlyScopes, CORE_GRAPH_SCOPES, IDENTITY_SCOPES, OPTIONAL_GRAPH_SCOPES } from "@entra-explorer/graph";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface LiveEntraConfig {
  enabled: true;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authority: string;
  scopes: string[];
  graphScopes: string[];
  databaseUrl: string;
  dataEncryptionKey: Uint8Array;
  sessionMaxAgeSeconds: number;
}

export interface DisabledEntraConfig {
  enabled: false;
  reason: string;
}

export type EntraConfig = LiveEntraConfig | DisabledEntraConfig;

export function parseEntraConfig(environment: NodeJS.ProcessEnv): EntraConfig {
  if (environment.ENTRA_ENABLE_LIVE !== "true") {
    return { enabled: false, reason: "Live Microsoft Entra access is disabled. The product is using synthetic fixtures." };
  }

  const tenantId = required(environment, "ENTRA_TENANT_ID");
  const clientId = required(environment, "ENTRA_CLIENT_ID");
  const clientSecret = required(environment, "ENTRA_CLIENT_SECRET");
  const redirectUri = required(environment, "ENTRA_REDIRECT_URI");
  const encodedKey = required(environment, "ENTRA_DATA_ENCRYPTION_KEY");
  const databaseUrl = required(environment, "DATABASE_URL");

  if (!UUID_PATTERN.test(tenantId)) throw new Error("ENTRA_TENANT_ID must be a concrete tenant UUID; common and organizations are not allowed.");
  if (!UUID_PATTERN.test(clientId)) throw new Error("ENTRA_CLIENT_ID must be a UUID.");
  const redirect = approvedRedirect(redirectUri);
  assertSecretIsAllowedHere(environment, redirect);

  const dataEncryptionKey = Uint8Array.from(Buffer.from(encodedKey, "base64"));
  if (dataEncryptionKey.byteLength !== 32) throw new Error("ENTRA_DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");

  const sessionMaxAgeSeconds = parseSessionMaxAge(environment.ENTRA_SESSION_MAX_AGE_SECONDS);
  const graphScopes = [...CORE_GRAPH_SCOPES, ...approvedOptionalScopes(environment.ENTRA_OPTIONAL_GRAPH_SCOPES)];
  const scopes = [...IDENTITY_SCOPES, ...graphScopes];
  // Stryker disable next-line all: defense in depth. Every scope reaching this line is already
  // on the product allow-list, so no input can make removing the assertion observable — it exists
  // to fail loudly if that allow-list ever grows a write-capable scope.
  assertReadOnlyScopes(scopes);
  return {
    enabled: true,
    tenantId,
    clientId,
    clientSecret,
    redirectUri: redirect.toString(),
    authority: `https://login.microsoftonline.com/${tenantId}`,
    scopes,
    graphScopes,
    databaseUrl,
    dataEncryptionKey,
    sessionMaxAgeSeconds,
  };
}


/** The sign-in redirect must be HTTPS, or plain HTTP only on a loopback development address. */
function approvedRedirect(redirectUri: string): URL {
  const redirect = new URL(redirectUri);
  // Stryker disable next-line ConditionalExpression: a non-HTTPS scheme other than loopback HTTP is rejected by the same test either way.
  if (redirect.protocol !== "https:" && !(isLoopback(redirect) && redirect.protocol === "http:")) {
    throw new Error("ENTRA_REDIRECT_URI must use HTTPS, except for a loopback local-development address.");
  }
  if (redirect.pathname !== "/api/auth/callback") {
    throw new Error("ENTRA_REDIRECT_URI must end at /api/auth/callback.");
  }
  return redirect;
}

/** Phase 1 signs in with a client secret, which production may only do against loopback. */
function assertSecretIsAllowedHere(environment: NodeJS.ProcessEnv, redirect: URL): void {
  if (environment.NODE_ENV === "production" && !(environment.ENTRA_ALLOW_LOCAL_CLIENT_SECRET === "true" && isLoopback(redirect))) {
    throw new Error("Phase 1 local/admin authentication must not use a client secret in production; use the approved certificate or managed-identity phase.");
  }
}

function isLoopback(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1";
}

/** Optional evidence scopes the operator asked for, checked against the product's own list. */
function approvedOptionalScopes(raw: string | undefined): string[] {
  // Stryker disable next-line Regex: filter(Boolean) drops the empty entries a single-character separator would leave, so the quantifier cannot change the result.
  const requested = (raw ?? "").split(/[\s,]+/).filter(Boolean).map((scope) => scope.startsWith("https://") ? scope : `https://graph.microsoft.com/${scope}`);
  const approved = new Set<string>(OPTIONAL_GRAPH_SCOPES);
  for (const scope of requested) if (!approved.has(scope)) throw new Error(`Optional Graph scope is not approved by the product: ${scope}`);
  return requested;
}

// Bounded to [15 minutes, 24 hours]; Graph access tokens are still refreshed on
// their own shorter schedule, so a longer app session never extends token life.
function parseSessionMaxAge(raw: string | undefined): number {
  const defaultSeconds = 8 * 60 * 60;
  if (!raw?.trim()) return defaultSeconds;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) throw new Error("ENTRA_SESSION_MAX_AGE_SECONDS must be an integer number of seconds.");
  return Math.min(24 * 60 * 60, Math.max(15 * 60, parsed));
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`${name} is required when ENTRA_ENABLE_LIVE=true.`);
  return value;
}
