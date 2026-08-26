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
  const redirect = new URL(redirectUri);
  const isLocal = redirect.hostname === "localhost" || redirect.hostname === "127.0.0.1";
  if (redirect.protocol !== "https:" && !(isLocal && redirect.protocol === "http:")) {
    throw new Error("ENTRA_REDIRECT_URI must use HTTPS, except for a loopback local-development address.");
  }
  if (redirect.pathname !== "/api/auth/callback") {
    throw new Error("ENTRA_REDIRECT_URI must end at /api/auth/callback.");
  }
  if (environment.NODE_ENV === "production" && !(environment.ENTRA_ALLOW_LOCAL_CLIENT_SECRET === "true" && isLocal)) {
    throw new Error("Phase 1 local/admin authentication must not use a client secret in production; use the approved certificate or managed-identity phase.");
  }

  const dataEncryptionKey = Uint8Array.from(Buffer.from(encodedKey, "base64"));
  if (dataEncryptionKey.byteLength !== 32) throw new Error("ENTRA_DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");

  const requestedOptional = (environment.ENTRA_OPTIONAL_GRAPH_SCOPES ?? "").split(/[\s,]+/).filter(Boolean).map((scope) => scope.startsWith("https://") ? scope : `https://graph.microsoft.com/${scope}`);
  const approvedOptional = new Set<string>(OPTIONAL_GRAPH_SCOPES);
  for (const scope of requestedOptional) if (!approvedOptional.has(scope)) throw new Error(`Optional Graph scope is not approved by the product: ${scope}`);
  const graphScopes = [...CORE_GRAPH_SCOPES, ...requestedOptional];
  const scopes = [...IDENTITY_SCOPES, ...graphScopes];
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
    sessionMaxAgeSeconds: 60 * 60,
  };
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`${name} is required when ENTRA_ENABLE_LIVE=true.`);
  return value;
}
