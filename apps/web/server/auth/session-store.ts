import "server-only";
import { randomUUID } from "node:crypto";
import type { AccountInfo, AuthenticationResult } from "@azure/msal-node";
import type { DurableSession } from "@entra-explorer/backend";
import type { LiveEntraConfig } from "../config-core";
import { getBackend } from "../backend";
import { acquireSilent } from "./msal";

export const SESSION_COOKIE = "entra_explorer_session";
export const AUTH_FLOW_COOKIE = "entra_explorer_auth_flow";

export type ServerSession = DurableSession & { account: AccountInfo };

export async function createServerSession(config: LiveEntraConfig, result: AuthenticationResult, tokenCache: string): Promise<ServerSession> {
  if (!result.account || result.account.tenantId !== config.tenantId) {
    throw new Error("The authenticated account does not belong to the configured tenant.");
  }
  if (!result.accessToken) throw new Error("Microsoft identity did not return a Graph access token.");
  const now = Date.now();
  const session: ServerSession = {
    id: randomUUID(),
    tenantId: result.account.tenantId,
    account: result.account,
    accessToken: result.accessToken,
    accessTokenExpiresAt: result.expiresOn?.getTime() ?? now + 55 * 60 * 1_000,
    tokenCache,
    sessionExpiresAt: now + config.sessionMaxAgeSeconds * 1_000,
  };
  await (await getBackend(config)).createSession(session);
  return session;
}

export async function getServerSession(id: string | undefined, config: LiveEntraConfig): Promise<ServerSession | null> {
  if (!id) return null;
  return (await (await getBackend(config)).getSession(id, config.tenantId)) as ServerSession | null;
}

export async function getSessionAccessToken(id: string | undefined, config: LiveEntraConfig): Promise<string | null> {
  const session = await getServerSession(id, config);
  if (!session || session.tenantId !== config.tenantId) return null;
  if (session.accessTokenExpiresAt - Date.now() > 5 * 60 * 1_000) return session.accessToken;
  const refreshed = await acquireSilent(config, session.account, session.tokenCache);
  if (!refreshed?.result.accessToken) return null;
  session.accessToken = refreshed.result.accessToken;
  session.accessTokenExpiresAt = refreshed.result.expiresOn?.getTime() ?? Date.now() + 55 * 60 * 1_000;
  session.tokenCache = refreshed.tokenCache;
  await (await getBackend(config)).updateSession(session);
  return session.accessToken;
}

export async function deleteServerSession(id: string | undefined, config: LiveEntraConfig): Promise<void> {
  if (id) await (await getBackend(config)).deleteSession(id, config.tenantId);
}
