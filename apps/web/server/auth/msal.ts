import {
  ConfidentialClientApplication,
  CryptoProvider,
  LogLevel,
  ResponseMode,
  type AccountInfo,
  type AuthenticationResult,
} from "@azure/msal-node";
import type { LiveEntraConfig } from "../config-core";

const cryptoProvider = new CryptoProvider();

export function getMsalClient(config: LiveEntraConfig): ConfidentialClientApplication {
  return new ConfidentialClientApplication({
    auth: {
      clientId: config.clientId,
      authority: config.authority,
      clientSecret: config.clientSecret,
    },
    system: {
      loggerOptions: {
        piiLoggingEnabled: false,
        logLevel: LogLevel.Error,
        loggerCallback: () => undefined,
      },
    },
  });
}

export async function createAuthorizationRequest(config: LiveEntraConfig) {
  const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
  return { verifier, challenge };
}

export async function authorizationUrl(
  config: LiveEntraConfig,
  state: string,
  challenge: string,
): Promise<string> {
  return getMsalClient(config).getAuthCodeUrl({
    scopes: config.scopes,
    redirectUri: config.redirectUri,
    state,
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
    responseMode: ResponseMode.QUERY,
    prompt: "select_account",
  });
}

export async function redeemAuthorizationCode(
  config: LiveEntraConfig,
  code: string,
  verifier: string,
): Promise<{ result: AuthenticationResult; tokenCache: string }> {
  const client = getMsalClient(config);
  const result = await client.acquireTokenByCode({
    code,
    scopes: config.scopes,
    redirectUri: config.redirectUri,
    codeVerifier: verifier,
  });
  return { result, tokenCache: client.getTokenCache().serialize() };
}

export async function acquireSilent(
  config: LiveEntraConfig,
  account: AccountInfo,
  tokenCache: string,
): Promise<{ result: AuthenticationResult; tokenCache: string } | null> {
  const client = getMsalClient(config);
  await client.getTokenCache().deserialize(tokenCache);
  const result = await client.acquireTokenSilent({ account, scopes: config.graphScopes });
  return result ? { result, tokenCache: client.getTokenCache().serialize() } : null;
}
