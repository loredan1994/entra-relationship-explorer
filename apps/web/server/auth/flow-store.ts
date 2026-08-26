import "server-only";
import { randomBytes, randomUUID } from "node:crypto";
import type { LiveEntraConfig } from "../config-core";
import { getBackend } from "../backend";

const FLOW_MAX_AGE_MS = 10 * 60 * 1_000;

export async function createAuthFlow(config: LiveEntraConfig, verifier: string): Promise<{ flowId: string; state: string }> {
  const flowId = randomUUID();
  const state = randomBytes(32).toString("base64url");
  await (await getBackend(config)).createAuthFlow({ id: flowId, tenantId: config.tenantId, state, verifier, expiresAt: Date.now() + FLOW_MAX_AGE_MS });
  return { flowId, state };
}

export async function consumeAuthFlow(config: LiveEntraConfig, flowId: string | undefined, returnedState: string | null) {
  if (!flowId || !returnedState) return null;
  return (await getBackend(config)).consumeAuthFlow(flowId, config.tenantId, returnedState);
}
