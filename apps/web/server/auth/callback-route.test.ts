import { NextRequest } from "next/server";
import { MemoryBackend } from "@entra-explorer/backend";
import { beforeEach, expect, it, vi } from "vitest";
import type { LiveEntraConfig } from "../config-core";

const redeemAuthorizationCode = vi.fn();
const config = { enabled: true, tenantId: "11111111-1111-4111-8111-111111111111", redirectUri: "http://127.0.0.1:3200/api/auth/callback", sessionMaxAgeSeconds: 900 } as LiveEntraConfig;
let backend: MemoryBackend;
vi.mock("../config", () => ({ getEntraConfig: () => config }));
vi.mock("../backend", () => ({ getBackend: async () => backend }));
vi.mock("./msal", () => ({ redeemAuthorizationCode: (...args: unknown[]) => redeemAuthorizationCode(...args) }));

const { GET } = await import("../../app/api/auth/callback/route");
const { createAuthFlow } = await import("./flow-store");

beforeEach(() => {
  vi.resetAllMocks();
  backend = new MemoryBackend();
});

it("expires a rejected flow cookie on the recovery redirect without redeeming a code", async () => {
  const response = await GET(new NextRequest("http://127.0.0.1:3200/api/auth/callback?state=invalid&code=unused", { headers: { cookie: "entra_explorer_auth_flow=invalid" } }));
  expect(response.status).toBe(302);
  expect(response.headers.get("location")).toBe("http://127.0.0.1:3200/settings?authError=invalid_state");
  const cookie = response.headers.get("set-cookie");
  expect(cookie).toContain("entra_explorer_auth_flow=;");
  expect(cookie).toContain("Path=/api/auth;");
  expect(cookie).toContain("Max-Age=0;");
  expect(cookie).toContain("HttpOnly;");
  expect(redeemAuthorizationCode).not.toHaveBeenCalled();
});

it("preserves the newer pending sign-in when an older callback arrives with its cookie", async () => {
  const older = await createAuthFlow(config, "old-verifier");
  const newer = await createAuthFlow(config, "new-verifier");
  const callback = (state: string) => new NextRequest(`http://127.0.0.1:3200/api/auth/callback?state=${state}&code=synthetic-code`, { headers: { cookie: `entra_explorer_auth_flow=${newer.flowId}` } });

  // A second sign-in replaced the shared cookie before the first tab returned.
  const stale = await GET(callback(older.state));
  expect(stale.status).toBe(302);
  expect(stale.headers.get("location")).toBe("http://127.0.0.1:3200/settings?authError=invalid_state");
  expect(stale.headers.get("set-cookie")).toBeNull();
  expect(redeemAuthorizationCode).not.toHaveBeenCalled();

  redeemAuthorizationCode.mockResolvedValue({ result: { account: { tenantId: config.tenantId }, accessToken: "synthetic-token" }, tokenCache: "synthetic-cache" });
  const current = await GET(callback(newer.state));
  expect(current.status).toBe(302);
  expect(current.headers.get("location")).toBe("http://127.0.0.1:3200/settings?connected=1");
  expect(redeemAuthorizationCode).toHaveBeenCalledExactlyOnceWith(config, "synthetic-code", "new-verifier");
  const cookie = current.headers.get("set-cookie");
  expect(cookie).toContain("entra_explorer_auth_flow=;");
  const sessionId = cookie?.match(/entra_explorer_session=([0-9a-f-]{36})/)?.[1];
  expect(sessionId).toBeDefined();
  expect(await backend.getSession(sessionId!, config.tenantId)).toMatchObject({ tenantId: config.tenantId, accessToken: "synthetic-token" });
});
