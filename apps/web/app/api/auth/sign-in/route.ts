import { NextResponse } from "next/server";
import { getEntraConfig } from "@/server/config";
import { createAuthFlow } from "@/server/auth/flow-store";
import { authorizationUrl, createAuthorizationRequest } from "@/server/auth/msal";
import { AUTH_FLOW_COOKIE } from "@/server/auth/session-store";
import { noStoreJson } from "@/server/http";

export const dynamic = "force-dynamic";

export async function GET() {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 });

  const { verifier, challenge } = await createAuthorizationRequest(config);
  const flow = await createAuthFlow(config, verifier);
  const destination = await authorizationUrl(config, flow.state, challenge);
  const response = NextResponse.redirect(destination, { status: 302 });
  response.headers.set("cache-control", "no-store, private");
  response.cookies.set(AUTH_FLOW_COOKIE, flow.flowId, {
    httpOnly: true,
    secure: new URL(config.redirectUri).protocol === "https:",
    sameSite: "lax",
    maxAge: 10 * 60,
    path: "/api/auth",
    priority: "high",
  });
  return response;
}
