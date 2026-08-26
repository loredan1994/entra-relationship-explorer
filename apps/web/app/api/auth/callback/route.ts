import { NextRequest, NextResponse } from "next/server";
import { consumeAuthFlow } from "@/server/auth/flow-store";
import { redeemAuthorizationCode } from "@/server/auth/msal";
import { AUTH_FLOW_COOKIE, createServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { noStoreJson } from "@/server/http";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 });

  const settingsUrl = new URL("/settings", config.redirectUri);
  const providerError = request.nextUrl.searchParams.get("error");
  if (providerError) {
    settingsUrl.searchParams.set("authError", providerError === "access_denied" ? "access_denied" : "identity_error");
    return clearFlowCookie(NextResponse.redirect(settingsUrl, { status: 302 }), config.redirectUri);
  }

  const flow = await consumeAuthFlow(
    config,
    request.cookies.get(AUTH_FLOW_COOKIE)?.value,
    request.nextUrl.searchParams.get("state"),
  );
  const code = request.nextUrl.searchParams.get("code");
  if (!flow || !code) {
    settingsUrl.searchParams.set("authError", "invalid_state");
    return clearFlowCookie(NextResponse.redirect(settingsUrl, { status: 302 }), config.redirectUri);
  }

  try {
    const redeemed = await redeemAuthorizationCode(config, code, flow.verifier);
    const session = await createServerSession(config, redeemed.result, redeemed.tokenCache);
    settingsUrl.searchParams.set("connected", "1");
    const response = clearFlowCookie(NextResponse.redirect(settingsUrl, { status: 302 }), config.redirectUri);
    response.cookies.set(SESSION_COOKIE, session.id, {
      httpOnly: true,
      secure: new URL(config.redirectUri).protocol === "https:",
      sameSite: "lax",
      maxAge: config.sessionMaxAgeSeconds,
      path: "/",
      priority: "high",
    });
    response.headers.set("cache-control", "no-store, private");
    return response;
  } catch {
    settingsUrl.searchParams.set("authError", "token_exchange_failed");
    return clearFlowCookie(NextResponse.redirect(settingsUrl, { status: 302 }), config.redirectUri);
  }
}

function clearFlowCookie(response: NextResponse, redirectUri: string): NextResponse {
  response.cookies.set(AUTH_FLOW_COOKIE, "", {
    httpOnly: true,
    secure: new URL(redirectUri).protocol === "https:",
    sameSite: "lax",
    maxAge: 0,
    path: "/api/auth",
  });
  return response;
}
