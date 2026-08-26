import { NextRequest } from "next/server";
import { deleteServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { noStoreJson, requireSameOrigin } from "@/server/http";

export async function POST(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 });
  try {
    requireSameOrigin(request, config.redirectUri);
  } catch {
    return noStoreJson({ error: "Cross-origin request rejected." }, { status: 403 });
  }
  await deleteServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  const response = noStoreJson({ signedOut: true });
  response.headers.append(
    "set-cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${new URL(config.redirectUri).protocol === "https:" ? "; Secure" : ""}`,
  );
  return response;
}
