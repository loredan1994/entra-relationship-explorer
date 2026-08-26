import { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { noStoreJson } from "@/server/http";

export async function GET(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ enabled: false, connected: false });
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return noStoreJson({ enabled: true, connected: false });
  return noStoreJson({
    enabled: true,
    connected: true,
    tenantId: session.tenantId,
    expiresAt: new Date(session.sessionExpiresAt).toISOString(),
  });
}
