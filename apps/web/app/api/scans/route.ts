import { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";
import { noStoreJson, requireSameOrigin } from "@/server/http";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 });
  try {
    requireSameOrigin(request, config.redirectUri);
  } catch {
    return noStoreJson({ error: "Cross-origin request rejected." }, { status: 403 });
  }
  const sessionId = request.cookies.get(SESSION_COOKIE)?.value;
  const session = await getServerSession(sessionId, config);
  if (!session || session.tenantId !== config.tenantId) return noStoreJson({ error: "Authentication required." }, { status: 401 });
  const job = await (await getBackend(config)).enqueueScan(session.tenantId, session.id);
  return noStoreJson({ job }, { status: 202 });
}

export async function GET(request: NextRequest) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ enabled: false, job: null });
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return noStoreJson({ error: "Authentication required." }, { status: 401 });
  return noStoreJson({ enabled: true, job: await (await getBackend(config)).getLatestJob(session.tenantId) });
}
