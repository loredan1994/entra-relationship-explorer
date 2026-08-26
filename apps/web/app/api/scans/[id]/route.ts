import { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { noStoreJson } from "@/server/http";
import { getBackend } from "@/server/backend";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 });
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return noStoreJson({ error: "Authentication required." }, { status: 401 });
  const { id } = await context.params;
  const job = await (await getBackend(config)).getJob(id, session.tenantId);
  return job ? noStoreJson({ job }) : noStoreJson({ error: "Scan job not found." }, { status: 404 });
}
