import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";
import { noStoreJson } from "@/server/http";

export const dynamic = "force-dynamic";

export async function GET() {
  const config = getEntraConfig();
  if (!config.enabled) return noStoreJson({ ok: true, mode: "fixture", database: null, graphBoundary: "read-only" });
  try {
    const health = await (await getBackend(config)).health();
    return noStoreJson({ ...health, mode: "live", graphBoundary: "read-only" });
  } catch {
    return noStoreJson({ ok: false, mode: "live", database: "postgres", graphBoundary: "read-only" }, { status: 503 });
  }
}
