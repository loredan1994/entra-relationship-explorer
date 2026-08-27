import "server-only";
import { analyzeTenantIntelligenceHistory, buildAttackPathEvidencePacket, buildFindingEvidencePacket, type EvidencePacket, type EvidencePacketReviewContext } from "@entra-explorer/domain";
import type { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "./auth/session-store";
import { getBackend } from "./backend";
import { getEntraConfig } from "./config";
import { loadExportSnapshotHistory } from "./export-snapshot";

export async function loadEvidencePacket(request: NextRequest, resourceType: string): Promise<EvidencePacket | Response> {
  const kind = request.nextUrl.searchParams.get("kind");
  const id = request.nextUrl.searchParams.get("id")?.trim();
  if ((kind !== "finding" && kind !== "path") || !id) return new Response("Choose one finding or attack path to export.", { status: 400 });
  const history = await loadExportSnapshotHistory(request, resourceType);
  if (history instanceof Response) return history;

  try {
    const findingId = kind === "finding" ? id : analyzeTenantIntelligenceHistory(history).findings.find((finding) => finding.attackPathId === id)?.id;
    const review = findingId ? await loadReviewContext(request, history[0]!.id, findingId) : null;
    return kind === "finding" ? buildFindingEvidencePacket(history, id, review) : buildAttackPathEvidencePacket(history, id, review);
  } catch (error) {
    if (error instanceof Error && error.message.includes("not detected in the current snapshot")) return new Response(kind === "finding" ? "Finding not found." : "Attack path not found.", { status: 404 });
    throw error;
  }
}

async function loadReviewContext(request: NextRequest, snapshotId: string, findingId: string): Promise<EvidencePacketReviewContext | null> {
  const config = getEntraConfig();
  if (!config.enabled) return null;
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return null;
  const review = await (await getBackend(config)).getThreatReview(session.tenantId, snapshotId, findingId);
  return review ? { disposition: review.disposition, owner: review.owner, expiresAt: review.expiresAt, assumption: review.assumption, updatedAt: review.updatedAt, sourceSnapshotId: review.snapshotId } : null;
}
