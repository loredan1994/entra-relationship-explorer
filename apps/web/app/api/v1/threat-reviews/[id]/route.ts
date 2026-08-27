import { analyzeTenantIntelligenceHistory } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";
import { noStoreJson, requireSameOrigin } from "@/server/http";
import { revalidateThreatReview } from "@/server/review-revalidation";

export const dynamic = "force-dynamic";
const DISPOSITIONS = new Set(["open", "mitigating", "accepted", "resolved"]);

async function contextFor(request: NextRequest, id: string) {
  const config = getEntraConfig();
  if (!config.enabled) return { error: noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 }) };
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return { error: noStoreJson({ error: "Authentication required." }, { status: 401 }) };
  const backend = await getBackend(config);
  const history = await backend.recentSnapshots(session.tenantId, 20);
  const snapshot = history[0];
  if (!snapshot) return { error: noStoreJson({ error: "No tenant snapshot is available." }, { status: 404 }) };
  if (!analyzeTenantIntelligenceHistory(history).findings.some((finding) => finding.id === id)) return { error: noStoreJson({ error: "Finding not found in the current tenant snapshot." }, { status: 404 }) };
  return { config, session, backend, snapshot };
}

export async function GET(request: NextRequest, route: { params: Promise<{ id: string }> }) {
  const { id } = await route.params;
  const context = await contextFor(request, id);
  if ("error" in context) return context.error;
  const [review, priorReview] = await Promise.all([
    context.backend.getThreatReview(context.session.tenantId, context.snapshot.id, id),
    context.backend.priorThreatReviews(context.session.tenantId, context.snapshot.id, [id]).then((items) => items[0] ?? null),
  ]);
  return noStoreJson({ review, priorReview });
}

export async function PUT(request: NextRequest, route: { params: Promise<{ id: string }> }) {
  const { id } = await route.params;
  const context = await contextFor(request, id);
  if ("error" in context) return context.error;
  try { requireSameOrigin(request, context.config.redirectUri); } catch { return noStoreJson({ error: "Cross-origin request rejected." }, { status: 403 }); }
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body.disposition !== "string" || !DISPOSITIONS.has(body.disposition)) return noStoreJson({ error: "A valid disposition is required." }, { status: 400 });
  const owner = typeof body.owner === "string" ? body.owner.trim().slice(0, 160) : "";
  const assumption = typeof body.assumption === "string" ? body.assumption.trim().slice(0, 4_000) : "";
  const expiresAt = typeof body.expiresAt === "string" && /^\d{4}-\d{2}-\d{2}$/.test(body.expiresAt) ? body.expiresAt : null;
  const flowDraft = Array.isArray(body.flowDraft) ? body.flowDraft.slice(0, 20).flatMap((candidate, index) => {
    if (!candidate || typeof candidate !== "object") return [];
    const item = candidate as Record<string, unknown>;
    const title = typeof item.title === "string" ? item.title.trim().slice(0, 500) : "";
    if (!title) return [];
    return [{ id: typeof item.id === "string" ? item.id.slice(0, 100) : `step-${index + 1}`, title, evidenceEdgeId: typeof item.evidenceEdgeId === "string" ? item.evidenceEdgeId.slice(0, 160) : null }];
  }) : [];
  if (body.disposition === "accepted" && (!owner || !expiresAt || !assumption)) return noStoreJson({ error: "Accepted risk requires an owner, expiry date, and rationale." }, { status: 400 });
  const review = await context.backend.upsertThreatReview({ findingId: id, snapshotId: context.snapshot.id, tenantId: context.session.tenantId, disposition: body.disposition as "open" | "mitigating" | "accepted" | "resolved", owner, expiresAt, assumption, flowDraft, updatedAt: new Date().toISOString() }, context.session.id);
  return noStoreJson({ review });
}

export async function POST(request: NextRequest, route: { params: Promise<{ id: string }> }) {
  const { id } = await route.params;
  const context = await contextFor(request, id);
  if ("error" in context) return context.error;
  try { requireSameOrigin(request, context.config.redirectUri); } catch { return noStoreJson({ error: "Cross-origin request rejected." }, { status: 403 }); }
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body.sourceSnapshotId !== "string") return noStoreJson({ error: "A prior source snapshot is required." }, { status: 400 });
  const prior = (await context.backend.priorThreatReviews(context.session.tenantId, context.snapshot.id, [id]))[0];
  if (!prior || prior.snapshotId !== body.sourceSnapshotId) return noStoreJson({ error: "The prior review is stale or unavailable." }, { status: 409 });
  const review = await context.backend.upsertThreatReview(revalidateThreatReview(prior, context.snapshot.id), context.session.id);
  await context.backend.recordAccess(context.session.tenantId, context.session.id, "revalidate", "threat_review", id);
  return noStoreJson({ review });
}
