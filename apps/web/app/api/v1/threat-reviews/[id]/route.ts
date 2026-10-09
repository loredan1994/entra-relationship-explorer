import type { ThreatReview } from "@entra-explorer/backend";
import { analyzeTenantIntelligenceHistory } from "@entra-explorer/domain";
import { NextRequest } from "next/server";
import { THREAT_REVIEW_LIMITS } from "@/lib/threat-review-limits";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getBackend } from "@/server/backend";
import { getEntraConfig } from "@/server/config";
import { noStoreJson, readJsonObject, requireSameOrigin } from "@/server/http";
import { revalidateThreatReview } from "@/server/review-revalidation";

export const dynamic = "force-dynamic";
const DISPOSITIONS = new Set(["open", "mitigating", "accepted", "resolved"]);

function reviewFields(body: Record<string, unknown>) {
  for (const field of ["owner", "assumption"] as const) {
    if (body[field] !== undefined && typeof body[field] !== "string") return { error: `${field === "owner" ? "Owner" : "Rationale"} must be text.` };
    if (typeof body[field] === "string" && body[field].length > THREAT_REVIEW_LIMITS[field]) return { error: `${field === "owner" ? "Owner" : "Rationale"} must be at most ${THREAT_REVIEW_LIMITS[field]} characters.` };
  }
  const owner = typeof body.owner === "string" ? body.owner.trim() : "";
  const assumption = typeof body.assumption === "string" ? body.assumption.trim() : "";
  const expiresAt = body.expiresAt === undefined || body.expiresAt === null || body.expiresAt === "" ? null : body.expiresAt;
  if (expiresAt !== null && (typeof expiresAt !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt) || !Number.isFinite(Date.parse(expiresAt)) || new Date(expiresAt).toISOString().slice(0, 10) !== expiresAt)) return { error: "Expiry must be a valid calendar date (YYYY-MM-DD)." };
  if (body.flowDraft !== undefined && !Array.isArray(body.flowDraft)) return { error: "Review flow must be a list of steps." };
  const candidates = body.flowDraft ?? [];
  if (candidates.length > THREAT_REVIEW_LIMITS.flowDraft) return { error: `Review flow must contain at most ${THREAT_REVIEW_LIMITS.flowDraft} steps.` };
  const flowDraft: NonNullable<ThreatReview["flowDraft"]> = [];
  for (const [index, candidate] of candidates.entries()) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return { error: `Review step ${index + 1} must be an object.` };
    const item = candidate as Record<string, unknown>;
    if (typeof item.title !== "string" || !item.title.trim() || item.title.length > THREAT_REVIEW_LIMITS.title) return { error: `Review step ${index + 1} needs a title of 1–${THREAT_REVIEW_LIMITS.title} characters.` };
    if (item.id !== undefined && (typeof item.id !== "string" || !item.id.trim() || item.id.length > THREAT_REVIEW_LIMITS.id)) return { error: `Review step ${index + 1} needs an ID of 1–${THREAT_REVIEW_LIMITS.id} characters.` };
    if (item.evidenceEdgeId !== undefined && item.evidenceEdgeId !== null && (typeof item.evidenceEdgeId !== "string" || !item.evidenceEdgeId.trim() || item.evidenceEdgeId.length > THREAT_REVIEW_LIMITS.evidenceEdgeId)) return { error: `Review step ${index + 1} evidence ID must be 1–${THREAT_REVIEW_LIMITS.evidenceEdgeId} characters when supplied.` };
    flowDraft.push({ id: typeof item.id === "string" ? item.id : `step-${index + 1}`, title: item.title.trim(), evidenceEdgeId: typeof item.evidenceEdgeId === "string" ? item.evidenceEdgeId : null });
  }
  return { value: { owner, assumption, expiresAt, flowDraft } };
}

async function contextFor(request: NextRequest, id: string) {
  const config = getEntraConfig();
  if (!config.enabled) return { error: noStoreJson({ error: "Live Entra access is disabled." }, { status: 404 }) };
  const session = await getServerSession(request.cookies.get(SESSION_COOKIE)?.value, config);
  if (!session || session.tenantId !== config.tenantId) return { error: noStoreJson({ error: "Authentication required." }, { status: 401 }) };
  const backend = await getBackend(config);
  const history = await backend.recentSnapshots(session.tenantId, 20);
  const snapshot = history[0];
  if (!snapshot) return { error: noStoreJson({ error: "No tenant snapshot is available." }, { status: 404 }) };
  const expectedSnapshot = request.nextUrl.searchParams.get("snapshot");
  if (!expectedSnapshot) return { error: noStoreJson({ error: "The displayed snapshot ID is required." }, { status: 400 }) };
  if (expectedSnapshot !== snapshot.id) return { error: noStoreJson({ error: "A newer scan is available. Reload and review its evidence before saving." }, { status: 409 }) };
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
  const body = await readJsonObject(request);
  if (body instanceof Response) return body;
  if (typeof body.disposition !== "string" || !DISPOSITIONS.has(body.disposition)) return noStoreJson({ error: "A valid disposition is required." }, { status: 400 });
  if (!(body.expectedRevision === null || typeof body.expectedRevision === "string")) return noStoreJson({ error: "The current review revision is required." }, { status: 400 });
  const fields = reviewFields(body);
  if ("error" in fields) return noStoreJson({ error: fields.error }, { status: 400 });
  const { owner, assumption, expiresAt, flowDraft } = fields.value;
  if (body.disposition === "accepted" && (!owner || !expiresAt || !assumption)) return noStoreJson({ error: "Accepted risk requires an owner, expiry date, and rationale." }, { status: 400 });
  try {
    const review = await context.backend.upsertThreatReview({ findingId: id, snapshotId: context.snapshot.id, tenantId: context.session.tenantId, disposition: body.disposition as "open" | "mitigating" | "accepted" | "resolved", owner, expiresAt, assumption, flowDraft, updatedAt: new Date().toISOString() }, context.session.id, body.expectedRevision);
    return noStoreJson({ review });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Review conflict:")) return noStoreJson({ error: error.message }, { status: 409 });
    throw error;
  }
}

export async function POST(request: NextRequest, route: { params: Promise<{ id: string }> }) {
  const { id } = await route.params;
  const context = await contextFor(request, id);
  if ("error" in context) return context.error;
  try { requireSameOrigin(request, context.config.redirectUri); } catch { return noStoreJson({ error: "Cross-origin request rejected." }, { status: 403 }); }
  const body = await readJsonObject(request);
  if (body instanceof Response) return body;
  if (typeof body.sourceSnapshotId !== "string") return noStoreJson({ error: "A prior source snapshot is required." }, { status: 400 });
  if (!(body.expectedRevision === null || typeof body.expectedRevision === "string")) return noStoreJson({ error: "The current review revision is required." }, { status: 400 });
  const prior = (await context.backend.priorThreatReviews(context.session.tenantId, context.snapshot.id, [id]))[0];
  if (!prior || prior.snapshotId !== body.sourceSnapshotId) return noStoreJson({ error: "The prior review is stale or unavailable." }, { status: 409 });
  try {
    const review = await context.backend.upsertThreatReview(revalidateThreatReview(prior, context.snapshot.id), context.session.id, body.expectedRevision);
    await context.backend.recordAccess(context.session.tenantId, context.session.id, "revalidate", "threat_review", id);
    return noStoreJson({ review });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Review conflict:")) return noStoreJson({ error: error.message }, { status: 409 });
    throw error;
  }
}
