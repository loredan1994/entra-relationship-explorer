import type { FederationTrust } from "@entra-explorer/domain";
import { bound, unique } from "./canonical";
import { complete, context } from "./model";
import type { EvidenceModel, Verdict, WorkflowResult } from "./types";

export interface SyntheticClaims { issuer: string; subject: string; audience: string }
export interface TrustComparison { left: string; right: string; verdict: Verdict; witness: SyntheticClaims | null; reason: string }

function validTrust(trust: FederationTrust | undefined): trust is FederationTrust {
  return Boolean(trust && !trust.unsupported.length && trust.issuer && trust.subject && trust.audiences.length === 1 && trust.audiences[0] && trust.issuer.trim() === trust.issuer);
}

export function matchesTrust(trust: FederationTrust | undefined, claims: SyntheticClaims): Verdict {
  if (!validTrust(trust)) return "unknown";
  return trust.issuer === claims.issuer && trust.subject === claims.subject && trust.audiences.includes(claims.audience) ? "supported" : "refuted";
}

export function intersectTrusts(left: FederationTrust | undefined, right: FederationTrust | undefined): { verdict: Verdict; witness: SyntheticClaims | null } {
  if (!validTrust(left) || !validTrust(right)) return { verdict: "unknown", witness: null };
  const audience = left.audiences.find(a => right.audiences.includes(a));
  if (left.issuer !== right.issuer || left.subject !== right.subject || !audience) return { verdict: "refuted", witness: null };
  return { verdict: "supported", witness: { issuer: left.issuer, subject: left.subject, audience } };
}

export function analyzeFederation(model: EvidenceModel, maxSteps = 20_000): WorkflowResult & { comparisons: TrustComparison[]; unknownTrusts: string[] } {
  bound(maxSteps, 1_000_000, "trust comparisons");
  const trusts = model.nodes.filter(n => n.kind === "federatedCredential");
  const comparisons: TrustComparison[] = [];
  const unknownTrusts = trusts.filter(n => !validTrust(n.federationTrust)).map(n => n.id);
  let steps = 0, exhausted = false;
  outer: for (let i = 0; i < trusts.length; i++) for (let j = i + 1; j < trusts.length; j++) {
    if (steps === maxSteps) { exhausted = true; break outer; }
    steps++;
    const a = trusts[i]!, b = trusts[j]!;
    const result = intersectTrusts(a.federationTrust, b.federationTrust);
    comparisons.push({ left: a.id, right: b.id, ...result,
      reason: result.verdict === "supported" ? "Exact trust constraints share synthetic claims." : result.verdict === "refuted" ? "Issuer, subject, or audience differs." : "Structured v1.0 exact trust evidence is missing or unsupported." });
  }
  const missing = unique([...unknownTrusts.map(id => `object:${id}:exact-trust`),
    ...model.conflicts.filter(c => trusts.some(n => c.factId === `object:${n.id}`)).map(c => c.factId),
    ...(complete(model, "federatedIdentityCredentials") ? [] : ["coverage:federatedIdentityCredentials"])]);
  return { ...context(model), verdict: exhausted || missing.length ? "unknown" : comparisons.some(c => c.verdict === "supported") ? "supported" : "refuted",
    comparisons, unknownTrusts, missing, limits: { steps, maxSteps, exhausted },
    assumptions: ["Witnesses are unsigned synthetic claims, never tokens. A match does not establish issuer control, token validity, successful exchange, or observed use.", "Only exact case-sensitive v1.0 semantics and one audience are supported. Preview expressions and historical flattened audience strings remain unknown."] };
}
