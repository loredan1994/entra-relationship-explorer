import type { ConditionalAccessDefinition } from "@entra-explorer/domain";
import { bound, canonical, compare, unique } from "./canonical";
import { complete, context } from "./model";
import type { EvidenceModel, WorkflowResult } from "./types";

type Truth = true | false | null;
export interface SignInScenario {
  userId: string;
  applicationId: string;
  groups: string[] | null;
  platform: string | null;
  location: string | null;
  trustedLocation: boolean | null;
  clientAppType: string | null;
  mfa: boolean | null;
  compliantDevice: boolean | null;
  hybridJoinedDevice: boolean | null;
}
export interface PolicyDecision { id: string; mode: "enforced" | "report-only" | "disabled" | "unknown"; applies: Truth; satisfied: Truth; unsupported: string[] }
export interface ScenarioEvaluation { decision: "permits-under-model" | "requirements-unmet" | "unknown"; policies: PolicyDecision[] }
export interface PolicyIntent { require: "mfa" | "compliantDevice" | "block"; userIds: string[]; applicationIds: string[] }

function and(values: Truth[]): Truth { return values.includes(false) ? false : values.includes(null) ? null : true; }
function or(values: Truth[]): Truth { return values.includes(true) ? true : values.includes(null) ? null : false; }
function includes(values: string[], actual: string | null, all = "All"): Truth {
  if (values.includes(all)) return true;
  if (values.every(v => v === "None")) return false;
  return actual === null ? null : values.includes(actual);
}
function groups(values: string[], actual: string[] | null): Truth { return !values.length ? false : actual === null ? null : values.some(id => actual.includes(id)); }
function location(values: string[], scenario: SignInScenario): Truth {
  return or([includes(values.filter(v => v !== "AllTrusted"), scenario.location), values.includes("AllTrusted") ? scenario.trustedLocation : false]);
}
function selector(include: Truth, exclude: Truth): Truth { return exclude === true ? false : and([include, exclude === null ? null : true]); }

function applicability(policy: ConditionalAccessDefinition, scenario: SignInScenario): Truth {
  const userInclude = or([includes(policy.users.include, scenario.userId), groups(policy.users.includeGroups, scenario.groups)]);
  const userExclude = or([includes(policy.users.exclude, scenario.userId), groups(policy.users.excludeGroups, scenario.groups)]);
  // A definite supported exclusion is decisive. Unsupported/malformed selectors must
  // otherwise stay unknown, including when sanitization removed their raw values.
  if (userExclude === true || includes(policy.applications.exclude, scenario.applicationId) === true) return false;
  if (policy.unsupported.length || [...policy.applications.include, ...policy.applications.exclude].some(id => ["Office365", "MicrosoftAdminPortals"].includes(id)) ||
    [...policy.users.include, ...policy.users.exclude].includes("GuestsOrExternalUsers")) return null;
  const predicates: Truth[] = [selector(userInclude, userExclude), selector(includes(policy.applications.include, scenario.applicationId), includes(policy.applications.exclude, scenario.applicationId))];
  if (policy.platforms) predicates.push(selector(includes(policy.platforms.include, scenario.platform, "all"), includes(policy.platforms.exclude, scenario.platform, "all")));
  if (policy.locations) predicates.push(selector(location(policy.locations.include, scenario), location(policy.locations.exclude, scenario)));
  if (policy.clientAppTypes.length) predicates.push(includes(policy.clientAppTypes, scenario.clientAppType, "all"));
  return and(predicates);
}

function controls(policy: ConditionalAccessDefinition, scenario: SignInScenario): Truth {
  if (!policy.grant || !policy.grant.controls.length) return null;
  if (policy.grant.controls.includes("block")) return false;
  const values = policy.grant.controls.map((control): Truth => {
    switch (control) {
      case "mfa": return scenario.mfa;
      case "compliantDevice": return scenario.compliantDevice;
      case "domainJoinedDevice": return scenario.hybridJoinedDevice;
      default: return null;
    }
  });
  return policy.grant.operator === "AND" ? and(values) : policy.grant.operator === "OR" ? or(values) : null;
}

function scenarioEvaluator(model: EvidenceModel): (scenario: SignInScenario) => ScenarioEvaluation {
  const conflicts = new Set(model.conflicts.map(c => c.factId));
  const nodes = model.nodes.filter(n => n.conditionalAccess || (n.kind === "policy" && (n.sourceEndpoint?.startsWith("/identity/conditionalAccess") || !["authorization", "permissionGrant", "crossTenantAccess"].includes(String(n.metadata?.policyType)))));
  const incomplete = !complete(model, "conditionalAccess") || model.conflicts.length > 0;
  return scenario => {
    const policies = nodes.map((node): PolicyDecision => {
      // Compilation retains one canonical variant for stable output. It is not
      // authoritative when the same policy ID has contradictory source records.
      if (conflicts.has(`object:${node.id}`)) return { id: node.id, mode: "unknown", applies: null, satisfied: null, unsupported: ["conflicting-policy-evidence"] };
      const p = node.conditionalAccess;
      if (!p) return { id: node.id, mode: "unknown", applies: null, satisfied: null, unsupported: ["structured-policy-not-collected"] };
      const mode = p.state === "enabled" ? "enforced" : p.state === "enabledForReportingButNotEnforced" ? "report-only" : p.state === "disabled" ? "disabled" : "unknown";
      return { id: node.id, mode, applies: mode === "disabled" ? false : applicability(p, scenario), satisfied: controls(p, scenario), unsupported: p.unsupported };
    });
    const enforced = policies.filter(p => p.mode === "enforced" || p.mode === "unknown");
    const denied = enforced.some(p => p.mode === "enforced" && p.applies === true && p.satisfied === false);
    const unknown = incomplete || enforced.some(p => p.mode === "unknown" || p.applies === null || (p.applies === true && p.satisfied === null));
    return { decision: denied ? "requirements-unmet" : unknown ? "unknown" : "permits-under-model", policies };
  };
}

export function evaluatePolicyScenario(model: EvidenceModel, scenario: SignInScenario): ScenarioEvaluation {
  return scenarioEvaluator(model)(scenario);
}

function violates(intent: PolicyIntent, scenario: SignInScenario): boolean {
  // The generator selects only identities in the declared intent domain, and
  // minimization never changes userId or applicationId.
  return intent.require === "block" || scenario[intent.require] === false;
}

function minimized(evaluate: (scenario: SignInScenario) => ScenarioEvaluation, intent: PolicyIntent, original: SignInScenario): SignInScenario {
  const scenario = { ...original };
  for (const field of ["groups", "platform", "location", "trustedLocation", "clientAppType", "mfa", "compliantDevice", "hybridJoinedDevice"] as const) {
    const proposed = { ...scenario, [field]: null };
    if (violates(intent, proposed) && evaluate(proposed).decision === "permits-under-model") Object.assign(scenario, proposed);
  }
  return scenario;
}

function groupResolver(model: EvidenceModel) {
  const cache = new Map<string, string[] | null>();
  // A canonical conflicting relationship cannot prove either membership or its
  // absence. Keep generated group assumptions unknown until sources agree.
  const completeGroups = complete(model, "groupMemberships") && model.conflicts.length === 0;
  const groups = new Set(model.nodes.filter(n => n.kind === "group").map(n => n.id));
  const outgoing = new Map<string, typeof model.edges>();
  for (const edge of model.edges) if (edge.type === "MEMBER_OF" && edge.evidence.configured) {
    const edges = outgoing.get(edge.sourceId);
    if (edges) edges.push(edge);
    else outgoing.set(edge.sourceId, [edge]);
  }
  let remaining = 100_000;
  return (userId: string): string[] | null => {
    if (!completeGroups) return null;
    if (cache.has(userId)) return cache.get(userId)!;
    const visited = new Set([userId]), queue = [userId];
    let known = true;
    for (let i = 0; i < queue.length && known; i++) for (const edge of outgoing.get(queue[i]!) ?? []) {
      if (--remaining < 0 || edge.evidence.completeness !== "complete" || !groups.has(edge.targetId)) { known = false; break; }
      if (!visited.has(edge.targetId)) { visited.add(edge.targetId); queue.push(edge.targetId); }
    }
    visited.delete(userId);
    const result = known ? unique([...visited]) : null;
    cache.set(userId, result);
    return result;
  };
}

/** Enumerate boundaries from policy literals, plus one representative of their complement. */
export function findPolicyCounterexamples(model: EvidenceModel, intent: PolicyIntent, maxSteps = 10_000): WorkflowResult & { witnesses: Array<{ scenario: SignInScenario; evaluation: ScenarioEvaluation }>; checked: number; unknown: number; domainSize: number } {
  bound(maxSteps, 100_000, "policy scenarios");
  if (!["mfa", "compliantDevice", "block"].includes(intent.require) || !intent.userIds.length || !intent.applicationIds.length) throw new Error("Invalid policy intent.");
  const policies = model.nodes.flatMap(n => n.conditionalAccess ? [n.conditionalAccess] : []);
  const complement = (items: string[]) => { let id = "synthetic:other"; while (items.includes(id)) id += ":other"; return id; };
  const domain = (items: string[]) => { const specific = unique(items.filter(id => !["All", "None", "all", "AllTrusted"].includes(id))); return [...specific, complement(specific)]; };
  const users = intent.userIds.includes("All") ? domain([...model.nodes.filter(n => n.kind === "user").map(n => n.id), ...policies.flatMap(p => [...p.users.include, ...p.users.exclude])]) : unique(intent.userIds);
  const apps = intent.applicationIds.includes("All") ? domain(policies.flatMap(p => [...p.applications.include, ...p.applications.exclude])) : unique(intent.applicationIds);
  const platforms = domain(policies.flatMap(p => [...(p.platforms?.include ?? []), ...(p.platforms?.exclude ?? [])]));
  const locations = domain(policies.flatMap(p => [...(p.locations?.include ?? []), ...(p.locations?.exclude ?? [])]));
  const clients = domain(policies.flatMap(p => p.clientAppTypes));
  const domainSize = users.length * apps.length * platforms.length * locations.length * clients.length * 16;
  const witnesses: Array<{ scenario: SignInScenario; evaluation: ScenarioEvaluation }> = [];
  const seen = new Set<string>();
  let checked = 0, unknown = 0, exhausted = false;
  // Resolve only users actually visited by the bounded scenario search. Group
  // closure is a separate bounded worklist; an incomplete closure remains unknown.
  const resolveGroups = groupResolver(model);
  const evaluate = scenarioEvaluator(model);
  outer: for (const userId of users) for (const applicationId of apps) for (const platform of platforms) for (const location of locations) for (const clientAppType of clients) for (let bits = 0; bits < 16; bits++) {
    if (checked === maxSteps) { exhausted = true; break outer; }
    checked++;
    const scenario: SignInScenario = { userId, applicationId, platform, location, clientAppType, groups: resolveGroups(userId),
      mfa: Boolean(bits & 1), compliantDevice: Boolean(bits & 2), hybridJoinedDevice: Boolean(bits & 4), trustedLocation: Boolean(bits & 8) };
    const evaluation = evaluate(scenario);
    if (evaluation.decision === "unknown") unknown++;
    if (evaluation.decision === "permits-under-model" && violates(intent, scenario)) {
      const witness = minimized(evaluate, intent, scenario), key = canonical(witness);
      if (!seen.has(key)) { seen.add(key); if (witnesses.length < 100) witnesses.push({ scenario: witness, evaluation: evaluate(witness) }); }
    }
  }
  witnesses.sort((a, b) => compare(canonical(a.scenario), canonical(b.scenario)));
  return { ...context(model), verdict: witnesses.length ? "supported" : exhausted || unknown ? "unknown" : "refuted", witnesses, checked, unknown, domainSize,
    missing: unique([...(unknown ? ["supported-complete-policy-conditions"] : []), ...(exhausted ? ["budget:policy-scenarios"] : [])]), limits: { steps: checked, maxSteps, exhausted },
    assumptions: ["Counterexamples violate the supplied intent within a finite user-sign-in model. They do not establish an actual successful sign-in.", "Supported: exact user/group/resource selectors, platform, named-location IDs with supplied trust state, client type, AND/OR MFA, compliant-device and hybrid-join controls, and block. Workload policy, risk, device filters, authentication strengths, session controls, aliases and service dependencies remain unknown.", "Up to 100 distinct minimized witnesses are shown. A no-counterexample result applies only to the declared finite domain."] };
}
