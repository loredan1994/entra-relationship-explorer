import { cpus, platform, arch, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
import { compileSnapshot, evaluateAuthorization, createEvaluator, findPolicyCounterexamples, solveChanges } from "../packages/engine/src/index.ts";
import { edge, node, query, snapshot } from "../packages/engine/src/test-support.ts";

const measurements = [];
for (const size of [100, 1_000, 5_000]) {
  const source = snapshot([]);
  source.nodes = [node("resource"), node("person", "user")];
  for (let i = 0; i < size; i++) {
    source.nodes.push(node(`client-${i}`));
    source.edges.push(edge(`grant-${i}`, `client-${i}`, "resource"), edge(`owner-${i}`, "person", `client-${i}`, "OWNS"));
  }
  const start = performance.now(), model = compileSnapshot(source), compiled = performance.now();
  const result = evaluateAuthorization(model, { ...query, kind: "control-path", principalId: "person", permissionId: undefined });
  const evaluated = performance.now(), cache = createEvaluator(model), direct = { ...query, principalId: "client-0" };
  cache.evaluate(direct); const cacheStart = performance.now();
  for (let i = 0; i < 100; i++) cache.evaluate(direct);
  measurements.push({ nodes: source.nodes.length, edges: source.edges.length, compileMs: compiled - start, queryMs: evaluated - compiled, cachedQueryMeanMs: (performance.now() - cacheStart) / 100,
    paths: result.paths.length, limits: result.limits, rssBytes: process.memoryUsage().rss });
}
const fanout = snapshot([]);
for (let i = 0; i < 40_000; i++) {
  fanout.nodes.push(node(`owned-${i}`));
  fanout.edges.push(edge(`owner-${i}`, "person", `owned-${i}`, "OWNS"));
}
const fanoutModel = compileSnapshot(fanout), fanoutStart = performance.now();
const fanoutProof = evaluateAuthorization(fanoutModel, { ...query, kind: "control-path", principalId: "person" }, { maxSteps: 1, maxPaths: 128, maxDepth: 12 });
const boundedFanout = { nodes: fanout.nodes.length, edges: fanout.edges.length, queryMs: performance.now() - fanoutStart, limits: fanoutProof.limits, verdict: fanoutProof.verdict };
const policySource = snapshot([]);
for (let i = 0; i < 20_000; i++) {
  policySource.nodes.push(node(`group-${i}`, "group"));
  policySource.edges.push(edge(`membership-${i}`, "person", `group-${i}`, "MEMBER_OF"));
}
const policyModel = compileSnapshot(policySource), policyStart = performance.now();
const policyResult = findPolicyCounterexamples(policyModel, { userIds: ["person"], applicationIds: ["resource"], require: "mfa" }, 1);
const boundedPolicy = { nodes: policySource.nodes.length, edges: policySource.edges.length, queryMs: performance.now() - policyStart, limits: policyResult.limits, verdict: policyResult.verdict };
const changes = Array.from({ length: 200 }, (_, i) => `change-${String(i).padStart(3, "0")}`), plannerStart = performance.now();
const plan = solveChanges({ context: fanoutModel, paths: changes.map(id => ({ id, dependencies: [id] })), candidates: changes.map(id => ({ id, cost: 1, removes: [id], description: "Synthetic exclusion" })), protectedIntegrations: [], evidenceComplete: true, maxSteps: 1 });
const boundedPlanner = { candidates: changes.length, paths: changes.length, queryMs: performance.now() - plannerStart, limits: plan.limits, status: plan.status, plans: plan.plans.length };
process.stdout.write(`${JSON.stringify({ generatedAt: new Date().toISOString(), node: process.version, hardware: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model, logicalCpus: cpus().length, totalMemoryBytes: totalmem() },
  distribution: "Synthetic fan-out: one owner, N independently owned identities, N application grants to one resource. Default query bounds; 100 repeated direct-grant cache reads. Stress cases use 40,000 outgoing ownership edges, 20,000 direct group memberships, and 200 independent planning paths at one search step. Wall times are local measurements, not service-level claims.", measurements, boundedFanout, boundedPolicy, boundedPlanner }, null, 2)}\n`);
