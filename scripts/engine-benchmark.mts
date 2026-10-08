import { cpus, platform, arch, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
import { compileSnapshot, evaluateAuthorization, createEvaluator } from "../packages/engine/src/index.ts";
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
process.stdout.write(`${JSON.stringify({ generatedAt: new Date().toISOString(), node: process.version, hardware: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model, logicalCpus: cpus().length, totalMemoryBytes: totalmem() },
  distribution: "Synthetic fan-out: one owner, N independently owned identities, N application grants to one resource. Default query bounds; 100 repeated direct-grant cache reads. Wall times are local measurements, not service-level claims.", measurements }, null, 2)}\n`);
