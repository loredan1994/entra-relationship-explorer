import { arch, cpus, platform, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
import { analyzeTenantIntelligence } from "../packages/domain/src/intelligence.ts";
import { edge, node, snapshot } from "../packages/domain/src/test-support.ts";

const measurements = [];
for (const size of [1_000, 10_000, 30_000]) {
  const owner = node({ id: "owner", kind: "user", label: "Synthetic owner" });
  const workloads = Array.from({ length: size }, (_, i) => node({ id: `workload-${i}`, kind: "servicePrincipal", label: `Workload ${i}`, ownerIds: [owner.id] }));
  const source = snapshot([owner, ...workloads], workloads.map((target, i) => edge("OWNS", owner, target, { id: `ownership-${i}` })));
  const samplesMs: number[] = [];
  let result;
  for (let repeat = 0; repeat < 3; repeat++) {
    const start = performance.now();
    result = analyzeTenantIntelligence(source);
    samplesMs.push(performance.now() - start);
  }
  measurements.push({ nodes: source.nodes.length, edges: source.edges.length, samplesMs,
    medianMs: [...samplesMs].sort((a, b) => a - b)[1], paths: result!.paths.length,
    pathAnalysis: result!.pathAnalysis, rssBytes: process.memoryUsage().rss });
}
process.stdout.write(`${JSON.stringify({ generatedAt: new Date().toISOString(), node: process.version,
  hardware: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model, logicalCpus: cpus().length, totalMemoryBytes: totalmem() },
  distribution: "Synthetic ownership fan-out: one person owns N tenant identities with no terminal grants. Three sequential analysis calls per size, input construction excluded. Zero reportable paths isolates indexing and bounded traversal. Results are local measurements, not service-level guarantees; RSS is process memory, not per-query allocation.",
  measurements }, null, 2)}\n`);
