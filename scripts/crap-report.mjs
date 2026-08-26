#!/usr/bin/env node
/**
 * CRAP report: Change Risk Anti-Patterns.
 *
 * For every function in the unit-tested source, CRAP(f) = comp(f)^2 * (1 - cov(f))^3 + comp(f),
 * where comp is cyclomatic complexity (ESLint's `complexity` rule) and cov is the fraction
 * of the function's statements executed by the unit tests (vitest v8 coverage).
 * A complex function is fine if it is well tested; an untested one is a change risk.
 * Conventional reading: CRAP <= 5 healthy, 5-30 review, > 30 refactor or test.
 *
 * Run `pnpm quality:crap` (runs coverage first). Output: console summary plus
 * quality-reports/crap-report.md.
 */
import { ESLint } from "eslint";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const PACKAGES = [
  { name: "@entra-explorer/domain", dir: "packages/domain" },
  { name: "@entra-explorer/graph", dir: "packages/graph" },
  { name: "@entra-explorer/backend", dir: "packages/backend" },
  { name: "@entra-explorer/web (server)", dir: "apps/web" },
];
const CRAP_THRESHOLD = 30;

function loadCoverage(dir) {
  const file = path.join(ROOT, dir, "coverage", "coverage-final.json");
  if (!existsSync(file)) return null;
  return JSON.parse(readFileSync(file, "utf8"));
}

function loadSummary(dir) {
  const file = path.join(ROOT, dir, "coverage", "coverage-summary.json");
  if (!existsSync(file)) return null;
  return JSON.parse(readFileSync(file, "utf8"));
}

/** Per-file map of function complexities keyed by the reported start line. */
async function complexityByFile(files) {
  const eslint = new ESLint({
    cwd: ROOT,
    overrideConfig: { rules: { complexity: ["warn", { max: 0 }] } },
  });
  const results = await eslint.lintFiles(files);
  const map = new Map();
  for (const result of results) {
    const perLine = new Map();
    for (const message of result.messages) {
      if (message.ruleId !== "complexity") continue;
      const match = /complexity of (\d+)/.exec(message.message);
      if (match) perLine.set(message.line, Number(match[1]));
    }
    map.set(result.filePath, perLine);
  }
  return map;
}

function functionCoverage(fileCov, fn) {
  const { start, end } = fn.loc;
  let total = 0;
  let covered = 0;
  for (const [id, stmt] of Object.entries(fileCov.statementMap)) {
    if (stmt.start.line >= start.line && stmt.end.line <= end.line) {
      total += 1;
      if (fileCov.s[id] > 0) covered += 1;
    }
  }
  if (total === 0) return fileCov.f[fn.id ?? 0] > 0 ? 1 : 0;
  return covered / total;
}

function crap(complexity, coverage) {
  return complexity ** 2 * (1 - coverage) ** 3 + complexity;
}

const rows = [];
const packageSummaries = [];
for (const pkg of PACKAGES) {
  const coverage = loadCoverage(pkg.dir);
  const summary = loadSummary(pkg.dir);
  if (!coverage) {
    console.error(`No coverage data for ${pkg.name}; run \`pnpm test:coverage\` first.`);
    process.exitCode = 1;
    continue;
  }
  if (summary?.total) {
    packageSummaries.push({
      name: pkg.name,
      statements: summary.total.statements.pct,
      branches: summary.total.branches.pct,
      functions: summary.total.functions.pct,
    });
  }
  const files = Object.keys(coverage);
  const complexity = await complexityByFile(files);
  for (const [filePath, fileCov] of Object.entries(coverage)) {
    const perLine = complexity.get(filePath) ?? new Map();
    for (const [fnId, fn] of Object.entries(fileCov.fnMap)) {
      // ESLint reports at the function keyword/arrow line; fnMap decl start matches it.
      const comp = perLine.get(fn.decl.start.line) ?? perLine.get(fn.loc.start.line) ?? 1;
      const cov = functionCoverage(fileCov, { ...fn, id: fnId });
      rows.push({
        pkg: pkg.name,
        file: path.relative(ROOT, filePath),
        fn: fn.name?.startsWith("(") || !fn.name ? `(anonymous) L${fn.decl.start.line}` : fn.name,
        line: fn.decl.start.line,
        complexity: comp,
        coverage: cov,
        crap: crap(comp, cov),
      });
    }
  }
}

rows.sort((a, b) => b.crap - a.crap);
const risky = rows.filter((row) => row.crap > CRAP_THRESHOLD);
const pct = (value) => `${Math.round(value * 100)}%`;

const lines = [];
lines.push("# CRAP report", "");
lines.push(`Generated ${new Date().toISOString()} · ${rows.length} functions analyzed · threshold ${CRAP_THRESHOLD}`, "");
lines.push("CRAP = complexity² × (1 − coverage)³ + complexity. High complexity is acceptable when covered; complex *and* untested is a change risk.", "");
lines.push("## Package coverage", "", "| Package | Statements | Branches | Functions |", "|---|---|---|---|");
for (const s of packageSummaries) lines.push(`| ${s.name} | ${s.statements}% | ${s.branches}% | ${s.functions}% |`);
lines.push("", `## Functions over threshold (${risky.length})`, "");
lines.push("| CRAP | Complexity | Coverage | Function | File |", "|---|---|---|---|---|");
for (const row of risky) lines.push(`| ${row.crap.toFixed(1)} | ${row.complexity} | ${pct(row.coverage)} | ${row.fn} | ${row.file}:${row.line} |`);
lines.push("", "## Top 20 overall", "");
lines.push("| CRAP | Complexity | Coverage | Function | File |", "|---|---|---|---|---|");
for (const row of rows.slice(0, 20)) lines.push(`| ${row.crap.toFixed(1)} | ${row.complexity} | ${pct(row.coverage)} | ${row.fn} | ${row.file}:${row.line} |`);
lines.push("");

mkdirSync(path.join(ROOT, "quality-reports"), { recursive: true });
const outFile = path.join(ROOT, "quality-reports", "crap-report.md");
writeFileSync(outFile, lines.join("\n"));

console.log(`\nCRAP report — ${rows.length} functions, ${risky.length} over threshold ${CRAP_THRESHOLD}`);
for (const s of packageSummaries) console.log(`  ${s.name}: ${s.statements}% statements, ${s.branches}% branches, ${s.functions}% functions`);
console.log("\nTop change risks:");
for (const row of rows.slice(0, 10)) {
  console.log(`  CRAP ${row.crap.toFixed(1).padStart(7)}  comp ${String(row.complexity).padStart(3)}  cov ${pct(row.coverage).padStart(4)}  ${row.fn}  (${row.file}:${row.line})`);
}
console.log(`\nFull report: ${path.relative(ROOT, outFile)}`);
