import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const threatDragonPath = resolve(root, "security/threat-dragon/entra-relationship-explorer.json");
const threagilePath = resolve(root, "security/threagile/threagile.yaml");
const riskPath = resolve(root, "security/risk-register.yaml");
const asvsPath = resolve(root, "security/asvs/controls.yaml");
const linddunPath = resolve(root, "security/privacy/linddun.yaml");
const evidencePath = resolve(root, "security/invariants/evidence.yaml");

const fail = (message) => { throw new Error(`Security model validation failed: ${message}`); };
const parseJsonYaml = (path) => JSON.parse(readFileSync(path, "utf8"));
const threatDragon = parseJsonYaml(threatDragonPath);
const threagile = readFileSync(threagilePath, "utf8");
const riskRegister = parseJsonYaml(riskPath);
const asvs = parseJsonYaml(asvsPath);
const linddun = parseJsonYaml(linddunPath);
const evidence = parseJsonYaml(evidencePath);

if (!threatDragon.summary?.title || !Array.isArray(threatDragon.detail?.diagrams) || threatDragon.detail.diagrams.length < 2) fail("Threat Dragon summary and two diagrams are required.");
const cells = threatDragon.detail.diagrams.flatMap((diagram) => diagram.diagramJson?.cells ?? []);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const cellIds = new Set();
for (const cell of cells) {
  if (!cell.attrs || !cell.size || !cell.type || !Number.isInteger(cell.z) || !uuid.test(cell.id)) fail(`Invalid Threat Dragon cell ${cell.id ?? "without ID"}.`);
  if (cellIds.has(cell.id)) fail(`Duplicate Threat Dragon cell UUID ${cell.id}.`);
  cellIds.add(cell.id);
}
for (const cell of cells.filter((candidate) => candidate.type === "tm.Flow")) {
  if (!cell.source?.id || !cell.target?.id || !cellIds.has(cell.source.id) || !cellIds.has(cell.target.id)) fail(`Broken Threat Dragon flow ${cell.id}.`);
}

const expected = {
  ta: ["ta-browser","ta-web","ta-worker","ta-migration","ta-postgres","ta-pg-volume","ta-docker-host","ta-docker-network","ta-ms-identity","ta-ms-graph","ta-key-vault","ta-export-destination"],
  tb: ["tb-operator-device","tb-export","tb-loopback","tb-docker-host","tb-compose-network","tb-persistent-storage","tb-ms-cloud","tb-key-vault"],
  da: ["da-oauth-flow","da-msal-material","da-app-credential","da-encryption-key","da-database-credential","da-tenant-session","da-tenant-snapshot","da-permissions","da-scan-jobs","da-audit-records","da-csv-export","da-graph-response"],
  df: Array.from({ length: 12 }, (_, index) => `df-${String(index + 1).padStart(2, "0")}`),
  threat: Array.from({ length: 11 }, (_, index) => `thr-${String(index + 1).padStart(3, "0")}`),
};
const threatDragonText = JSON.stringify(threatDragon);
for (const [kind, ids] of Object.entries(expected)) {
  for (const id of ids) {
    if (!threagile.includes(id)) fail(`${kind} identifier ${id} is missing from Threagile.`);
    if (!threatDragonText.includes(id)) fail(`${kind} identifier ${id} is missing from Threat Dragon.`);
  }
}
const graphBlock = threagile.match(/df-07 Microsoft Graph GET-only v1\.0:[\s\S]*?(?=\n  [A-Za-z][^\n]+:\n|\ntrust_boundaries:)/)?.[0];
if (!graphBlock || !/readonly:\s*true/.test(graphBlock) || !/STRICTLY READ-ONLY/.test(graphBlock) || !/HTTPS GET only/.test(graphBlock)) fail("df-07 must be explicitly GET-only and readonly in Threagile.");
if (/graph[\s\S]{0,300}readonly:\s*false/i.test(graphBlock)) fail("A Microsoft Graph flow is writable.");
if (!/df-07[^\n]*(?:GET-ONLY|GET-only)/.test(threatDragonText) || !/STRICTLY READ-ONLY Microsoft Graph flow/.test(threatDragonText)) fail("df-07 must be explicitly read-only in Threat Dragon.");

for (const risk of riskRegister.risks ?? []) {
  for (const required of ["id","title","severity","rationale","affected_assets","trust_boundaries","owner","mitigation","verification_evidence","status","tracking_issue","expiry_date"]) {
    if (!(required in risk)) fail(`Risk ${risk.id ?? "unknown"} lacks ${required}.`);
  }
  if (risk.status === "accepted" && (!risk.expiry_date || !risk.approver)) fail(`Accepted risk ${risk.id} lacks an expiry date or approver.`);
}
if (asvs.assurance_statement?.toLowerCase().includes("not a claim") !== true) fail("ASVS mapping must disclaim compliance.");
for (const control of asvs.controls ?? []) {
  for (const required of ["id","level","requirement","threats","implemented_control","verification_evidence","status"]) if (!(required in control)) fail(`ASVS control ${control.id ?? "unknown"} lacks ${required}.`);
}
if ((linddun.threats ?? []).length !== 7) fail("All seven LINDDUN categories must be represented.");
if ((evidence.invariants ?? []).length !== 12) fail("Exactly twelve requested security invariants must be mapped.");

console.log(`Threat Dragon structure and cross-model IDs valid (${cells.length} cells).`);
console.log(`Risk, ASVS, LINDDUN, and invariant traceability structures valid.`);
