#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const [reportPath, rootfsPath, triagePath] = process.argv.slice(2);
if (!reportPath || !rootfsPath || !triagePath) {
  throw new Error("Usage: gate-trivy-report.mjs <report.json> <rootfs> <triage.json>");
}

const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const triage = JSON.parse(fs.readFileSync(triagePath, "utf8"));
const today = new Date().toISOString().slice(0, 10);
const failures = [];
const falsePositives = [];
const upstreamBlocked = [];

for (const result of report.Results ?? []) {
  for (const finding of result.Vulnerabilities ?? []) {
    if (!["HIGH", "CRITICAL"].includes(finding.Severity) || !finding.FixedVersion) continue;

    if (finding.PkgPath) {
      const evidencePath = path.join(rootfsPath, finding.PkgPath.replace(/^\/+/, ""));
      if (!fs.existsSync(evidencePath)) {
        falsePositives.push(`${finding.VulnerabilityID}/${finding.PkgName}: reported package path is absent from the final filesystem`);
        continue;
      }
    }

    const detectedDebian13 = String(result.Target).includes("debian 13");
    if (detectedDebian13 && /deb12/.test(finding.InstalledVersion ?? "")) {
      falsePositives.push(`${finding.VulnerabilityID}/${finding.PkgName}: Debian 12 package metadata mismatches the detected Debian 13 runtime`);
      continue;
    }

    const disposition = (triage.entries ?? []).find((entry) =>
      entry.vulnerability_id === finding.VulnerabilityID &&
      entry.package === finding.PkgName &&
      entry.installed_version === finding.InstalledVersion
    );
    if (disposition?.status === "upstream-blocked" && disposition.review_by >= today) {
      upstreamBlocked.push(`${finding.VulnerabilityID}/${finding.PkgName} (${disposition.id}, review by ${disposition.review_by})`);
      continue;
    }

    failures.push(`${finding.Severity} ${finding.VulnerabilityID}/${finding.PkgName} ${finding.InstalledVersion} -> ${finding.FixedVersion}`);
  }
}

for (const item of falsePositives) console.log(`TRIVY FALSE POSITIVE: ${item}`);
for (const item of upstreamBlocked) console.log(`TRIVY EXPLICIT TRIAGE: ${item}`);
if (failures.length) {
  for (const failure of failures) console.error(`TRIVY GATE FAILURE: ${failure}`);
  process.exit(1);
}
console.log(`Trivy gate passed: ${falsePositives.length} evidenced false positives, ${upstreamBlocked.length} time-bounded upstream disposition(s).`);
