# Security bootstrap

This directory is the version-controlled security source of truth for the local, read-only Entra Relationship Explorer. It complements the narrative documents in `docs/`; it does not claim certification or OWASP ASVS compliance.

## Canonical artifacts

- `threat-dragon/entra-relationship-explorer.json` is the visual STRIDE model.
- `threagile/threagile.yaml` is the canonical machine-validated architecture model.
- `privacy/linddun.yaml` is the privacy threat pass.
- `asvs/controls.yaml` is the selected ASVS 5.0.0 Level 2 traceability subset.
- `risk-register.yaml` is the disposition register. No entry may be marked `accepted` without an expiry date and named approver.
- `invariants/evidence.yaml` maps product security invariants to executable evidence.

Stable identifiers are lower-case (`ta-*`, `tb-*`, `df-*`, `da-*`, `thr-*`, `lind-*`, and `risk-*`) and must match across artifacts. Microsoft Graph data flow `df-07` is explicitly GET-only and `readonly: true`.

## Reviewed tool pins

All security tools are referenced by both version and immutable multi-platform manifest digest in `tool-versions.env`.

- Threagile 1.0.0 image tag `0.9.1`. The upstream tag and binary version differ; both are recorded.
- Gitleaks `v8.28.0`. `v8.30.1` was deliberately not selected because its release had a confirmed detector regression.
- Trivy `0.74.0`.
- OWASP ZAP `2.17.0`.

Review the pins before updating them. Do not replace them with floating tags.

## Commands

The commands write only to ignored `security/generated/`. They do not pass application environment variables into scanner containers.

```sh
pnpm security:models
pnpm test:security
pnpm security:gitleaks
pnpm security:trivy:repo
pnpm security:trivy:image
pnpm security:zap
pnpm security:sbom
```

`security:zap` performs passive processing of two unauthenticated GET endpoints only. It does not spider, fuzz, authenticate, or run an active scan. The target must already be running on the Compose network.

Trivy scans the repository, dependency lockfile, Dockerfile, and the final exported filesystem of the application image. Final-filesystem scanning prevents deleted build-stage tools from being reported as runtime packages; the export is created in a temporary directory and is never committed. The pinned Trivy release does not interpret Docker Compose as an IaC type, so `security:trivy:repo` also invokes Trivy explicitly against `compose.yaml` (to preserve evidence of that limitation) and runs `validate-compose-security.mjs`. The deterministic validator fails for non-loopback published ports, worker or migration port publication, privileged/host namespaces, missing `no-new-privileges`, or an unpinned PostgreSQL image.

High and critical image findings are evaluated by `gate-trivy-report.mjs`. A package-path finding is considered a false positive only when the reported path is provably absent from the exported final filesystem. Upstream-blocked findings require an exact version match and a future review date in `trivy/triage.json`; expired or unmatched findings fail. These dispositions are evidence, not risk acceptance.

## Gates

1. Invalid threat models fail immediately.
2. Broken invariant tests fail immediately.
3. Confirmed secret exposure fails immediately.
4. Trivy fails only for actionable HIGH or CRITICAL findings with a known fix; the full report remains available for triage.
5. ZAP and lower-confidence findings are reports until a human disposition promotes a specific rule to a gate.

Generated reports, SBOMs, scanner caches, tenant exports, tokens, raw Graph responses, and tenant snapshots must not be committed. They are excluded from the container image as well as from Git.

This tooling is a development and CI concern. It is deliberately not exposed in the product: the application's `/security` section reports the security of the *scanned tenant*, not of this codebase.

## Primary references

- [OWASP Threat Dragon model schema](https://github.com/OWASP/threat-dragon/blob/main/td.vue/src/assets/schema/threat-dragon-v1.schema.json)
- [Threagile](https://github.com/Threagile/threagile)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Trivy](https://github.com/aquasecurity/trivy)
