# Security modeling and verification strategy

## Decision

Entra Relationship Explorer will use a layered, open-source security-modeling and verification approach:

1. **OWASP Threat Dragon** for visual data-flow diagrams and facilitated STRIDE/LINDDUN review.
2. **Threagile** as the canonical, version-controlled threat-model-as-code source and automated risk generator.
3. **LINDDUN** as the privacy-specific review method applied to the same architecture and data flows.
4. **OWASP ASVS 5.0** as the source of testable application-security requirements.
5. **Security-invariant tests** to enforce the product's non-negotiable architectural properties.
6. **Gitleaks, Trivy, OWASP ZAP, and CycloneDX** for repeatable security evidence around secrets, dependencies, containers, runtime behavior, and the software supply chain.
7. **A living risk register** to assign ownership, record decisions, and prevent accepted risks from becoming permanent by accident.

This strategy supplements `THREAT_MODEL.md` and `SECURITY_PRIVACY.md`. It does not replace the product's read-only Microsoft Entra boundary.

## Why we want this

The product handles security-sensitive tenant inventory, Microsoft identity sessions, permissions, ownership relationships, encrypted snapshots, and explicit exports. A narrative threat model is valuable but can drift as the architecture changes. A diagram alone is easy to understand but difficult to validate continuously. Automated scanners find implementation issues but cannot determine whether the architecture or product claims are correct.

The layers serve different purposes:

| Layer | Purpose | Source of truth |
|---|---|---|
| Threat Dragon | Human-friendly architecture and review workshops | Visual review artifact |
| Threagile | Diffable architecture, generated risks, and risk status | Canonical machine-readable model |
| LINDDUN | Privacy threats involving identity and tenant inventory | Review findings linked to the model |
| ASVS | Concrete security requirements and verification targets | Selected-control matrix |
| Invariant tests | Prevent regression of product-specific security boundaries | Executable test suite |
| Security scanners | Detect secrets, vulnerable components, container problems, and runtime weaknesses | Reproducible scan evidence |
| Risk register | Ownership, disposition, evidence, and expiry | Canonical risk decisions |

Using both Threat Dragon and Threagile is intentional, but they must not become competing models. Component and data-flow identifiers must be consistent across them. Threagile is authoritative when the two disagree; the visual model must then be reconciled during review.

## Model scope

The initial model must include:

### Actors and external systems

- Local operator.
- Microsoft identity platform.
- Microsoft Graph.
- Azure Key Vault.
- Operator-controlled export destination.

### Technical assets

- Browser.
- Next.js web container.
- Background scan-worker container.
- Database-migration container.
- PostgreSQL database and persistent volume.
- Docker host and local container network.

### Sensitive data assets

- OAuth authorization state and PKCE verifier.
- MSAL token cache and access tokens.
- Application credential and data-encryption key.
- Tenant ID and session metadata.
- Tenant snapshots, names, object IDs, ownership, permissions, and evidence.
- Scan jobs, completeness state, and sanitized errors.
- CSV exports.
- Access and security-event records.

### Trust boundaries and flows

- Browser to web application.
- Web application to PostgreSQL.
- Worker to PostgreSQL.
- Worker to Microsoft identity and Microsoft Graph.
- Startup tooling to Azure Key Vault.
- Containers to Docker host and persistent volume.
- Explicit export from the web application to the operator filesystem.

Microsoft Graph collection flows must be modeled as read-only. No model, generated recommendation, security test, or implementation task may add Graph write permissions or a tenant mutation path.

## Initial priority threats

The first review must address at least:

- OAuth state, PKCE, redirect, or session-cookie compromise.
- Client credential, access token, token cache, or encryption-key disclosure.
- Tenant crossover caused by a missing or incorrect tenant predicate.
- A worker claiming, updating, or completing another worker's or tenant's job.
- Snapshot substitution or decryption under the wrong tenant context.
- Malicious Microsoft Graph pagination links or redirection outside the fixed Graph origin and API version.
- Throttling, timeout, or partial collection being presented as a complete scan.
- Confusion between configured access and observed activity.
- PostgreSQL or persistent-volume exposure outside the intended local boundary.
- Export disclosure and spreadsheet formula injection.
- Secrets or tenant material entering Git, logs, build layers, reports, or CI artifacts.
- Vulnerable or malicious dependencies and base images.
- Missing session revocation, expiry, stale-job recovery, retention, or audit evidence.
- Denial of service through unbounded pages, items, retries, jobs, history, or graph rendering.

## Required security invariants

The implementation must maintain automated tests proving that:

1. The Microsoft Graph transport can issue only `GET` requests.
2. Write-capable or unknown Graph scopes fail configuration validation.
3. Every durable session, job, snapshot, and access-event operation is tenant-scoped.
4. Authentication flows are short-lived, single-use, state-validated, and tenant-bound.
5. A worker cannot update or complete a job it has not claimed.
6. Snapshot encryption uses authenticated encryption with tenant-bound context.
7. Graph pagination remains on HTTPS `graph.microsoft.com/v1.0` URLs.
8. Retry behavior honors server throttling guidance and remains bounded.
9. Missing or failed endpoints produce visible partial-completion evidence.
10. Configured permissions are never labeled as observed use without a separately approved activity source.
11. CSV cells capable of initiating spreadsheet formulas are neutralized.
12. Tokens, credentials, encryption keys, raw Graph bodies, and tenant exports do not appear in API responses or sanitized logs.

## Verification tooling

### ASVS

Select the applicable OWASP ASVS 5.0 Level 2 requirements for architecture, authentication, session management, access control, validation, cryptography, secure communication, data protection, API security, logging, and configuration. Do not claim ASVS compliance merely because a checklist exists.

Each selected requirement must map to:

```text
ASVS requirement -> applicable threat -> implemented control -> verification evidence -> status
```

### Automated tools

- **Gitleaks:** scan the worktree and Git history for exposed credentials.
- **Trivy:** scan the repository, dependency manifests, Compose/Docker configuration, and built images for vulnerabilities, secrets, licenses, and relevant misconfigurations.
- **OWASP ZAP:** run a passive baseline and a narrowly scoped API scan against the local container stack. It must not initiate Microsoft Entra mutations or broaden Graph consent.
- **CycloneDX:** generate an SBOM for each releasable image or release candidate.

Roll out gates gradually. Initially block on confirmed secret exposure, failed security invariants, invalid threat models, and actionable critical/high findings with a known fix. Record other findings for triage instead of allowing an unreviewed warning backlog to become normal.

## Risk register

Each risk must include:

- Stable ID and title.
- Originating method or tool.
- Affected data asset, technical asset, flow, and trust boundary.
- Threat scenario and preconditions.
- Likelihood, impact, severity, and rationale.
- Owner and status.
- Mitigation and verification evidence.
- Tracking issue when work remains.
- Acceptance justification, approver, review date, and expiry when accepted.

Allowed states are `unchecked`, `in-discussion`, `accepted`, `in-progress`, `mitigated`, and `false-positive`. Accepted risks require an expiry or architecture-review trigger.

## Repository artifacts

The target structure is:

```text
security/
  README.md
  threat-dragon/
    entra-relationship-explorer.json
  threagile/
    threagile.yaml
  asvs/
    controls.yaml
  risk-register.yaml
  zap/
    automation.yaml
  trivy.yaml
  gitleaks.toml
  generated/              # ignored unless a specific artifact is approved for versioning
```

Generated reports must not contain credentials, tokens, raw tenant data, or exported tenant inventory. Pin container tools to reviewed versions or immutable digests rather than floating `latest` tags.

## Review triggers

Review and reconcile the models whenever any of these change:

- Microsoft Graph permissions or endpoints.
- Authentication, session, token-cache, or credential design.
- Tenant-isolation rules.
- Storage, encryption, retention, backup, or export behavior.
- Container, host, network, or deployment boundaries.
- Background-job ownership, retries, throttling, or recovery.
- Collected data fields or privacy disclosures.
- A new external service or trust boundary.
- A material security incident or newly applicable vulnerability.

At minimum, review the models before a shared deployment and at every major architecture phase.

## Definition of done

The initial security-modeling bootstrap is complete when:

- Threat Dragon and Threagile represent the current containerized architecture and share stable component IDs.
- Threagile validates and generates its diagram and risk outputs locally through a pinned container.
- The priority threats above are represented and triaged.
- Applicable ASVS controls are selected and linked to evidence without making an unsupported compliance claim.
- Product-specific invariants have automated tests.
- Gitleaks, Trivy, ZAP, and SBOM generation have documented, reproducible commands.
- The risk register has owners and dispositions for all high and critical findings.
- `THREAT_MODEL.md`, `SECURITY_PRIVACY.md`, and `ARCHITECTURE.md` agree with the modeled system.
- No Microsoft Entra write permission, write endpoint, mutation action, or unapproved deployment has been introduced.

## Implementation prompt

Use the following prompt to implement this strategy in a dedicated task:

> Continue the Entra Relationship Explorer as a security-modeling bootstrap. First read `README.md`, `DESIGN.md`, `AGENTS.md`, `docs/PRODUCT_SPEC.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRIVACY.md`, `docs/THREAT_MODEL.md`, and `docs/SECURITY_MODELING_STRATEGY.md`, plus any nested instructions applying to files you change. Inspect the current worktree and container architecture before editing, preserve all existing user changes, and keep the Microsoft Entra integration strictly read-only.
>
> Implement the layered strategy described in `docs/SECURITY_MODELING_STRATEGY.md`. Add a visual OWASP Threat Dragon model and a canonical Threagile threat-model-as-code representation for the current browser, Next.js web container, scan worker, migration container, PostgreSQL database/volume, Docker host/network, Microsoft identity platform, Microsoft Graph, Azure Key Vault, and explicit CSV export boundary. Use consistent stable identifiers across both models. Represent OAuth/MSAL material, credentials, encryption keys, tenant snapshots, permissions, jobs, audit records, and exports as data assets. Mark every Microsoft Graph flow read-only and do not add, request, or imply any Graph write permission.
>
> Add a privacy pass using LINDDUN and select an appropriate OWASP ASVS 5.0 Level 2 subset. Create a traceable mapping from each selected ASVS requirement to its threat, implemented control, verification evidence, and status; do not claim ASVS compliance. Create a version-controlled risk register with stable IDs, severity rationale, owner, mitigation, evidence, status, issue link where applicable, and expiry for accepted risks.
>
> Add automated security-invariant tests for GET-only Graph transport, scope allowlisting, tenant isolation, single-use tenant-bound OAuth flows, worker job ownership, tenant-bound authenticated encryption, Graph next-link origin validation, bounded throttling retries, partial-scan reporting, separation of configured access from observed activity, CSV formula neutralization, and secret/token redaction. Reuse existing tests where they already prove an invariant and record that evidence instead of duplicating tests.
>
> Add reproducible, container-friendly configurations and documented commands for Gitleaks, Trivy, OWASP ZAP's Automation Framework, and CycloneDX SBOM generation. Pin tool images to reviewed versions or immutable digests. Keep generated security output free of credentials, tokens, raw Graph responses, and tenant exports; ignore generated output by default unless a specific safe artifact is intentionally versioned. Introduce CI gates gradually: fail on invalid models, failed invariants, confirmed secret exposure, and actionable critical/high findings with known fixes; report lower-confidence findings for triage.
>
> Run the model validation, existing unit/type/build tests, the new security-invariant tests, and safe local scans. Do not perform destructive active scanning, alter Microsoft Entra, broaden consent, deploy anything, or expose PostgreSQL beyond the loopback/local container boundary. Finish by updating the architecture, security/privacy, and threat-model documents so they agree, and report completed artifacts, commands run, findings by severity, accepted residual risks, and any item that still requires owner approval.

## References

- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [Threagile](https://github.com/Threagile/threagile)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [LINDDUN privacy threat modeling](https://linddun.org/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Trivy container scanning](https://trivy.dev/docs/dev/guide/target/container_image/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
