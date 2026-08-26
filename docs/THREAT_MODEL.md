# Local security and privacy threat model

This narrative is the human-readable entry point. The visual model is `security/threat-dragon/entra-relationship-explorer.json`; the canonical machine-validated model is `security/threagile/threagile.yaml`. Stable IDs in those models map to `security/asvs/controls.yaml`, `security/privacy/linddun.yaml`, `security/invariants/evidence.yaml`, and `security/risk-register.yaml`.

The model is a bootstrap and review record, not a claim of OWASP ASVS compliance or of complete threat coverage.

## Scope and immutable boundary

The current runtime includes:

- `ta-browser`: operator browser on the local device.
- `ta-web`: Next.js standalone web/API container in a pinned non-root distroless runtime, published only on `127.0.0.1:3200`.
- `ta-worker`: restart-safe scan worker and the only Microsoft Graph client.
- `ta-migration`: one-shot local PostgreSQL schema migration.
- `ta-postgres` and `ta-pg-volume`: PostgreSQL 17 and its Docker volume.
- `ta-docker-host` and `ta-docker-network`: local Docker host and private Compose bridge.
- `ta-ms-identity`, `ta-ms-graph`, and `ta-key-vault`: external Microsoft identity, Graph, and secret-management services.
- `ta-export-destination`: explicit operator-controlled CSV destination.

Microsoft Entra remains strictly read-only. `df-07` is the only Microsoft Graph flow. It is HTTPS GET-only, restricted to `graph.microsoft.com/v1.0`, and uses only `Application.Read.All` and `Directory.Read.All`. Database writes and migrations affect only the local product database; they are not Entra writes.

## Data assets

The models classify OAuth state/PKCE material, MSAL tokens/cache, application and database credentials, the snapshot-encryption key, tenant sessions and snapshots, configured permissions, scan jobs, audit records, transient Graph responses, and CSV exports. Secret-like Graph fields and raw response bodies are discarded rather than persisted.

Every durable session and snapshot payload is AES-256-GCM encrypted with associated data that includes its record identity and tenant. Tenant IDs, status, timestamps, and scheduling metadata remain plaintext indexes; this is recorded as `risk-003`.

## Trust boundaries

1. `tb-operator-device`: the operator-controlled browser/device.
2. `tb-loopback`: only loopback host publications cross from browser/host into the stack.
3. `tb-docker-host`: Docker daemon, runtime, and host-disk authority.
4. `tb-compose-network`: private project bridge between web, worker, migration, and PostgreSQL.
5. `tb-persistent-storage`: database container to Docker volume/host disk.
6. `tb-ms-cloud`: TLS/Internet boundary to Microsoft identity and Graph.
7. `tb-key-vault`: separate secret-management boundary.
8. `tb-export`: explicit transition to an operator-controlled file.

## Primary threats and controls

| ID | Threat | Implemented control | Residual disposition |
|---|---|---|---|
| `thr-001` | Microsoft Graph write capability is introduced | Fixed read-only scope allowlist, GET-only transport, cross-model read-only assertion, automated tests, separate owner approval required for any write phase | Mitigated in current design |
| `thr-002` | Cross-tenant disclosure | Concrete tenant, tenant-bound backend methods and SQL predicates, tenant AAD, tenant-isolation tests | `risk-003` covers necessary plaintext indexes |
| `thr-003` | OAuth replay/substitution | 256-bit state, PKCE, short expiry, single-use atomic consume, constant-time comparison, tenant binding, HttpOnly SameSite cookies | Local HTTP prevents Secure cookies; must change before non-local use |
| `thr-004` | Worker job ownership tampering | Atomic `SKIP LOCKED` claim; status and `worker_id` predicates on updates/completion/failure | Mitigated |
| `thr-005` | nextLink bearer-token exfiltration or API-version drift | HTTPS, exact origin, and `/v1.0/` validation on every initial and continuation URL | Microsoft Graph remains a trusted upstream |
| `thr-006` | Throttling/resource exhaustion or misleading partial data | Retry-After, capped exponential backoff, retry/page/item/timeout/concurrency bounds, durable progress, explicit partial status | A heavily throttled scan may require a later rerun |
| `thr-007` | Secret, token, key, raw response, export, or tenant data leakage | Server-only tokens, typed Graph sanitization, generic top-level logs, safe error codes, no-store responses, ignored generated output, invariant tests, Gitleaks | `risk-001` covers local Docker-admin visibility |
| `thr-008` | Ciphertext swapping or tampering | AES-256-GCM, fresh IV, record/tenant contextual AAD, tamper and wrong-tenant tests | Key lifecycle policy remains owner work |
| `thr-009` | CSV formula execution or uncontrolled export disclosure | Formula-prefix neutralization including tab/null, CSV quoting, authenticated explicit download, no-store, export audit event | `risk-002` remains outside the application after download |
| `thr-010` | Configured permission is represented as activity or partial scan as complete | `configured=true`, `observed=null`, evidence/completeness on every edge, explicit partial errors, tests | Mitigated |
| `thr-011` | Docker host/runtime or supply-chain compromise | Single-user local scope, Key Vault retrieval, immutable base/tool pins, non-root production-only distroless runtime, no public service binding, no secrets in Git/reports | `risk-001` remains open before shared hosting; upstream image finding `risk-006` is open and due for recheck 2026-09-02 |

## Privacy pass

`security/privacy/linddun.yaml` covers all seven LINDDUN categories. Material residual privacy risks are linkability and identification across snapshots, organizational-event detection through topology changes, disclosure through local storage or exports, subject unawareness, and the absence of an owner-approved wider-use retention/rights policy. No telemetry, advertising, or third-party tracker is part of the product.

## Verification and security tooling

- `security/invariants/evidence.yaml` maps the twelve required invariants to tests and implementation evidence.
- `security/asvs/controls.yaml` maps a risk-selected ASVS 5.0.0 Level 2 subset plus one risk-driven Level 3 CSV requirement. A checklist does not establish compliance.
- `security/risk-register.yaml` is the disposition record. No risk is marked accepted without owner approval, an approver, and an expiry date.
- `scripts/security-tools.sh` runs pinned Threagile, Gitleaks, Trivy, ZAP, and CycloneDX workflows. Generated output is ignored.
- ZAP sends only unauthenticated GET requests to `/api/v1/health` and `/api/v1/session`, then passively analyzes the responses. It does not spider, authenticate, fuzz, or actively scan.
- Trivy image gating scans an exported final filesystem. Exact package-path absence and Debian-major metadata mismatches are reported as false positives, while any unmatched HIGH/CRITICAL with a fix fails. The sole upstream-blocked disposition is `risk-006`; it is time-bounded but not accepted.
- Lower-severity current-runtime findings remain explicit under `risk-008`, and the Compose-owned health check explains the Dockerfile-only false positive `risk-009`.
- Threagile reports two HIGH database-injection paths (`df-04` and `df-05`). They share `risk-007`, currently mitigated by parameterized queries, fixed identifiers/state transitions, and backend isolation/ownership tests; this is an implemented-control disposition, not a claim that all future queries are safe.

## Required owner decisions before broader use

- Replace the local client secret/runtime-environment pattern with workload identity, a certificate, or mounted runtime secrets.
- Approve a retention, deletion, backup, incident-response, subject-rights, and export-handling policy.
- Decide whether every snapshot read and every denied authorization attempt must create a durable access event; current audit coverage records enqueue, snapshot creation, and export but is not yet a complete authorization log.
- Remove or explicitly justify the PostgreSQL loopback publication and require TLS for all browser traffic.
- Repeat the model for the chosen hosted Azure network and identity architecture before deployment.
- Decide whether to accept a temporary upstream runtime risk if no patched distroless digest exists after the 2026-09-02 recheck; acceptance would require a named approver and expiry.
