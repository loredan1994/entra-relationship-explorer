# Entra Relationship Explorer

Understand an Entra tenant in ten seconds.

Entra Relationship Explorer is a client-ready, read-only IAM intelligence workspace that scans Microsoft Entra ID, explains identity relationships, discovers privilege paths, and produces evidence-backed remediation guidance.

## The simple version

- An **app registration** is the blueprint: what an application is, what roles it offers, and which APIs it wants to call.
- An **enterprise application** is that application's local identity inside a tenant. Microsoft Graph calls it a **service principal**.
- A **client service principal** receives permission to call a **resource service principal**.
- This tool draws those facts as a searchable map and shows the evidence behind every line.

The product is deliberately read-only. It does not grant permissions, remove assignments, create secrets, or change Entra.

## Start here

- [Product specification](docs/PRODUCT_SPEC.md)
- [Architecture and Graph model](docs/ARCHITECTURE.md)
- [Security and privacy](docs/SECURITY_PRIVACY.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Phase 1 read-only tenant scan](docs/PHASE_1_READ_ONLY.md)
- [Phase 2 investigation quality](docs/PHASE_2_INVESTIGATION.md)
- [Local container operations](docs/LOCAL_OPERATIONS.md)
- [Version 1 API contract](docs/openapi.yaml)
- [Research notes and primary references](docs/RESEARCH_NOTES.md)
- [Design system](DESIGN.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Interactive visual preview](previews/design-system-preview.html)

## Diagrams

| Diagram | PNG | Editable source |
|---|---|---|
| What the Entra objects mean | [PNG](diagrams/entra-object-model.png) | [Mermaid](diagrams/entra-object-model.mmd) · [Excalidraw](diagrams/entra-object-model.excalidraw) |
| Proposed system | [PNG](diagrams/system-architecture.png) | [Mermaid](diagrams/system-architecture.mmd) · [Excalidraw](diagrams/system-architecture.excalidraw) |
| Read-only scan flow | [PNG](diagrams/scan-flow.png) | [Mermaid](diagrams/scan-flow.mmd) · [Excalidraw](diagrams/scan-flow.excalidraw) |

## Current status

The product includes fixture-driven exploration, single-tenant Microsoft sign-in, GET-only paginated Graph SDK reads, PostgreSQL-backed encrypted sessions, checkpoints, snapshots, and finding decisions, a durable resumable scan queue, throttling-aware progress and cancellation, snapshot comparison, Cytoscape.js graph analysis, attack-path discovery, editable review copies of IAM attack flows, and CSV, standalone HTML, and MITRE Attack Flow exports. The default local registration still requests only `Application.Read.All` and `Directory.Read.All`; optional evidence is explicitly gated.

Optional scopes are configured through `ENTRA_OPTIONAL_GRAPH_SCOPES`: `RoleManagement.Read.Directory` adds active and PIM-eligible administrative roles, `Policy.Read.All` adds Conditional Access and partner cross-tenant settings, and `AuditLog.Read.All` adds a 30-day observed sign-in overlay. Unknown and write-capable scopes are rejected. All Graph transport remains GET-only.

## Run locally

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:3000/overview`. The `/security` section prioritizes transitive identity paths, distinguishes configured facts from observed activity, inferred possibilities, and missing evidence, maps relevant scenarios to MITRE ATT&CK®, and provides a synchronized review workspace. Run `pnpm run verify`; it validates Compose isolation, lints and type-checks the workspace, runs domain, scanner, storage, authentication, accessibility, and browser tests, and builds every product route.

The product remains in fixture mode by default. For the approved live local stack, start Docker Desktop and run `pnpm dev:live`. It retrieves the app credential, encryption key, and database password from `your-key-vault`, builds the containers, applies idempotent migrations, and starts PostgreSQL, web, and worker services on loopback interfaces. No secret is written into the repository.
