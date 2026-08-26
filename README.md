# Entra Relationship Explorer

Understand an Entra tenant in ten seconds.

Entra Relationship Explorer is a proposed read-only internal tool that scans Microsoft Entra ID and explains how app registrations, enterprise applications, permissions, owners, and identities connect.

## The simple version

- An **app registration** is the blueprint: what an application is, what roles it offers, and which APIs it wants to call.
- An **enterprise application** is that application's local identity inside a tenant. Microsoft Graph calls it a **service principal**.
- A **client service principal** receives permission to call a **resource service principal**.
- This tool draws those facts as a searchable map and shows the evidence behind every line.

The first release is deliberately read-only. It does not grant permissions, remove assignments, create secrets, or change Entra.

## Start here

- [Product specification](docs/PRODUCT_SPEC.md)
- [Architecture and Graph model](docs/ARCHITECTURE.md)
- [Security and privacy](docs/SECURITY_PRIVACY.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Concrete Phase 0 plan](docs/PHASE_0_PLAN.md)
- [Phase 1 read-only tenant scan](docs/PHASE_1_READ_ONLY.md)
- [Phase 1 security validation](docs/PHASE_1_SECURITY_VALIDATION.md)
- [Phase 2 investigation quality](docs/PHASE_2_INVESTIGATION.md)
- [Local threat model and privacy review](docs/THREAT_MODEL.md)
- [Local container operations](docs/LOCAL_OPERATIONS.md)
- [Version 1 API contract](docs/openapi.yaml)
- [Research notes and primary references](docs/RESEARCH_NOTES.md)
- [Design system](DESIGN.md)
- [Interactive visual preview](previews/design-system-preview.html)

## Diagrams

| Diagram | PNG | Editable source |
|---|---|---|
| What the Entra objects mean | [PNG](diagrams/entra-object-model.png) | [Mermaid](diagrams/entra-object-model.mmd) · [Excalidraw](diagrams/entra-object-model.excalidraw) |
| Proposed system | [PNG](diagrams/system-architecture.png) | [Mermaid](diagrams/system-architecture.mmd) · [Excalidraw](diagrams/system-architecture.excalidraw) |
| Read-only scan flow | [PNG](diagrams/scan-flow.png) | [Mermaid](diagrams/scan-flow.mmd) · [Excalidraw](diagrams/scan-flow.excalidraw) |

## Current status

Phases 0–2 are implemented locally. The product includes fixture-driven exploration, single-tenant Microsoft sign-in, GET-only paginated Graph readers, PostgreSQL-backed encrypted sessions and snapshots, a durable scan queue, a separate worker, throttling-aware progress, snapshot comparison, and explicit CSV export. The local app registration has only `Application.Read.All` and `Directory.Read.All`; no Entra object is changed.

## Run locally

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:3000/overview`. The `/security` section reports tenant exposure: which applications hold powerful or write-capable permissions, which identities have no owner, and which credentials are expiring. Run the product gate with `pnpm run verify`; it validates the security models, type-checks the workspace, runs domain, scanner, storage, authentication, accessibility, and browser tests, and builds every product route. Containerized secret, repository, image, passive API, and SBOM checks are documented in [`security/README.md`](security/README.md).

The product remains in fixture mode by default. For the approved live local stack, start Docker Desktop and run `pnpm dev:live`. It retrieves the app credential, encryption key, and database password from `your-key-vault`, builds the containers, applies idempotent migrations, and starts PostgreSQL, web, and worker services on loopback interfaces. No secret is written into the repository.
