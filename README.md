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

This repository is the approved design and engineering foundation. No scanner has been deployed and no Entra object has been changed.
