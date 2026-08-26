# Product specification

## Problem

Microsoft Entra stores application identity across several related object types and screens. Administrators can see individual records, but answering “what can call what, why, and where did that permission come from?” is slow and error-prone.

## Users

- Entra and cloud administrators
- Security architects and reviewers
- Application and project owners
- Auditors and incident responders

## Jobs to be done

- Explain the difference between an app registration and enterprise application using live tenant data.
- Find every caller of a resource API and the role each caller received.
- Find what a client application can call.
- Identify unowned apps, broad permissions, and expiring credentials.
- Show the source evidence for each conclusion.
- Compare two scans without changing the tenant.

## MVP

The MVP signs an administrator in, requests read-only consent, scans one tenant, normalizes the results, and presents:

- Application registrations and their local service principals
- Incoming and outgoing application-role assignments
- Delegated OAuth permission grants
- Users, groups, and service principals assigned to enterprise applications
- Owners and credential metadata (never credential values)
- Search, filters, graph view, table view, evidence inspector, JSON/CSV export

Optional after MVP: activity overlay from sign-in logs and snapshot-to-snapshot change alerts.

## Non-goals for v1

- Creating or deleting Entra objects
- Granting, revoking, or approving permissions
- Rotating or storing credentials
- Replacing Microsoft Entra admin center
- Claiming that configured access proves actual usage
- Automated remediation or attack-path scoring

## Success measures

- A new user can correctly identify blueprint, tenant identity, caller, resource, and permission in under two minutes.
- Any visible edge can be explained and traced to Microsoft Graph in two clicks.
- A tenant scan requests no write permission.
- The UI remains useful with 10,000 applications through clustering, filtering, and table fallback.

## Core user story

When I select `clean-project-orchestrator → clean-project-api`, I see:

> Clean Project Orchestrator can call Clean Project API using the application permissions `Api.Read` and `Api.Write`. This is configured access; it does not prove recent use.

The evidence panel then shows both service-principal object IDs, the resource app-role IDs, the assignment IDs, scan time, and source endpoint.

## Routes

| Route | Purpose |
|---|---|
| `/overview` | Tenant health and inventory |
| `/map` | Relationship exploration |
| `/applications/[id]` | One application and all connected objects |
| `/permissions` | Searchable access inventory |
| `/changes` | Snapshot comparison |
| `/settings` | Connection, permissions, scan scope, retention |

