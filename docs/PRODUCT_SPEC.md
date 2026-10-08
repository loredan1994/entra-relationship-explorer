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
- Find transitive paths to powerful application and directory access.
- Review IAM threats with evidence, remediation, ownership, assumptions, and expiry.
- Distinguish newly detected, ongoing, returned, and no-longer-detected findings across retained scans without silently carrying forward old decisions.

## Current product

The workspace starts with synthetic sample data. An operator can configure one tenant, sign in with read-only consent, collect a snapshot, and investigate:

- Application registrations and their local service principals
- Incoming and outgoing application-role assignments
- Delegated OAuth permission grants
- Users, groups, and service principals assigned to enterprise applications
- Owners and credential metadata (never credential values)
- Search, filters, Cytoscape-assisted graph layout, table view, evidence inspector, and CSV export
- Evidence-backed IAM findings and multi-stage attack flows
- A threat workspace with encrypted tenant decision records, editable analyst flow copies, and sanitized CSV, HTML, and Attack Flow exports
- A recurring investigation lifecycle with explicit per-scan review revalidation and acceptance-expiry warnings
- Application access context, per-collector coverage, requested-versus-granted permission reconciliation and individual credential/federation history
- Selectable retained snapshots with field-level differences and explicitly enabled directory-audit correlation
- Local what-if review plans and a synthetic rule laboratory
- Question-based overview shortcuts and an in-app Guide explaining workflows, evidence classes and data handling

Optional evidence is implemented behind separately approved read-only scopes: sign-in activity, active and PIM-eligible roles, Conditional Access, and partner cross-tenant settings. Maester is not embedded: an isolated posture worker remains appropriate only after a concrete, license-verified test pack produces evidence that the native Graph collector does not already provide.

## Non-goals for v1

- Creating or deleting Entra objects
- Granting, revoking, or approving permissions
- Rotating or storing credentials
- Replacing Microsoft Entra admin center
- Claiming that configured access proves actual usage
- Automated remediation or claims that an inferred path was exploited

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
| `/security` | IAM findings, attack paths, and threat workspace |
| `/settings` | Connection, permissions, scan scope, retention |
| `/investigations?view=coverage` | Readiness, collection status, failures and bounds |
| `/investigations?view=applications` | Application sign-in controls, ownership, assignments and consent |
| `/investigations?view=ledger` | Requested-versus-granted permission reconciliation |
| `/investigations?view=credentials` | Individual credentials and federated workload trust |
| `/investigations?view=scenarios` | Local what-if path comparison and review plans |
| `/investigations?view=rules` | Synthetic rule replay and contributor guidance |
| `/guide` | Product boundary, question-based workflows, evidence interpretation and first steps |

The [user guide](USER_GUIDE.md) is the operator walkthrough. [Investigation tools](INVESTIGATIONS.md) is the detailed behavior and limitations reference. [Release verification](RELEASE_VERIFICATION_2026-10-08.md) separates measured acceptance from the success measures above.
