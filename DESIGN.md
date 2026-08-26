# Design system — Operational Cartography

## Product promise

**Understand your Entra tenant in ten seconds.**

The interface should feel like an operational map: calm, exact, and built for investigation. It combines the speed of a security graph with the evidence density of an admin console.

## Principles

1. **Map first.** Relationships are the main object, not decoration around a table.
2. **Evidence beside every claim.** Selecting a line opens the exact source facts.
3. **Plain English before jargon.** “Can call” precedes “app role assignment.”
4. **Configured is not observed.** Solid lines mean configured access; activity is a separate optional overlay.
5. **Density without confusion.** Compact controls, generous grouping, restrained color.

## Visual foundation

### Color

| Token | Value | Use |
|---|---:|---|
| `canvas-deep` | `#07111F` | Relationship canvas |
| `canvas-raised` | `#0D1B2A` | Graph controls and node shells |
| `surface-app` | `#F5F7FA` | Main application background |
| `surface-panel` | `#FFFFFF` | Inspector and cards |
| `ink-strong` | `#172033` | Primary text on light surfaces |
| `ink-muted` | `#667085` | Supporting text |
| `line-light` | `#DCE3EC` | Dividers and borders |
| `action` | `#2F6FED` | Selection and primary actions |
| `identity` | `#16B8C4` | Application identity nodes |
| `success` | `#14866D` | Healthy / least privilege |
| `warning` | `#D97706` | Review needed |
| `danger` | `#D64545` | High exposure / expired credential |

Color never carries meaning alone. Every state also has a label, icon, shape, or line pattern.

### Type

- UI and headings: **Instrument Sans**, with `Inter`, `Segoe UI`, and sans-serif fallbacks.
- IDs, scopes, role values, and timestamps: **IBM Plex Mono**, with `SFMono-Regular` and monospace fallbacks.
- Display: 32/38, page title: 24/30, section: 18/24, body: 14/20, compact data: 12/18.

### Spacing and shape

- Base unit: 4 px. Standard rhythm: 4, 8, 12, 16, 24, 32, 48.
- Radius: 4 px for data controls, 8 px for cards, 12 px for large panels.
- Shadow only for elevation: `0 12px 32px rgba(7,17,31,.14)`.
- Default desktop shell: 72 px top bar, 280 px filter rail, flexible graph, 380 px evidence panel.

### Motion

- 120 ms for hover/focus, 180 ms for panel changes, 240 ms for graph focus.
- Use ease-out for entry and ease-in for exit.
- Respect `prefers-reduced-motion`; never animate the graph continuously.

## Node and edge grammar

| Object | Shape | Accent | Plain-English label |
|---|---|---|---|
| App registration | Rounded rectangle, double header | Blue | Blueprint |
| Enterprise application / service principal | Rounded rectangle | Cyan | Tenant identity |
| User | Circle | Neutral | Person |
| Group | Hexagon | Green | Group |
| Permission / app role | Small pill on an edge | Amber | Can call / can use |

| Relationship | Stroke | Meaning |
|---|---|---|
| Registration → service principal | Thin dotted | “Creates a tenant identity” |
| Client → resource | Solid arrow | “Can call” (application permission) |
| User/group → service principal | Dashed arrow | “Assigned to use” |
| Observed activity | Animated-looking double line, static in reduced motion | “Called recently” |

## Core components

- `AppShell`: tenant, last scan, global search, export.
- `FilterRail`: object type, permission type, risk, owner, credential state.
- `RelationshipCanvas`: pan, zoom, fit, selection, keyboard navigation.
- `EntityNode`: name, object type, health indicator, relationship count.
- `ConnectionLabel`: permission value plus “configured” or “observed”.
- `EvidenceInspector`: plain-English explanation, exact IDs, source endpoint, timestamps.
- `SummaryCard`: one number, one short label, optional trend; never a decorative card grid.
- `RiskBadge`: Low, Review, High; always paired with a reason.
- `EmptyState`: explains whether no data exists or the current filter hides it.
- `ScanProgress`: named stages and item counts; never a fake percentage.

## Key screens

1. **Overview** — inventory, unowned identities, powerful permissions, expiring credentials.
2. **Relationship map** — search/filter graph with evidence inspector.
3. **Application detail** — blueprint and tenant identity side by side.
4. **Permissions** — sortable configured-access inventory.
5. **Changes** — differences between read-only snapshots.
6. **Settings** — tenant connection, scan scope, retention, permissions.

## Accessibility

- WCAG 2.2 AA contrast, visible focus ring, 44 px minimum pointer targets where practical.
- Full keyboard traversal of filters, nodes, connections, and inspector.
- Graph has an equivalent table view and meaningful screen-reader summaries.
- Never rely on spatial position or color alone to explain a relationship.

## Voice

Short, direct, factual. Preferred: “Orchestrator can call Clean Project API with Api.Read.” Avoid: “A service principal app-role assignment relationship exists.”

