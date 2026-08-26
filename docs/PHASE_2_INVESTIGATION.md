# Phase 2 investigation quality

## Delivered locally

- Application detail keeps the app registration blueprint separate from the enterprise application (service principal).
- Saved filters persist only their query and object-type choices in the current browser. Values are validated, length-bounded, tenant-keyed, and capped at 20.
- Selecting an object creates a one-hop neighborhood. The visual map is capped at 15 objects and clearly reports truncation; the table remains the complete fallback.
- Unresolved relationships display a warning and retain their source evidence instead of being silently inferred.
- The Changes page compares the latest two encrypted snapshots from the same tenant and reports added, removed, or materially changed objects and relationships. Scan timestamps alone do not produce changes.
- A 10,000-object/9,999-edge contract test keeps one-hop traversal bounded and enforces a generous two-second regression ceiling.
- Desktop and mobile accessibility checks cover the main routes, keyboard interactions, and responsive overflow.

## Investigation rules

- “Configured” always means the directory permits the relationship; it never means the permission was used.
- A partial or unresolved source remains visible with its endpoint and record identifiers.
- Snapshot comparisons reject cross-tenant inputs.
- Changes reflect the two latest retained snapshots, not a continuous audit trail.
- Saved filters contain no tokens or snapshot payloads, but their search text may reveal an object name to another user of the same browser profile.

## Local operational limits

- Scan jobs, encrypted sessions, and encrypted snapshots are durable in PostgreSQL. A web restart preserves them; a worker restart recovers a stale running job after its bounded lease.
- Microsoft Graph throttling uses `Retry-After` or `x-ms-retry-after-ms` when supplied, exponential jitter otherwise, and bounded retries for 408, 429, 500, 502, 503, 504, timeouts, and network failures.
- Tokens are reacquired between Graph pages when they approach expiry.
- If retries are exhausted, the affected endpoint is recorded as skipped and the resulting snapshot is marked partial.
- The local map intentionally does not attempt to render an entire tenant at once.

## Phase 2 exit status

The implementation and synthetic quality gates are complete. A representative GET-only live tenant scan passed. Two UI-triggered scans remain the final visual snapshot-comparison acceptance check.
