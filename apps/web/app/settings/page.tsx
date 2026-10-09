import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { ScanControl } from "@/components/scan-control";
import { getEntraConfig } from "@/server/config";
import { loadSnapshotContext } from "@/server/current-snapshot";
import { getBackend } from "@/server/backend";

export const dynamic = "force-dynamic";

function endpointPatterns(endpoints: string[]) {
  const counts = new Map<string, number>();
  for (const endpoint of endpoints) {
    const pattern = endpoint.replace(/\/(applications|servicePrincipals|groups)\/[0-9a-f-]{36}(?=\/)/gi, "/$1/{id}");
    counts.set(pattern, (counts.get(pattern) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
}

const authErrors: Record<string, string> = {
  invalid_state: "Sign-in could not be verified. The sign-in attempt may have expired. Start a new sign-in below.",
  access_denied: "Microsoft sign-in was cancelled or access was denied. Start sign-in again when you are ready; no tenant changes were made.",
  identity_error: "Microsoft could not complete sign-in. Try again using an account in the configured tenant.",
  token_exchange_failed: "Sign-in could not be completed. Try again; if it continues, ask the operator to check the tenant and app authentication configuration.",
};

export default async function SettingsPage({ searchParams }: { searchParams: Promise<{ authError?: string | string[] }> }) {
  const { authError } = await searchParams;
  // The callback only emits fixed codes. Never reflect a provider description or
  // arbitrary URL text into the connection feedback.
  const authMessage = authError ? (typeof authError === "string" && Object.hasOwn(authErrors, authError) ? authErrors[authError] : "Sign-in could not be completed. Start a new sign-in below.") : null;
  const config = getEntraConfig();
  const context = await loadSnapshotContext(1);
  const { snapshot, state } = context;
  const connected = config.enabled && (state === "no-snapshot" || (state === "connected" && snapshot.tenant.tenantId === config.tenantId));
  const latestJob = connected && config.enabled ? await (await getBackend(config)).getLatestJob(config.tenantId) : null;
  const graphScopes = config.enabled ? config.graphScopes : ["Application.Read.All", "Directory.Read.All"];
  return (
    <AppShell context={context}>
      <div className="page-container settings-page">
        <PageHeading eyebrow="Product boundary" title="Settings" description="Connection, collection scope, retention, and required permissions." actions={<Link className="button button-secondary" href="/guide">Workspace guide</Link>} />
        <section className="onboarding-callout" aria-labelledby="onboarding-title">
          <div><p className="eyebrow">Before you connect</p><h2 id="onboarding-title">Read-only by design</h2><p>The collector inventories Entra relationships so it can explain configured access and possible privilege paths. It never grants consent, changes an object, creates a credential, or sends a token to the browser.</p></div>
          <ol>
            <li><strong>1 · Review</strong><span>Two core delegated read permissions, any explicitly enabled optional evidence scopes, and the exact endpoints below.</span></li>
            <li><strong>2 · Sign in</strong><span>Use an administrator in the one configured tenant. Authentication stays server-side.</span></li>
            <li><strong>3 · Scan</strong><span>Every Microsoft Graph request is validated HTTPS GET. Failures remain visible as partial evidence.</span></li>
            <li><strong>4 · Investigate</strong><span>Review relationships, attack paths, changes, and sanitized exports without modifying Entra.</span></li>
          </ol>
        </section>
        <section className="settings-section">
          <div><h2>Tenant connection</h2><p>Live access is disabled unless an operator deliberately configures it.</p></div>
          <div className="settings-card">
            <div className="setting-row"><div><strong>Data source</strong><p>{snapshot.tenant.tenantLabel}</p></div><span className="completion-badge neutral">{snapshot.mode === "tenant" ? "Live tenant snapshot" : "Sample data only"}</span></div>
            <div className="setting-row"><div><strong>Microsoft sign-in</strong><p>{config.enabled ? "Single configured tenant only; tokens remain server-side." : config.reason}</p></div><span>{connected ? "Connected" : "Not connected"}</span></div>
            <div className="setting-row"><div><strong>Tenant changes</strong><p>The product exposes no grant, revoke, edit, or remediation action.</p></div><span className="read-only-badge">Read-only</span></div>
            {authMessage ? <p className="notice-banner" role="alert">{authMessage}</p> : null}
            <ScanControl enabled={config.enabled} connected={connected} initialJob={latestJob} exportAvailable={connected && snapshot.mode === "tenant"} snapshotId={snapshot.id} />
          </div>
        </section>
        <section className="settings-section">
          <div><h2>Microsoft Graph permissions</h2><p>The scanner has a fixed allowlist; write-capable scopes are rejected at startup.</p></div>
          <div className="settings-card">
            <div className="permission-zero"><strong>{graphScopes.length}</strong><span>delegated Graph read permissions enabled for this deployment</span></div>
            <div className="permission-explanations">{graphScopes.map((scope) => { const name = scope.replace("https://graph.microsoft.com/", ""); const explanation: Record<string, string> = { "Application.Read.All": "Reads application registrations, enterprise applications (service principals), owners, credential metadata, app-role assignments, and federated workload trust.", "Directory.Read.All": "Reads people, groups, devices, administrative units, memberships, delegated permission grants, and directory details needed to resolve relationship endpoints.", "RoleManagement.Read.Directory": "Optionally reads role definitions, active administrative assignments, PIM eligibility schedules, and their directory scopes.", "Policy.Read.All": "Optionally reads Conditional Access, tenant authorization, and partner-specific cross-tenant access settings.", "Policy.Read.PermissionGrant": "Optionally reads permission grant policies and their include and exclude conditions so user-consent assignments can be explained.", "AuditLog.Read.All": "Optionally reads a server-filtered 30-day sign-in activity window so observed activity remains distinct from configured access." }; return <article key={scope}><code>{name}</code><p>{explanation[name] ?? "Approved read-only evidence scope."}</p></article>; })}</div>
            <p className="trust-note"><strong>{graphScopes.some((scope) => scope.endsWith("/AuditLog.Read.All")) ? "Activity overlay enabled." : "No activity permission."}</strong> {graphScopes.some((scope) => scope.endsWith("/AuditLog.Read.All")) ? "Observed sign-ins use a bounded 30-day Graph query and never convert configured access into proof of use." : "AuditLog.Read.All is not requested, so the product does not infer dormancy from unavailable logs."}</p>
          </div>
        </section>
        <section className="settings-section">
          <div><h2>Current scan scope</h2><p>Each connection remains traceable to its source endpoint and object IDs.</p></div>
          <div className="settings-card endpoint-list">
            <h3>Collected endpoint patterns</h3>
            {endpointPatterns(snapshot.completion.collectedEndpoints).map(([endpoint, count]) => <code key={endpoint}>{endpoint}{count > 1 ? ` · ${count} reads` : ""}</code>)}
            <h3>Skipped or unavailable</h3>
            {endpointPatterns(snapshot.completion.skippedEndpoints).map(([endpoint, count]) => <code key={endpoint}>{endpoint} · {count > 1 ? `${count} unavailable reads` : "unavailable in this scan"}</code>)}
            <p><Link className="text-link" href="/investigations?view=coverage">Review collection status, limits and failed reads →</Link></p>
          </div>
        </section>
        <section className="settings-section">
          <div><h2>Storage and retention</h2><p>Review records are local workspace data. Saving one never changes Microsoft Entra.</p></div>
          <div className="settings-card">
            <div className="setting-row"><div><strong>Tenant evidence and review decisions</strong><p>Encrypted in your own PostgreSQL database. Snapshot evidence and linked decisions expire after 30 days.</p></div></div>
            <div className="setting-row"><div><strong>Sample workspace and what-if plans</strong><p>Demo decisions use browser storage. What-if calculations stay in memory; importing a review plan does not upload it.</p></div></div>
            <div className="setting-row"><div><strong>Explicit exports</strong><p>Downloads can contain tenant identifiers and sensitive relationships. Sanitized exports are not anonymous; store and share them accordingly.</p></div></div>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
