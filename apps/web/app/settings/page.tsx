import { cookies } from "next/headers";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { ScanControl } from "@/components/scan-control";
import { getServerSession, SESSION_COOKIE } from "@/server/auth/session-store";
import { getEntraConfig } from "@/server/config";
import { loadCurrentSnapshot } from "@/server/current-snapshot";
import { getBackend } from "@/server/backend";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  const config = getEntraConfig();
  const snapshot = await loadCurrentSnapshot();
  const cookieStore = await cookies();
  const session = config.enabled ? await getServerSession(cookieStore.get(SESSION_COOKIE)?.value, config) : null;
  const connected = Boolean(config.enabled && session?.tenantId === config.tenantId);
  const latestJob = connected && session && config.enabled ? await (await getBackend(config)).getLatestJob(session.tenantId) : null;
  const graphScopes = config.enabled ? config.graphScopes : ["Application.Read.All", "Directory.Read.All"];
  return (
    <AppShell>
      <div className="page-container settings-page">
        <PageHeading eyebrow="Product boundary" title="Settings" description="Connection, collection scope, retention, and required permissions." />
        <section className="settings-section">
          <div><h2>Tenant connection</h2><p>Live access is disabled unless an operator deliberately configures it.</p></div>
          <div className="settings-card">
            <div className="setting-row"><div><strong>Data source</strong><p>{snapshot.tenant.tenantLabel}</p></div><span className="completion-badge neutral">{snapshot.mode === "tenant" ? "Tenant snapshot" : "Fixture only"}</span></div>
            <div className="setting-row"><div><strong>Microsoft sign-in</strong><p>{config.enabled ? "Single configured tenant only; tokens remain server-side." : config.reason}</p></div><span>{connected ? "Connected" : "Not connected"}</span></div>
            <div className="setting-row"><div><strong>Tenant changes</strong><p>The product exposes no grant, revoke, edit, or remediation action.</p></div><span className="read-only-badge">Read-only</span></div>
            <ScanControl enabled={config.enabled} connected={connected} initialJob={latestJob} />
          </div>
        </section>
        <section className="settings-section">
          <div><h2>Microsoft Graph permissions</h2><p>The scanner has a fixed allowlist; write-capable scopes are rejected at startup.</p></div>
          <div className="settings-card">
            <div className="permission-zero"><strong>{graphScopes.length}</strong><span>delegated Graph read permissions for the core scan</span></div>
            <div className="endpoint-list">{graphScopes.map((scope) => <code key={scope}>{scope.replace("https://graph.microsoft.com/", "")}</code>)}</div>
            <p className="trust-note"><strong>No activity permission.</strong> AuditLog.Read.All is not requested, so the product never labels configured access as observed use.</p>
          </div>
        </section>
        <section className="settings-section">
          <div><h2>Current scan scope</h2><p>Each connection remains traceable to its source endpoint and object IDs.</p></div>
          <div className="settings-card endpoint-list">
            <h3>Collected endpoint patterns</h3>
            {snapshot.completion.collectedEndpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}
            <h3>Intentionally skipped</h3>
            {snapshot.completion.skippedEndpoints.map((endpoint) => <code key={endpoint}>{endpoint} · optional activity</code>)}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
