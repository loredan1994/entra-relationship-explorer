import { Children, isValidElement, type ReactElement, type ReactNode } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { cleanProjectFixture, cleanProjectPreviousFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { AppShell } from "../components/app-shell";
import { AppShellClient } from "../components/app-shell-client";
import { RelationshipExplorer } from "../components/relationship-explorer";
import { EngineWorkspace } from "../components/engine/workspace";
import { ApplicationAccess } from "../components/application-access";
import { ThreatWorkspace } from "../components/threat-workspace";
import { ScanControl } from "../components/scan-control";
import { CredentialHistory } from "../components/credential-history";
import MapPage from "../app/map/page";
import OverviewPage from "../app/overview/page";
import ApplicationDetailPage from "../app/applications/[id]/page";
import EnginePage from "../app/engine/page";
import InvestigationsPage from "../app/investigations/page";
import SecurityPage from "../app/security/page";
import PermissionsPage from "../app/permissions/page";
import ChangesPage from "../app/changes/page";
import SettingsPage from "../app/settings/page";
import GuidePage from "../app/guide/page";
import { getEntraConfig } from "./config";
import { getServerSession } from "./auth/session-store";
import { loadCurrentSnapshot, loadSnapshotContext, loadSnapshotHistory, loadThreatReviewContext, type SnapshotContext } from "./current-snapshot";

const { latestJob } = vi.hoisted(() => ({ latestJob: vi.fn() }));
vi.mock("./current-snapshot", () => ({ loadCurrentSnapshot: vi.fn(), loadSnapshotHistory: vi.fn(), loadSnapshotContext: vi.fn(), loadThreatReviewContext: vi.fn() }));
vi.mock("./config", () => ({ getEntraConfig: vi.fn() }));
vi.mock("./backend", () => ({ getBackend: async () => ({ getLatestJob: latestJob }) }));
vi.mock("./auth/session-store", () => ({ getServerSession: vi.fn(), SESSION_COOKIE: "synthetic-session" }));

type ShellProps = Parameters<typeof AppShell>[0];
type PageElement = ReactElement<ShellProps>;

// Inspect the real server boundary without rendering client hooks. This catches
// a second snapshot read even when both reads happen to return the same data.
function assertShell(page: PageElement, context: SnapshotContext, snapshot = context.snapshot) {
  expect(page.type).toBe(AppShell);
  expect(page.props.context.snapshot).toBe(snapshot);
  expect(page.props.context.state).toBe(context.state);
  const header = AppShell(page.props);
  expect(header.type).toBe(AppShellClient);
  expect(header.props).toMatchObject({
    tenantLabel: snapshot.tenant.tenantLabel,
    scannedAt: snapshot.scannedAt,
    mode: snapshot.mode,
    connection: context.state,
  });
  expect(loadSnapshotContext).toHaveBeenCalledTimes(1);
  expect(loadCurrentSnapshot).not.toHaveBeenCalled();
  expect(loadSnapshotHistory).not.toHaveBeenCalled();
  expect(getServerSession).not.toHaveBeenCalled();
}

function childProps(node: ReactNode, type: unknown): Record<string, unknown> | undefined {
  for (const child of Children.toArray(node)) {
    if (!isValidElement<{ children?: ReactNode }>(child)) continue;
    if (child.type === type) return child.props;
    const found = childProps(child.props.children, type);
    if (found) return found;
  }
}

function contextFor(state: SnapshotContext["state"]): SnapshotContext {
  const snapshot: TenantSnapshot = state === "connected"
    ? { ...cleanProjectFixture, id: "synthetic-page-scan", mode: "tenant", tenant: { ...cleanProjectFixture.tenant, tenantLabel: "Synthetic route test" } }
    : cleanProjectFixture;
  return { snapshot, history: [snapshot], state, liveEnabled: state !== "demo" };
}

function arrange(context: SnapshotContext) {
  // If a header or page accidentally reads again, it observes a different state.
  vi.mocked(loadSnapshotContext).mockResolvedValueOnce(context).mockResolvedValue(contextFor("signed-out"));
  vi.mocked(getEntraConfig).mockReturnValue(context.liveEnabled ? {
    enabled: true, tenantId: cleanProjectFixture.tenant.tenantId, clientId: "synthetic-client",
    clientSecret: "synthetic-test-value", redirectUri: "http://127.0.0.1:3000/api/auth/callback",
    authority: "https://login.microsoftonline.com/synthetic", scopes: [], graphScopes: [],
    databaseUrl: "postgresql://unused/entra_review_test", dataEncryptionKey: new Uint8Array(32), sessionMaxAgeSeconds: 3600,
  } : { enabled: false, reason: "Synthetic demo" });
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(loadThreatReviewContext).mockResolvedValue({ currentReviews: [], priorReviews: [] });
  latestJob.mockResolvedValue(null);
});

const routes: { name: string; page: () => Promise<PageElement>; limit: number; content?: unknown }[] = [
  { name: "Map", page: MapPage, limit: 1, content: RelationshipExplorer },
  { name: "Overview", page: OverviewPage, limit: 1 },
  { name: "Application detail", page: () => ApplicationDetailPage({ params: Promise.resolve({ id: cleanProjectFixture.nodes.find(node => node.kind === "application")!.id }) }), limit: 1 },
  { name: "Engine", page: () => EnginePage({ searchParams: Promise.resolve({ view: "time" }) }), limit: 10, content: EngineWorkspace },
  { name: "Investigations", page: () => InvestigationsPage({ searchParams: Promise.resolve({ view: "applications" }) }), limit: 1, content: ApplicationAccess },
  { name: "Threat workspace", page: () => SecurityPage({ searchParams: Promise.resolve({}) }), limit: 20 },
  { name: "Permissions", page: PermissionsPage, limit: 1 },
  { name: "Changes", page: () => ChangesPage({ searchParams: Promise.resolve({}) }), limit: 20 },
  { name: "Settings", page: () => SettingsPage({ searchParams: Promise.resolve({}) }), limit: 1 },
  { name: "Guide", page: GuidePage, limit: 1 },
];

for (const state of ["connected", "demo"] as const) {
  it.each(routes)(`$name shares one authorized snapshot with its header in ${state} mode`, async ({ name, page: loadPage, limit, content }) => {
    const context = contextFor(state);
    arrange(context);
    const page = await loadPage();
    assertShell(page, context);
    expect(loadSnapshotContext).toHaveBeenCalledWith(limit);
    if (name !== "Changes") expect(page.props.context).toBe(context);
    if (content) expect(childProps(page.props.children, content)?.snapshot).toBe(context.snapshot);
    if (name === "Engine") expect(childProps(page.props.children, EngineWorkspace)?.history).toBe(context.history);
    if (name === "Threat workspace") {
      expect(childProps(page.props.children, ThreatWorkspace)).toMatchObject({ snapshotId: context.snapshot.id, tenantLabel: context.snapshot.tenant.tenantLabel });
      expect(loadThreatReviewContext).toHaveBeenCalledWith(context.snapshot, expect.any(Array));
    }
    if (name === "Settings") {
      expect(childProps(page.props.children, ScanControl)).toMatchObject({ connected: state === "connected", snapshotId: context.snapshot.id, exportAvailable: state === "connected" });
      expect(latestJob).toHaveBeenCalledTimes(state === "connected" ? 1 : 0);
      if (state === "connected") expect(latestJob).toHaveBeenCalledWith(context.snapshot.tenant.tenantId);
    }
  });
}

it("labels a historical comparison with its selected later scan, never the newest scan", async () => {
  const context = contextFor("connected");
  const newest = { ...context.snapshot, id: "newest", scannedAt: "2026-10-09T09:00:00Z" };
  const selected = { ...context.snapshot, id: "selected-later", scannedAt: "2026-10-08T09:00:00Z" };
  const earlier: TenantSnapshot = { ...cleanProjectPreviousFixture, mode: "tenant", id: "selected-earlier", scannedAt: "2026-10-07T09:00:00Z" };
  context.snapshot = newest;
  context.history = [newest, selected, earlier];
  arrange(context);
  const page = await ChangesPage({ searchParams: Promise.resolve({ before: earlier.id, after: selected.id }) });
  assertShell(page, context, selected);
  const comparison = childProps(page.props.children, CredentialHistory);
  expect(comparison?.before).toBe(earlier);
  expect(comparison?.after).toBe(selected);
  expect(context.snapshot).toBe(newest);
});

it.each(["signed-out", "no-snapshot"] as const)("keeps Settings controls and header aligned in %s state without reauthenticating", async state => {
  const context = contextFor(state);
  arrange(context);
  const page = await SettingsPage({ searchParams: Promise.resolve({}) });
  assertShell(page, context);
  expect(childProps(page.props.children, ScanControl)).toMatchObject({ connected: state === "no-snapshot", exportAvailable: false, snapshotId: context.snapshot.id });
  expect(latestJob).toHaveBeenCalledTimes(state === "no-snapshot" ? 1 : 0);
});
