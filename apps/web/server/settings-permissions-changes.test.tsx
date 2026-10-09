import { createElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
import { analyzeFindingLifecycle, cleanProjectFixture, cleanProjectPreviousFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { loadCurrentSnapshot, loadSnapshotContext, loadSnapshotHistory } from "./current-snapshot";
import { getEntraConfig } from "./config";
import { getServerSession } from "./auth/session-store";
import SettingsPage from "../app/settings/page";
import PermissionsPage from "../app/permissions/page";
import ChangesPage from "../app/changes/page";

vi.mock("./current-snapshot", () => ({ loadCurrentSnapshot: vi.fn(), loadSnapshotContext: vi.fn(), loadSnapshotHistory: vi.fn() }));
vi.mock("./config", () => ({ getEntraConfig: vi.fn() }));
vi.mock("./auth/session-store", () => ({ getServerSession: vi.fn(), SESSION_COOKIE: "entra_explorer_session" }));
vi.mock("./backend", () => ({ getBackend: async () => ({ getLatestJob: async () => null }) }));
vi.mock("next/headers", () => ({ cookies: async () => ({ get: () => ({ value: "synthetic" }) }) }));
vi.mock("../components/app-shell", () => ({ AppShell: ({ children }: { children: ReactNode }) => createElement("main", null, children) }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getEntraConfig).mockReturnValue({ enabled: false, reason: "Demo mode" });
  vi.mocked(getServerSession).mockResolvedValue(null);
  vi.mocked(loadCurrentSnapshot).mockResolvedValue(cleanProjectFixture);
  vi.mocked(loadSnapshotContext).mockResolvedValue({ snapshot: cleanProjectFixture, state: "demo", history: [cleanProjectFixture], liveEnabled: false });
  vi.mocked(loadSnapshotHistory).mockResolvedValue([cleanProjectFixture]);
});

it.each([
  ["invalid_state", "The sign-in attempt may have expired"],
  ["access_denied", "cancelled or access was denied"],
  ["identity_error", "Microsoft could not complete sign-in"],
  ["token_exchange_failed", "check the tenant and app authentication configuration"],
])("explains the %s sign-in failure with a safe recovery action", async (authError, expected) => {
  const html = renderToStaticMarkup(await SettingsPage({ searchParams: Promise.resolve({ authError }) }));
  expect(html).toContain('role="alert"');
  expect(html).toContain(expected);
});

it.each(["<script>private-provider-details</script>", "constructor", ["access_denied", "private-provider-details"]])("never echoes unknown or duplicated authentication parameters", async authError => {
  const html = renderToStaticMarkup(await SettingsPage({ searchParams: Promise.resolve({ authError }) }));
  expect(html).toContain("Sign-in could not be completed. Start a new sign-in below.");
  expect(html).not.toContain("private-provider-details");
});

it.each(["no-snapshot", "signed-out"] as const)("offers a useful recovery link instead of a broken download in %s state", async state => {
  vi.mocked(loadSnapshotContext).mockResolvedValue({ snapshot: cleanProjectFixture, state, history: [cleanProjectFixture], liveEnabled: true });
  const html = renderToStaticMarkup(await PermissionsPage());
  expect(html).not.toContain('href="/api/export/relationships.csv"');
  expect(html).toContain('href="/settings"');
  expect(html).toContain(state === "signed-out" ? "Sign in to export tenant data" : "Scan tenant to enable exports");
});

it("does not offer a tenant export before the first completed scan", async () => {
  vi.mocked(getEntraConfig).mockReturnValue({ enabled: true, tenantId: cleanProjectFixture.tenant.tenantId, graphScopes: [] } as never);
  vi.mocked(getServerSession).mockResolvedValue({ tenantId: cleanProjectFixture.tenant.tenantId } as never);
  const html = renderToStaticMarkup(await SettingsPage({ searchParams: Promise.resolve({}) }));
  expect(html).not.toContain('href="/api/export/relationships.csv"');
  expect(html).toContain("Complete a read-only scan to export tenant relationships.");
});

function history() {
  const earlier: TenantSnapshot = { ...cleanProjectPreviousFixture, mode: "tenant", id: "oldest", scannedAt: "2026-08-24T09:00:00Z" };
  const selected: TenantSnapshot = { ...cleanProjectFixture, mode: "tenant", id: "selected", scannedAt: "2026-08-25T09:00:00Z" };
  // The later observation intentionally has different findings. A historical view
  // must not leak these future observations into the selected lifecycle.
  const newest: TenantSnapshot = { ...selected, id: "newest", scannedAt: "2026-08-26T09:00:00Z", nodes: [], edges: [] };
  return [newest, selected, earlier];
}

it("computes the finding lifecycle through the selected later snapshot, not the newest scan", async () => {
  const snapshots = history();
  vi.mocked(loadSnapshotHistory).mockResolvedValue(snapshots);
  const selected = analyzeFindingLifecycle(snapshots.slice(1));
  const newest = analyzeFindingLifecycle(snapshots);
  expect(selected.counts).not.toEqual(newest.counts);
  const html = renderToStaticMarkup(await ChangesPage({ searchParams: Promise.resolve({ before: "oldest", after: "selected" }) }));
  for (const [status, label] of [["new", "New findings"], ["ongoing", "Ongoing"], ["no-longer-detected", "No longer detected"]] as const) {
    expect(html).toContain(`<strong>${selected.counts[status]}</strong><span>${label}</span>`);
  }
  expect(html).toContain("History through the selected later snapshot only.");
});

it("explains the earliest selected snapshot without claiming retained history vanished", async () => {
  vi.mocked(loadSnapshotHistory).mockResolvedValue(history());
  const html = renderToStaticMarkup(await ChangesPage({ searchParams: Promise.resolve({ after: "oldest" }) }));
  expect(html).toContain("No earlier snapshot for this selection");
  expect(html).toContain("Choose a more recent later snapshot");
  expect(html).toContain("Compare latest snapshots");
  expect(html).toContain("<strong>3</strong> retained snapshots");
  expect(html).not.toContain("One tenant snapshot is available");
});

it("explains a stale later-snapshot selection while retaining a usable comparison", async () => {
  vi.mocked(loadSnapshotHistory).mockResolvedValue(history());
  const html = renderToStaticMarkup(await ChangesPage({ searchParams: Promise.resolve({ after: "retention-expired" }) }));
  expect(html).toContain("The selected later snapshot is unavailable. Showing the latest retained snapshot.");
  expect(html).toContain('aria-label="Snapshot change summary"');
});
