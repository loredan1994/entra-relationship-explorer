import { createElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
import { cleanProjectFixture, type TenantSnapshot } from "@entra-explorer/domain";
import { loadSnapshotContext, type SnapshotContext } from "./current-snapshot";
import { AppShell } from "../components/app-shell";
import PermissionsPage from "../app/permissions/page";

vi.mock("./current-snapshot", () => ({ loadSnapshotContext: vi.fn() }));
vi.mock("../components/app-shell-client", () => ({
  AppShellClient: ({ children, tenantLabel, scannedAt, mode, connection }: { children: ReactNode; tenantLabel: string; scannedAt: string; mode: string; connection: string }) =>
    createElement("main", { "data-tenant": tenantLabel, "data-scan": scannedAt, "data-mode": mode, "data-connection": connection }, children),
}));

function live(id: string, scannedAt: string): SnapshotContext {
  const snapshot: TenantSnapshot = { ...cleanProjectFixture, id, mode: "tenant", scannedAt, tenant: { ...cleanProjectFixture.tenant, tenantLabel: `Synthetic ${id}` } };
  return { snapshot, history: [snapshot], state: "connected", liveEnabled: true };
}
const initial = live("first", "2026-10-09T08:00:00.000Z");
const published = live("newly-published", "2026-10-09T09:00:00.000Z");
const signedOut: SnapshotContext = { snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "signed-out", liveEnabled: true };
const noSnapshot: SnapshotContext = { ...signedOut, state: "no-snapshot" };
beforeEach(() => vi.resetAllMocks());

it.each([
  ["a scan is published", initial, published],
  ["the session expires", initial, signedOut],
  ["the first scan is published", noSnapshot, published],
] as const)("keeps the shell and content on one authorized context when %s between page and shell rendering", async (_event, context, laterContext) => {
  vi.mocked(loadSnapshotContext).mockResolvedValueOnce(context).mockResolvedValue(laterContext);
  const page = await PermissionsPage();
  const html = renderToStaticMarkup(await AppShell(page.props));
  expect(html.includes(`data-tenant="${context.snapshot.tenant.tenantLabel}"`)).toBe(true);
  expect(html.includes(`data-scan="${context.snapshot.scannedAt}"`)).toBe(true);
  expect(html.includes(`data-mode="${context.snapshot.mode}"`)).toBe(true);
  expect(html.includes(`data-connection="${context.state}"`)).toBe(true);
  expect(loadSnapshotContext).toHaveBeenCalledTimes(1);
});
