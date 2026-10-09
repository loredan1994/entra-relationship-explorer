import type { ReactNode } from "react";
import type { SnapshotContext } from "@/server/current-snapshot";
import { AppShellClient } from "./app-shell-client";

export function AppShell({ children, context }: { children: ReactNode; context: Pick<SnapshotContext, "snapshot" | "state"> }) {
  // The banner describes this page's evidence. A second read could observe a
  // newer scan or expired session and mislabel content already authorized here.
  const { snapshot, state } = context;
  return (
    <AppShellClient
      tenantLabel={snapshot.tenant.tenantLabel}
      scannedAt={snapshot.scannedAt}
      mode={snapshot.mode}
      connection={state}
    >
      {children}
    </AppShellClient>
  );
}
