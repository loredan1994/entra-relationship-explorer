import type { ReactNode } from "react";
import { loadSnapshotContext } from "@/server/current-snapshot";
import { AppShellClient } from "./app-shell-client";

export async function AppShell({ children }: { children: ReactNode }) {
  const { snapshot, state } = await loadSnapshotContext(1);
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
