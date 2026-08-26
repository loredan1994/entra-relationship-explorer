import type { ReactNode } from "react";
import { loadCurrentSnapshot } from "@/server/current-snapshot";
import { AppShellClient } from "./app-shell-client";

export async function AppShell({ children }: { children: ReactNode }) {
  const snapshot = await loadCurrentSnapshot();
  return <AppShellClient tenantLabel={snapshot.tenant.tenantLabel} scannedAt={snapshot.scannedAt} mode={snapshot.mode}>{children}</AppShellClient>;
}
