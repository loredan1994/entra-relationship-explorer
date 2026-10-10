import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";
import { createIsolatedTestDatabase } from "./test-support";
import type { DurableSession } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;

describe.skipIf(!connectionString)("PostgreSQL idle disconnect recovery", () => {
  it("replaces exactly its terminated idle connection and preserves stored session data", async () => {
    const database = await createIsolatedTestDatabase(connectionString!, Pool);
    const applicationName = `disconnect-${randomUUID()}`;
    const url = new URL(database.connectionString);
    url.searchParams.set("application_name", applicationName);
    const backend = new PostgresBackend({ connectionString: url.toString(), encryptionKey: randomBytes(32) });
    const pool = (backend as unknown as { pool: Pool }).pool;
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await backend.migrate();
      const session: DurableSession = {
        id: randomUUID(), tenantId: randomUUID(), account: {},
        accessToken: "synthetic-session-token", tokenCache: "synthetic-session-cache",
        accessTokenExpiresAt: Date.now() + 60_000, sessionExpiresAt: Date.now() + 60_000,
      };
      await backend.createSession(session);
      await expect(backend.health()).resolves.toEqual({ ok: true, database: "postgres" });
      const client = await pool.connect();
      let pid: number;
      try { pid = (await client.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid; }
      finally { client.release(); }
      expect(pool.totalCount).toBe(1);
      expect(pool.idleCount).toBe(1);

      // Restrict termination to the precise returned client of this test's pool.
      // No listener is added here: the production handler must absorb the error.
      const terminated = await database.sql.query<{ terminated: boolean }>(
        "SELECT pg_terminate_backend(pid) AS terminated FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND usename=current_user AND application_name=$2 AND state='idle'",
        [pid, applicationName],
      );
      expect(terminated.rows).toEqual([{ terminated: true }]);
      await vi.waitFor(() => {
        expect(warning.mock.calls).toEqual([["An idle database connection was lost. Future requests can reconnect."]]);
        expect(pool.totalCount).toBe(0);
      }, { timeout: 2000, interval: 10 });

      await expect(backend.health()).resolves.toEqual({ ok: true, database: "postgres" });
      await expect(backend.getSession(session.id, session.tenantId)).resolves.toEqual(session);
      const replacement = await database.sql.query<{ pid: number }>("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='idle'", [applicationName]);
      expect(replacement.rows).toHaveLength(1);
      expect(replacement.rows[0]!.pid).not.toBe(pid);
      expect(pool.totalCount).toBe(1);
      expect(pool.idleCount).toBe(1);
    } finally {
      warning.mockRestore();
      try { await backend.close(); }
      finally { await database.close(); }
    }
  });
});
