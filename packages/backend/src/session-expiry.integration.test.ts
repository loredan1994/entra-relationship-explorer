import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresBackend } from "./postgres";
import { createIsolatedTestDatabase } from "./test-support";
import type { DurableSession } from "./types";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString) {
  const url = new URL(connectionString);
  if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
}

describe.skipIf(!connectionString)("session expiry during credential refresh", () => {
  const tenantId = randomUUID();
  let database: Awaited<ReturnType<typeof createIsolatedTestDatabase>>;
  let backend: PostgresBackend;
  let sql: Pool;
  beforeAll(async () => {
    database = await createIsolatedTestDatabase(connectionString!, Pool);
    backend = new PostgresBackend({ connectionString: database.connectionString, encryptionKey: randomBytes(32) });
    sql = database.sql;
    await backend.migrate();
  });
  afterAll(async () => {
    try { await backend?.close(); }
    finally { await database?.close(); }
  });

  async function createSession(): Promise<DurableSession> {
    const session = { id: randomUUID(), tenantId, account: {}, accessToken: "original-synthetic-token", tokenCache: "original-synthetic-cache", accessTokenExpiresAt: Date.now() + 1000, sessionExpiresAt: Date.now() + 3600000 };
    await backend.createSession(session);
    return session;
  }

  it("persists refreshed credentials before the session deadline", async () => {
    const session = await createSession();
    const refreshed = { ...session, accessToken: "new-synthetic-token", tokenCache: "new-synthetic-cache", accessTokenExpiresAt: Date.now() + 60000 };
    await backend.updateSession(refreshed);
    expect(await backend.getSession(session.id, tenantId)).toEqual(refreshed);
  });

  it("cannot revive a session that expires while a refresh is pending", async () => {
    const session = await createSession();
    const pending = (await backend.getSession(session.id, tenantId))!;
    await sql.query("UPDATE sessions SET expires_at=now()-interval '1 millisecond' WHERE tenant_id=$1 AND id=$2", [tenantId, session.id]);
    const encryptedBefore = (await sql.query("SELECT expires_at,iv,ciphertext,auth_tag FROM sessions WHERE tenant_id=$1 AND id=$2", [tenantId, session.id])).rows[0];
    await expect(backend.updateSession({ ...pending, accessToken: "new-synthetic-token", tokenCache: "new-synthetic-cache" })).rejects.toThrow("Session was not found in this tenant.");
    expect(await backend.getSession(session.id, tenantId)).toBeNull();
    expect((await sql.query("SELECT expires_at,iv,ciphertext,auth_tag FROM sessions WHERE tenant_id=$1 AND id=$2", [tenantId, session.id])).rows[0]).toEqual(encryptedBefore);
  });
});
