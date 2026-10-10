import { randomBytes } from "node:crypto";
import { Pool } from "pg";
import { expect, it, vi } from "vitest";
import { PostgresBackend } from "./postgres";

it("handles repeated real-pool idle errors without throwing or logging connection data", async () => {
  // Constructing pg.Pool does not open a socket. Exercise its real EventEmitter:
  // a missing error listener throws synchronously and would crash a live process.
  const backend = new PostgresBackend({ connectionString: "postgresql://localhost/entra_review_test", encryptionKey: randomBytes(32) });
  const pool = (backend as unknown as { pool: Pool }).pool;
  const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
  try {
    expect(pool).toBeInstanceOf(Pool);
    expect(pool.totalCount).toBe(0);
    const connectionData = { connectionString: "synthetic-sensitive-connection", accessToken: "synthetic-sensitive-token" };
    for (let occurrence = 0; occurrence < 2; occurrence += 1) {
      const error = Object.assign(new Error("synthetic-sensitive-error"), { client: connectionData });
      expect(() => pool.emit("error", error, connectionData)).not.toThrow();
    }
    expect(warning.mock.calls).toEqual([
      ["An idle database connection was lost. Future requests can reconnect."],
      ["An idle database connection was lost. Future requests can reconnect."],
    ]);
    expect(pool.totalCount).toBe(0);
  } finally {
    warning.mockRestore();
    await backend.close();
  }
});
