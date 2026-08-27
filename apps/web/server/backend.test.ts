import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LiveEntraConfig } from "./config-core";

const migrate = vi.fn();
const constructed: Array<{ connectionString: string; encryptionKey: Uint8Array }> = [];

vi.mock("@entra-explorer/backend", () => ({
  PostgresBackend: class {
    constructor(options: { connectionString: string; encryptionKey: Uint8Array }) { constructed.push(options); }
    migrate = migrate;
  },
}));

const { getBackend } = await import("./backend");

const KEY = new Uint8Array(32).fill(7);
const configFor = (databaseUrl: string) => ({ databaseUrl, dataEncryptionKey: KEY }) as unknown as LiveEntraConfig;

beforeEach(() => {
  vi.clearAllMocks();
  constructed.length = 0;
  migrate.mockResolvedValue(undefined);
});

describe("connection reuse", () => {
  it("constructs the backend once and reuses it for the same database", async () => {
    const config = configFor("postgres://localhost/one");
    const first = await getBackend(config);
    const second = await getBackend(config);
    expect(second).toBe(first);
    expect(constructed).toHaveLength(1);
    expect(constructed[0]).toMatchObject({ connectionString: "postgres://localhost/one", encryptionKey: KEY });
  });

  it("migrates exactly once for a reused connection", async () => {
    const config = configFor("postgres://localhost/two");
    await getBackend(config);
    await getBackend(config);
    await getBackend(config);
    expect(migrate).toHaveBeenCalledTimes(1);
  });

  it("rebuilds the backend when the database URL changes", async () => {
    const first = await getBackend(configFor("postgres://localhost/three"));
    const second = await getBackend(configFor("postgres://localhost/four"));
    expect(second).not.toBe(first);
    expect(constructed.map((options) => options.connectionString)).toEqual([
      "postgres://localhost/three",
      "postgres://localhost/four",
    ]);
  });

  it("waits for the migration to finish before handing the backend out", async () => {
    let resolveMigration: () => void = () => {};
    migrate.mockReturnValue(new Promise<void>((resolve) => { resolveMigration = resolve; }));
    const config = configFor("postgres://localhost/five");
    let settled = false;
    const pending = getBackend(config).then((backend) => { settled = true; return backend; });
    await Promise.resolve();
    expect(settled).toBe(false);
    resolveMigration();
    await expect(pending).resolves.toBeDefined();
    expect(settled).toBe(true);
  });

  it("surfaces a migration failure to every caller awaiting the same connection", async () => {
    migrate.mockRejectedValue(new Error("migration failed"));
    const config = configFor("postgres://localhost/six");
    await expect(getBackend(config)).rejects.toThrow("migration failed");
    await expect(getBackend(config)).rejects.toThrow("migration failed");
    expect(constructed).toHaveLength(1);
  });
});
