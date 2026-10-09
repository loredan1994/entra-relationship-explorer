import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LiveEntraConfig } from "./config-core";

const migrate = vi.fn();
const close = vi.fn();
const constructed: Array<{ connectionString: string; encryptionKey: Uint8Array }> = [];
const instances: Array<{ migrate: typeof migrate; close: typeof close }> = [];

vi.mock("@entra-explorer/backend", () => ({
  PostgresBackend: class {
    constructor(options: { connectionString: string; encryptionKey: Uint8Array }) { constructed.push(options); instances.push(this); }
    migrate = migrate;
    close = close;
  },
}));

const { getBackend } = await import("./backend");

const KEY = new Uint8Array(32).fill(7);
const configFor = (databaseUrl: string) => ({ databaseUrl, dataEncryptionKey: KEY }) as unknown as LiveEntraConfig;

beforeEach(() => {
  vi.resetAllMocks();
  constructed.length = 0;
  instances.length = 0;
  migrate.mockResolvedValue(undefined);
  close.mockResolvedValue(undefined);
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
    const failure = new Error("migration failed");
    migrate.mockRejectedValue(failure);
    const config = configFor("postgres://localhost/six");
    expect(await Promise.allSettled([getBackend(config), getBackend(config)])).toEqual([
      { status: "rejected", reason: failure },
      { status: "rejected", reason: failure },
    ]);
    expect(constructed).toHaveLength(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("recovers on the next request after a temporary initialization failure", async () => {
    const failure = new Error("database temporarily unavailable");
    migrate.mockRejectedValueOnce(failure);
    const config = configFor("postgres://localhost/recovery");
    await expect(getBackend(config)).rejects.toBe(failure);
    const [firstRetry, secondRetry] = await Promise.all([getBackend(config), getBackend(config)]);
    expect(firstRetry).toBe(instances[1]);
    expect(secondRetry).toBe(firstRetry);
    expect(migrate).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledTimes(1);
    expect(close.mock.contexts[0]).toBe(instances[0]);
  });

  it("preserves the initialization failure and retry when failed-pool cleanup also rejects", async () => {
    const failure = new Error("migration connection was lost");
    migrate.mockRejectedValueOnce(failure);
    close.mockRejectedValueOnce(new Error("pool cleanup failed"));
    const config = configFor("postgres://localhost/cleanup-failure");
    await expect(getBackend(config)).rejects.toBe(failure);
    expect(await getBackend(config)).toBe(instances[1]);
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("does not evict or close a replacement connection when an older initialization fails", async () => {
    let rejectMigration!: (reason: Error) => void;
    migrate.mockReturnValueOnce(new Promise<void>((_resolve, reject) => { rejectMigration = reject; }));
    const oldRequest = getBackend(configFor("postgres://localhost/old-pending"));
    const failure = new Error("old database unavailable");
    const failedRequest = expect(oldRequest).rejects.toBe(failure);
    const replacementConfig = configFor("postgres://localhost/replacement");
    const replacement = await getBackend(replacementConfig);
    rejectMigration(failure);
    await failedRequest;
    expect(await getBackend(replacementConfig)).toBe(replacement);
    expect(constructed).toHaveLength(2);
    expect(close).toHaveBeenCalledTimes(1);
    expect(close.mock.contexts[0]).toBe(instances[0]);
  });

  it("returns the requested connection when another database initializes first", async () => {
    let resolveMigration!: () => void;
    migrate.mockReturnValueOnce(new Promise<void>(resolve => { resolveMigration = resolve; }));
    const oldRequest = getBackend(configFor("postgres://localhost/slow-initialization"));
    const replacementConfig = configFor("postgres://localhost/fast-initialization");
    const replacement = await getBackend(replacementConfig);
    resolveMigration();
    expect(await oldRequest).toBe(instances[0]);
    expect(await getBackend(replacementConfig)).toBe(replacement);
    expect(close).not.toHaveBeenCalled();
  });
});
