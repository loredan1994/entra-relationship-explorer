import type { Pool } from "pg";
import { beforeEach, describe, expect, it } from "vitest";
import { createIsolatedTestDatabase, FakePool } from "./test-support";

beforeEach(() => { FakePool.reset(); });

describe("synthetic database fixture safety", () => {
  it.each([
    "postgresql://localhost/entra_review_test?host=remote.example",
    "postgres://localhost/entra_review_test?%68ost=%2Ftmp",
    "socket://localhost/entra_review_test?db=other",
    "https://localhost/entra_review_test",
    "postgres://remote.example/entra_review_test",
    "postgres://localhost/other",
  ])("rejects a connection outside the explicit test target before creating a pool (%s)", async connectionString => {
    await expect(createIsolatedTestDatabase(connectionString, FakePool as unknown as typeof Pool)).rejects.toThrow("Integration tests require an isolated loopback entra_review_test database.");
    expect(FakePool.instances).toEqual([]);
  });
});
