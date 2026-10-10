/**
 * Test fixture builders and database isolation. Excluded from mutation and
 * coverage reports: this file provides only test setup and `pg` substitutes.
 */
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";

/** Isolate destructive expiry/DDL fixtures while preserving concurrent transactions. */
export async function createIsolatedTestDatabase(connectionString: string, Pool: typeof import("pg").Pool) {
  const url = new URL(connectionString);
  // pg accepts host query overrides and socket: URLs; neither may bypass the
  // explicit hostname/database boundary checked here before creating a pool.
  if (!["postgres:", "postgresql:"].includes(url.protocol) || url.searchParams.has("host") || !["localhost", "127.0.0.1"].includes(url.hostname) || url.pathname !== "/entra_review_test") throw new Error("Integration tests require an isolated loopback entra_review_test database.");
  // The identifier is generated here, never interpolated from configuration.
  const schema = `entra_test_${randomUUID().replaceAll("-", "")}`;
  const admin = new Pool({ connectionString, max: 1 });
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
  } catch (error) {
    await admin.end();
    throw error;
  }
  // Do not append public: unqualified DDL must never fall back to another suite.
  url.searchParams.set("options", `-c search_path=${schema}`);
  const scopedConnectionString = url.toString();
  const sql = new Pool({ connectionString: scopedConnectionString });
  return {
    connectionString: scopedConnectionString,
    sql,
    async close() {
      try { await sql.end(); }
      finally {
        try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); }
        finally { await admin.end(); }
      }
    },
  };
}

export interface RecordedQuery {
  sql: string;
  params: unknown[];
}

export interface QueryResult {
  rows: Array<Record<string, unknown>>;
  rowCount: number | null;
}

export type QueryResponder = (sql: string, params: unknown[]) => QueryResult | Promise<QueryResult>;

const EMPTY: QueryResult = { rows: [], rowCount: 0 };

export class FakePoolClient {
  constructor(private readonly pool: FakePool) {}
  async query(sql: string, params: unknown[] = []): Promise<QueryResult> { return this.pool.query(sql, params); }
  release(): void { this.pool.released += 1; }
}

/** Stands in for `pg.Pool`; every constructed instance registers itself. */
export class FakePool extends EventEmitter {
  static instances: FakePool[] = [];
  static reset(): void { FakePool.instances = []; }
  static get last(): FakePool { return FakePool.instances.at(-1)!; }

  readonly queries: RecordedQuery[] = [];
  released = 0;
  connects = 0;
  ended = false;
  responder: QueryResponder = () => EMPTY;

  constructor(readonly config: Record<string, unknown>) { super(); FakePool.instances.push(this); }

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    this.queries.push({ sql, params });
    return this.responder(sql, params);
  }

  async connect(): Promise<FakePoolClient> { this.connects += 1; return new FakePoolClient(this); }
  async end(): Promise<void> { this.ended = true; }

  /** Every recorded statement whose SQL contains `fragment`. */
  matching(fragment: string): RecordedQuery[] {
    return this.queries.filter((query) => query.sql.includes(fragment));
  }

  /** The single statement containing `fragment`, asserting there is exactly one. */
  only(fragment: string): RecordedQuery {
    const found = this.matching(fragment);
    if (found.length !== 1) throw new Error(`Expected exactly one query containing ${fragment}, found ${found.length}.`);
    return found[0]!;
  }

  get sql(): string[] { return this.queries.map((query) => query.sql); }
}

/** Answers a single SQL fragment with fixed rows and leaves everything else empty. */
export function respondTo(fragment: string, result: Partial<QueryResult>): QueryResponder {
  return (sql) => (sql.includes(fragment) ? { rows: result.rows ?? [], rowCount: result.rowCount ?? (result.rows?.length ?? 0) } : EMPTY);
}

export function rows(...values: Array<Record<string, unknown>>): QueryResult {
  return { rows: values, rowCount: values.length };
}

/** A scan_jobs row shaped the way `mapJob` expects to read it. */
export function jobRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "job-1",
    tenant_id: "11111111-1111-4111-8111-111111111111",
    session_id: "session-1",
    status: "queued",
    stage: "applications",
    collected: 0,
    detail: "Waiting to begin the read-only scan",
    created_at: new Date("2026-08-26T10:00:00.000Z"),
    updated_at: new Date("2026-08-26T10:00:00.000Z"),
    finished_at: null,
    snapshot_id: null,
    completion: null,
    error: null,
    attempt: 0,
    worker_id: null,
    ...overrides,
  };
}

/** Follow blockers through the startup migration gate without serializing concurrency tests. */
export async function blockedTransactions(pool: import("pg").Pool, applicationName: string, blockerPids: number[], excludePid = 0) {
  return pool.query<{ pid: number; started_at: string }>("WITH RECURSIVE waiting AS (SELECT a.pid,unnest(pg_blocking_pids(a.pid)) AS blocker FROM pg_stat_activity a WHERE a.application_name=$1 UNION SELECT w.pid,unnest(pg_blocking_pids(w.blocker)) FROM waiting w) SELECT DISTINCT w.pid,a.xact_start::text AS started_at FROM waiting w JOIN pg_stat_activity a ON a.pid=w.pid WHERE w.blocker=ANY($2::int[]) AND w.pid<>$3", [applicationName, blockerPids, excludePid]);
}
