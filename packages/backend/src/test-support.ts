/**
 * Test fixture builders. Excluded from mutation and coverage reports: this file
 * exists only to stand in for `pg` so the Postgres backend's SQL, tenant scoping,
 * and error branches can be exercised without a live database.
 */

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
export class FakePool {
  static instances: FakePool[] = [];
  static reset(): void { FakePool.instances = []; }
  static get last(): FakePool { return FakePool.instances.at(-1)!; }

  readonly queries: RecordedQuery[] = [];
  released = 0;
  connects = 0;
  ended = false;
  responder: QueryResponder = () => EMPTY;

  constructor(readonly config: Record<string, unknown>) { FakePool.instances.push(this); }

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
