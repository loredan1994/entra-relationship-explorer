import { describe, expect, it } from "vitest";
import { DATABASE_SCHEMA } from "./schema";

/**
 * The schema is the last line of defence for two product rules: a scan result
 * belongs to exactly one tenant, and no secret material is stored in the clear.
 * These assertions read the DDL rather than a live database, so they run everywhere.
 */

const TENANT_SCOPED_TABLES = ["auth_flows", "sessions", "snapshots", "scan_jobs", "scan_checkpoints", "access_events", "threat_reviews"];
const ENCRYPTED_TABLES = ["auth_flows", "sessions", "snapshots", "scan_checkpoints", "threat_reviews"];

/** The body of a CREATE TABLE block, up to its closing parenthesis. */
function tableBody(table: string): string {
  const match = new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n\\);`).exec(DATABASE_SCHEMA);
  expect(match, `${table} is not declared`).not.toBeNull();
  return match![1]!;
}

describe("tenant isolation", () => {
  it.each(TENANT_SCOPED_TABLES)("gives %s a non-null tenant_id", (table) => {
    expect(tableBody(table)).toMatch(/tenant_id uuid NOT NULL/);
  });

  // auth_flows is addressed only by primary key (`WHERE id=$1 AND tenant_id=$2`),
  // so its tenant column is a guard rather than a search key and needs no index.
  const TENANT_RANGE_READ_TABLES = TENANT_SCOPED_TABLES.filter((table) => table !== "auth_flows");

  it.each(TENANT_RANGE_READ_TABLES)("leads an index on %s with tenant_id, so a scoped read stays cheap", (table) => {
    expect(DATABASE_SCHEMA).toMatch(new RegExp(`ON ${table} \\(tenant_id`));
  });

  it("indexes auth_flows for expiry sweeps instead", () => {
    expect(DATABASE_SCHEMA).toContain("ON auth_flows (expires_at)");
  });

  it("keys a threat review by tenant, snapshot, and finding together", () => {
    expect(tableBody("threat_reviews")).toContain("PRIMARY KEY (tenant_id, snapshot_id, finding_id)");
  });
});

describe("secret handling", () => {
  it.each(ENCRYPTED_TABLES)("stores %s payloads only as an authenticated ciphertext triple", (table) => {
    const body = tableBody(table);
    expect(body).toMatch(/iv bytea NOT NULL/);
    expect(body).toMatch(/ciphertext bytea NOT NULL/);
    expect(body).toMatch(/auth_tag bytea NOT NULL/);
  });

  it("declares no column that would hold a token, secret, or certificate in the clear", () => {
    expect(DATABASE_SCHEMA).not.toMatch(/\b(access_token|refresh_token|secret|password|private_key|certificate|token_cache)\b/i);
  });

  it("gives every row holding tenant data an expiry or a retention key", () => {
    expect(tableBody("auth_flows")).toMatch(/expires_at timestamptz NOT NULL/);
    expect(tableBody("sessions")).toMatch(/expires_at timestamptz NOT NULL/);
    expect(tableBody("snapshots")).toMatch(/scanned_at timestamptz NOT NULL/);
  });
});

describe("scan job constraints", () => {
  it("permits exactly one active scan per tenant", () => {
    expect(DATABASE_SCHEMA).toContain("CREATE UNIQUE INDEX scan_jobs_one_active_per_tenant ON scan_jobs (tenant_id) WHERE status IN ('queued', 'running', 'cancel_requested')");
  });

  it("recreates the active-scan index rather than skipping it on an existing database", () => {
    // A plain CREATE UNIQUE INDEX IF NOT EXISTS would leave an older, weaker
    // predicate in place after a migration; the drop makes the rule authoritative.
    const dropIndex = DATABASE_SCHEMA.indexOf("DROP INDEX IF EXISTS scan_jobs_one_active_per_tenant");
    const createIndex = DATABASE_SCHEMA.indexOf("CREATE UNIQUE INDEX scan_jobs_one_active_per_tenant");
    expect(dropIndex).toBeGreaterThan(-1);
    expect(dropIndex).toBeLessThan(createIndex);
  });

  it("constrains status to the states the backend actually writes", () => {
    const statuses = ["queued", "running", "complete", "failed", "cancel_requested", "cancelled"];
    const check = /ADD CONSTRAINT scan_jobs_status_check CHECK \(status IN \(([^)]*)\)\)/.exec(DATABASE_SCHEMA);
    expect(check).not.toBeNull();
    for (const status of statuses) expect(check![1]).toContain(`'${status}'`);
  });

  it("re-applies the status constraint so an older database gains the newer states", () => {
    const drop = DATABASE_SCHEMA.indexOf("DROP CONSTRAINT IF EXISTS scan_jobs_status_check");
    const add = DATABASE_SCHEMA.indexOf("ADD CONSTRAINT scan_jobs_status_check");
    expect(drop).toBeGreaterThan(-1);
    expect(drop).toBeLessThan(add);
  });

  it("constrains completion to the two snapshot outcomes or nothing at all", () => {
    expect(tableBody("scan_jobs")).toContain("completion text CHECK (completion IS NULL OR completion IN ('complete', 'partial'))");
  });

  it("refuses negative counters", () => {
    const body = tableBody("scan_jobs");
    expect(body).toContain("collected integer NOT NULL DEFAULT 0 CHECK (collected >= 0)");
    expect(body).toContain("attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0)");
  });

  it("indexes the claim path by status, availability, and age", () => {
    expect(DATABASE_SCHEMA).toContain("ON scan_jobs (status, available_at, created_at)");
  });
});

describe("referential cleanup", () => {
  it("discards a checkpoint with the job it belongs to", () => {
    expect(tableBody("scan_checkpoints")).toContain("job_id uuid PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE");
  });

  it("keeps a job record when its session or snapshot is removed", () => {
    const body = tableBody("scan_jobs");
    expect(body).toContain("session_id uuid REFERENCES sessions(id) ON DELETE SET NULL");
    expect(body).toContain("snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL");
  });

  it("keeps every audit event, unlinked from any deleted session", () => {
    // access_events deliberately carries no foreign key: the audit trail must
    // outlive the session that produced it.
    expect(tableBody("access_events")).toContain("session_id uuid");
    expect(tableBody("access_events")).not.toContain("REFERENCES sessions");
  });
});

describe("idempotent migration", () => {
  it("guards every table and index creation so migrate can run repeatedly", () => {
    const creates = DATABASE_SCHEMA.match(/CREATE TABLE[^(]*/g) ?? [];
    expect(creates.length).toBe(7);
    for (const statement of creates) expect(statement).toContain("IF NOT EXISTS");
    for (const statement of DATABASE_SCHEMA.match(/CREATE INDEX[^(]*/g) ?? []) expect(statement).toContain("IF NOT EXISTS");
  });

  it("declares tables before the tables that reference them", () => {
    expect(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS sessions")).toBeLessThan(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS scan_jobs"));
    expect(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS snapshots")).toBeLessThan(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS scan_jobs"));
    expect(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS scan_jobs")).toBeLessThan(DATABASE_SCHEMA.indexOf("CREATE TABLE IF NOT EXISTS scan_checkpoints"));
  });
});
