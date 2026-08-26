export const DATABASE_SCHEMA = `
CREATE TABLE IF NOT EXISTS auth_flows (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  auth_tag bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_flows_expires_at ON auth_flows (expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  auth_tag bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_tenant_expires_at ON sessions (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS snapshots (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  scanned_at timestamptz NOT NULL,
  completion_status text NOT NULL CHECK (completion_status IN ('complete', 'partial')),
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  auth_tag bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS snapshots_tenant_scanned_at ON snapshots (tenant_id, scanned_at DESC);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancel_requested', 'cancelled')),
  stage text NOT NULL,
  collected integer NOT NULL DEFAULT 0 CHECK (collected >= 0),
  detail text NOT NULL,
  snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
  completion text CHECK (completion IS NULL OR completion IN ('complete', 'partial')),
  error text,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  worker_id text,
  locked_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancel_requested', 'cancelled'));
DROP INDEX IF EXISTS scan_jobs_one_active_per_tenant;
CREATE UNIQUE INDEX scan_jobs_one_active_per_tenant ON scan_jobs (tenant_id) WHERE status IN ('queued', 'running', 'cancel_requested');
CREATE INDEX IF NOT EXISTS scan_jobs_claim ON scan_jobs (status, available_at, created_at);
CREATE INDEX IF NOT EXISTS scan_jobs_tenant_created ON scan_jobs (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
  job_id uuid PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  auth_tag bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scan_checkpoints_tenant ON scan_checkpoints (tenant_id);

CREATE TABLE IF NOT EXISTS access_events (
  id bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  session_id uuid,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_events_tenant_created ON access_events (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS threat_reviews (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  finding_id text NOT NULL,
  iv bytea NOT NULL,
  ciphertext bytea NOT NULL,
  auth_tag bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, snapshot_id, finding_id)
);
CREATE INDEX IF NOT EXISTS threat_reviews_tenant_snapshot ON threat_reviews (tenant_id, snapshot_id);
`;
