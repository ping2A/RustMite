-- RustMite initial schema (docs/07 §4). Observations use a default partition for MVP.

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  display_name text NOT NULL,
  primary_addr inet,
  ssh_port int NOT NULL DEFAULT 22,
  arch text,
  kernel text,
  os_release jsonb,
  labels jsonb NOT NULL DEFAULT '{}',
  first_seen timestamptz,
  last_scan_at timestamptz,
  last_outcome text,
  UNIQUE (tenant_id, display_name)
);
CREATE INDEX hosts_labels_gin ON hosts USING gin (labels);

CREATE TABLE host_keys (
  host_id uuid REFERENCES hosts,
  key_type text,
  fingerprint text,
  pinned_at timestamptz NOT NULL,
  expires_at timestamptz,
  PRIMARY KEY (host_id, fingerprint)
);

CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  name text,
  last_seen timestamptz,
  capacity int,
  in_flight int,
  version text,
  cert_fingerprint text
);

CREATE TABLE check_definitions (
  id text,
  version int,
  type text NOT NULL,
  severity text NOT NULL,
  confidence text NOT NULL,
  enabled bool NOT NULL DEFAULT true,
  manifest jsonb NOT NULL,
  attack text[],
  cost text,
  signature bytea,
  PRIMARY KEY (id, version)
);

CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY,
  host_id uuid NOT NULL REFERENCES hosts,
  check_set text NOT NULL,
  priority int NOT NULL DEFAULT 100,
  state text NOT NULL DEFAULT 'queued',
  leased_by uuid REFERENCES nodes,
  leased_at timestamptz,
  scheduled_at timestamptz NOT NULL,
  deadline timestamptz NOT NULL,
  attempts int NOT NULL DEFAULT 0
);
CREATE INDEX scan_jobs_dispatch ON scan_jobs (priority DESC, scheduled_at)
  WHERE state = 'queued';
CREATE UNIQUE INDEX one_active_scan_per_host ON scan_jobs (host_id)
  WHERE state IN ('leased', 'running');

CREATE TABLE scan_meta (
  scan_id uuid PRIMARY KEY REFERENCES scan_jobs,
  host_id uuid NOT NULL,
  node_id uuid,
  outcome text NOT NULL,
  delivery jsonb,
  caps jsonb,
  collectors jsonb,
  probe_version text,
  arch text,
  kernel text,
  boot_id text,
  applicable_checks int,
  fired int,
  not_applicable int,
  bytes_from_probe bigint,
  observation_count int,
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms bigint,
  node_signature bytea
);

CREATE TABLE observations (
  scan_id uuid NOT NULL,
  host_id uuid NOT NULL,
  seq int NOT NULL,
  collector text NOT NULL,
  kind text NOT NULL,
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scan_id, seq, created_at)
) PARTITION BY RANGE (created_at);
CREATE TABLE observations_default PARTITION OF observations DEFAULT;
CREATE INDEX observations_data_gin ON observations USING gin (data jsonb_path_ops);
CREATE INDEX observations_host_kind ON observations (host_id, kind);

CREATE TABLE findings (
  id uuid PRIMARY KEY,
  scan_id uuid NOT NULL,
  host_id uuid NOT NULL,
  check_id text NOT NULL,
  check_version int,
  check_type text NOT NULL,
  severity text NOT NULL,
  confidence text NOT NULL,
  title text NOT NULL,
  evidence jsonb NOT NULL,
  attack text[],
  correlation_id uuid,
  status text NOT NULL DEFAULT 'new',
  suppressed_by uuid,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL
);
CREATE INDEX findings_host_status ON findings (host_id, status, severity);
CREATE INDEX findings_check_id ON findings (check_id);
CREATE INDEX findings_evidence_gin ON findings USING gin (evidence);
CREATE UNIQUE INDEX finding_identity ON findings (host_id, check_id, (evidence->>'dedupe_key'));

CREATE TABLE baselines (
  id uuid PRIMARY KEY,
  host_id uuid NOT NULL,
  kind text NOT NULL,
  merkle_root bytea NOT NULL,
  data jsonb NOT NULL,
  created_by uuid,
  created_at timestamptz NOT NULL,
  signature bytea NOT NULL,
  active bool NOT NULL DEFAULT true
);
CREATE INDEX baselines_host_kind ON baselines (host_id, kind) WHERE active;

CREATE TABLE allowlists (
  id uuid PRIMARY KEY,
  tenant_id uuid,
  check_id text NOT NULL,
  match_key text NOT NULL,
  scope text NOT NULL,
  scope_ref text,
  reason text NOT NULL,
  author uuid NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz
);

CREATE TABLE ssh_keys (
  fingerprint text PRIMARY KEY,
  key_type text,
  bits int,
  comment text,
  first_seen timestamptz
);

CREATE TABLE operators (
  id uuid PRIMARY KEY,
  tenant_id uuid,
  email text UNIQUE,
  pw_hash text,
  role text NOT NULL,
  mfa_secret bytea,
  disabled bool DEFAULT false
);

CREATE TABLE api_tokens (
  id uuid PRIMARY KEY,
  tenant_id uuid,
  name text,
  hash bytea NOT NULL,
  scopes text[],
  expires_at timestamptz,
  created_by uuid
);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  tenant_id uuid,
  actor uuid,
  actor_kind text,
  action text NOT NULL,
  target text,
  detail jsonb,
  at timestamptz NOT NULL DEFAULT now(),
  prev_hash bytea,
  hash bytea
);
