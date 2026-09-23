# 07 — Data Model

Defines the wire types (shared by probe, node, server via `rustmite-proto`), the PostgreSQL schema, and the hostile-input ingest rules.

## 1. Principles

- **One definition.** Every wire type is declared once in `rustmite-proto` (`no_std + alloc`), used by probe and server. No duplicated structs.
- **Stable, versioned schemas.** Every top-level message has a `schema: u16`. Bump on breaking change; the node/server accept a known range.
- **Bytes-honest.** Paths and names are byte strings, not `String`. See `PathBytes` (`03` §3).
- **Big-number-safe.** Values exceeding 2^53 serialise as strings for JSON safety.

## 2. Core newtypes and enums

```rust
pub struct HostId(pub Uuid);           // v7
pub struct NodeId(pub Uuid);
pub struct ScanId(pub Uuid);           // v7, time-sortable
pub struct FindingId(pub Uuid);
pub struct CheckId(pub String);        // "RM-PROC-0007"
pub struct CollectorId(pub &'static str);

pub struct PathBytes(pub Vec<u8>);     // serde: {"s": utf8} | {"b": base64}

pub enum Severity { Info, Low, Medium, High, Critical }
pub enum Confidence { Low, Medium, High }
pub enum CheckType { Process, File, User, Directory, Log, Policy, Incident, Recon, Custom }
pub enum CollectorStatus { Complete, Truncated, Failed, Unsupported, NotApplicable }
pub enum ScanOutcome { /* see 01 §7 */ }
```

## 3. Observation model

An `Observation` is a tagged union; each collector emits one or more variants. Only the most important are shown; the full set is one variant per detection module in `06`.

```rust
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Observation {
    Process(ProcessObs),
    HiddenProcess(HiddenProcessObs),
    Socket(SocketObs),
    HiddenSocket(HiddenSocketObs),
    Module(ModuleObs),
    HiddenModule(ModuleObs),
    BpfProg(BpfProgObs),
    FileMeta(FileMetaObs),
    FileEntropy(FileEntropyObs),
    ElfInfo(ElfInfoObs),
    Preload(PreloadObs),
    ScheduledTask(ScheduledTaskObs),
    Service(ServiceObs),
    Account(AccountObs),
    ShadowEntry(ShadowEntryObs),      // hashes = secret; special handling (10 §7)
    SudoRule(SudoRuleObs),
    AuthorizedKey(AuthorizedKeyObs),
    SshHostKey(SshHostKeyObs),
    DirAnomaly(DirAnomalyObs),
    Timestomp(TimestompObs),
    Mount(MountObs),
    LogIntegrity(LogIntegrityObs),
    UtmpSession(UtmpSessionObs),
    IntegrityMismatch(IntegrityObs),
    IocHit(IocHitObs),
    ContainerInfo(ContainerObs),
    Recon(ReconObs),
}
```

### 3.1 Example variant

```rust
pub struct ProcessObs {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,                 // parsed via last ')' rule
    pub exe: Option<PathBytes>,       // None if unreadable
    pub exe_deleted: bool,            // "(deleted)" or memfd/anon
    pub exe_memfd: bool,
    pub cmdline: Vec<PathBytes>,
    pub cwd: Option<PathBytes>,
    pub root: Option<PathBytes>,
    pub uids: [u32; 4],               // real, eff, saved, fs
    pub gids: [u32; 4],
    pub starttime: u64,               // stat field 22 (string on wire if large)
    pub num_threads: i64,
    pub tty: i32,
    pub state: char,
    pub caps_eff: u64,
    pub ns: NamespaceIds,             // inode per namespace
    pub rwx_maps: u32,                // count of rwx regions
    pub unbacked_exec: u32,           // executable regions with no file backing
    pub listen_ports: Vec<u16>,       // filled by join with sockets
    pub selinux: Option<String>,
}
```

### 3.4 `Finding`

```rust
pub struct Finding {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub host_id: HostId,
    pub check_id: CheckId,
    pub check_version: u32,
    pub check_type: CheckType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,                // rendered from template
    pub evidence: serde_json::Map<String, Value>,  // the fields the check chose
    pub observation_ref: ObservationRef,           // pointer into stored observations
    pub attack: Vec<String>,          // ATT&CK IDs
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub status: FindingStatus,        // New | Acknowledged | Suppressed | Resolved
    pub suppressed_by: Option<AllowlistRef>,
    pub correlation_id: Option<Uuid>, // groups into an incident
}
```

### 3.6 `ScanMeta` (delivery/telemetry)
```rust
pub struct ScanMeta {
    pub scan_id: ScanId, pub host_id: HostId, pub node_id: NodeId,
    pub outcome: ScanOutcome,
    pub delivery: DeliveryReport,     // method A/B/C/D, encoder, bytes, cleanup (04 §6)
    pub probe_version: String, pub arch: Arch, pub kernel: String, pub boot_id: String,
    pub caps: CapabilitySet,          // Hello.caps
    pub collectors: Vec<CollectorReport>,   // per-collector status + counts
    pub applicable_checks: u32, pub fired: u32, pub not_applicable: u32,
    pub started_at: Timestamp, pub finished_at: Timestamp, pub duration_ms: u64,
    pub bytes_from_probe: u64, pub observation_count: u32,
    pub node_signature: Signature,    // node signs the normalised result (10 §4)
}
```

## 4. PostgreSQL schema

PostgreSQL 14+. `sqlx` with compile-time query checking. UUIDv7 primary keys for time-locality. JSONB for evidence/observations with GIN indexes for hunting.

```sql
-- Tenancy & identity ------------------------------------------------------
CREATE TABLE tenants (
  id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL default now());

CREATE TABLE hosts (
  id uuid PRIMARY KEY,                       -- HostId (v7)
  tenant_id uuid NOT NULL REFERENCES tenants,
  display_name text NOT NULL,
  primary_addr inet, ssh_port int NOT NULL default 22,
  arch text, kernel text, os_release jsonb,
  labels jsonb NOT NULL default '{}',        -- {"env":"prod","group":"web"}
  first_seen timestamptz, last_scan_at timestamptz,
  last_outcome text,
  UNIQUE (tenant_id, display_name));
CREATE INDEX ON hosts USING gin (labels);

CREATE TABLE host_keys (                     -- SSH host-key pinning (04 §2.4)
  host_id uuid REFERENCES hosts, key_type text, fingerprint text,
  pinned_at timestamptz NOT NULL, expires_at timestamptz,
  PRIMARY KEY (host_id, fingerprint));

-- Nodes -------------------------------------------------------------------
CREATE TABLE nodes (
  id uuid PRIMARY KEY, name text, last_seen timestamptz,
  capacity int, in_flight int, version text, cert_fingerprint text);

-- Checks ------------------------------------------------------------------
CREATE TABLE check_definitions (
  id text, version int, type text NOT NULL, severity text NOT NULL,
  confidence text NOT NULL, enabled bool NOT NULL default true,
  manifest jsonb NOT NULL, attack text[], cost text,
  signature bytea,                            -- catalog signing (05 §9)
  PRIMARY KEY (id, version));

-- Scans, observations, findings ------------------------------------------
CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY,                         -- ScanId (v7)
  host_id uuid NOT NULL REFERENCES hosts,
  check_set text NOT NULL,                     -- pulse|standard|deep|incident|custom
  priority int NOT NULL default 100,
  state text NOT NULL default 'queued',        -- queued|leased|running|complete|failed
  leased_by uuid REFERENCES nodes, leased_at timestamptz,
  scheduled_at timestamptz NOT NULL, deadline timestamptz NOT NULL,
  attempts int NOT NULL default 0);
-- The lease query relies on this:
CREATE INDEX scan_jobs_dispatch ON scan_jobs (priority DESC, scheduled_at)
  WHERE state = 'queued';
-- One in-flight scan per host (01 §5):
CREATE UNIQUE INDEX one_active_scan_per_host ON scan_jobs (host_id)
  WHERE state IN ('leased','running');

CREATE TABLE scan_meta (
  scan_id uuid PRIMARY KEY REFERENCES scan_jobs,
  host_id uuid NOT NULL, node_id uuid,
  outcome text NOT NULL, delivery jsonb, caps jsonb, collectors jsonb,
  probe_version text, arch text, kernel text, boot_id text,
  applicable_checks int, fired int, not_applicable int,
  bytes_from_probe bigint, observation_count int,
  started_at timestamptz, finished_at timestamptz, duration_ms bigint,
  node_signature bytea);

-- Observations: partitioned by month, retained per policy.
CREATE TABLE observations (
  scan_id uuid NOT NULL, host_id uuid NOT NULL, seq int NOT NULL,
  collector text NOT NULL, kind text NOT NULL, data jsonb NOT NULL,
  created_at timestamptz NOT NULL default now(),
  PRIMARY KEY (scan_id, seq)) PARTITION BY RANGE (created_at);
CREATE INDEX ON observations USING gin (data jsonb_path_ops);
CREATE INDEX ON observations (host_id, kind);

CREATE TABLE findings (
  id uuid PRIMARY KEY, scan_id uuid NOT NULL, host_id uuid NOT NULL,
  check_id text NOT NULL, check_version int, check_type text NOT NULL,
  severity text NOT NULL, confidence text NOT NULL,
  title text NOT NULL, evidence jsonb NOT NULL, attack text[],
  correlation_id uuid,
  status text NOT NULL default 'new',
  suppressed_by uuid,
  first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL);
CREATE INDEX ON findings (host_id, status, severity);
CREATE INDEX ON findings (check_id);
CREATE INDEX ON findings USING gin (evidence);
-- Dedup identity: same host+check+evidence-key collapses into one row updated in place.
CREATE UNIQUE INDEX finding_identity ON findings (host_id, check_id, (evidence->>'dedupe_key'));

-- Baselines (drift, 06 §21) ----------------------------------------------
CREATE TABLE baselines (
  id uuid PRIMARY KEY, host_id uuid NOT NULL, kind text NOT NULL,  -- files|ports|modules|accounts|...
  merkle_root bytea NOT NULL, data jsonb NOT NULL,
  created_by uuid, created_at timestamptz NOT NULL, signature bytea NOT NULL,
  active bool NOT NULL default true);
CREATE INDEX ON baselines (host_id, kind) WHERE active;

-- Allowlists / suppression (05 §8) ---------------------------------------
CREATE TABLE allowlists (
  id uuid PRIMARY KEY, tenant_id uuid, check_id text NOT NULL,
  match_key text NOT NULL, scope text NOT NULL,      -- host|group|global
  scope_ref text, reason text NOT NULL, author uuid NOT NULL,
  created_at timestamptz NOT NULL, expires_at timestamptz);

-- SSH key graph (06 §19) --------------------------------------------------
CREATE TABLE ssh_keys (
  fingerprint text PRIMARY KEY, key_type text, bits int, comment text,
  first_seen timestamptz);
CREATE TABLE ssh_key_placements (
  fingerprint text REFERENCES ssh_keys, host_id uuid, username text,
  role text,                                          -- authorized|host|user_private_pub
  options jsonb, seen_at timestamptz,
  PRIMARY KEY (fingerprint, host_id, username, role));
CREATE INDEX ON ssh_key_placements (host_id);

-- Identity / RBAC (08 §2) -------------------------------------------------
CREATE TABLE operators (
  id uuid PRIMARY KEY, tenant_id uuid, email text UNIQUE, pw_hash text,
  role text NOT NULL, mfa_secret bytea, disabled bool default false);
CREATE TABLE api_tokens (
  id uuid PRIMARY KEY, tenant_id uuid, name text, hash bytea NOT NULL,
  scopes text[], expires_at timestamptz, created_by uuid);
CREATE TABLE audit_log (                              -- append-only (10 §5)
  id bigserial PRIMARY KEY, tenant_id uuid, actor uuid, actor_kind text,
  action text NOT NULL, target text, detail jsonb, at timestamptz NOT NULL default now(),
  prev_hash bytea, hash bytea);                       -- hash chain
```

### 4.3 Notable design points
- **`SELECT … FOR UPDATE SKIP LOCKED`** on `scan_jobs_dispatch` is the whole job-queue (ADR-5). No broker.
- **Partitioned `observations`** — the largest table; drop old partitions per retention rather than `DELETE`.
- **`finding_identity`** gives idempotent findings: a persistent hidden process updates `last_seen`, not a new row each sweep.
- **Hash-chained `audit_log`** makes operator/response actions tamper-evident (`10` §5).
- **Row-level security** by `tenant_id` for multi-tenant deployments.

## 5. Retention & lifecycle
| Data | Default retention | Rationale |
|---|---|---|
| observations | 30 days (configurable), longer for `deep` | volume; enable retro-hunt window |
| findings | 1 year | investigations, compliance |
| scan_meta | 1 year | coverage/audit |
| baselines | until replaced + N historical | drift comparisons |
| audit_log | ≥ 3 years, immutable | compliance |
| shadow hashes | **never persisted in cleartext**; audit *result* only (10 §7) | secret hygiene |

## 6. Hardened ingest (untrusted probe output)

Everything from a probe is attacker-controlled. The node's normaliser enforces:

1. **Bounded reader** (`04` §7): total bytes, per-line bytes, line count, nesting depth caps.
2. **Typed parse only**: `serde_json::from_slice::<Envelope>` — never `serde_json::Value` in the hot path. Unknown fields ignored (`#[serde(deny_unknown_fields)]` is *not* used on wire ingest, to allow forward-compat, but sizes are capped).
3. **No panics**: normaliser is in a crate with `deny(unwrap_used, panic)`.
4. **Sanitisation for storage/display**: paths kept as bytes; when rendered to API/JSON, control characters and ANSI escapes are escaped, never interpreted. UTF-8 validated lazily at the display boundary, never assumed.
5. **Resource fairness**: one hostile host cannot exhaust the node — per-scan memory is O(1) in host size due to streaming; per-scan CPU is deadline-bounded.
6. **Count caps → Truncated**: exceeding `max_observations` stops ingest and marks the scan `Partial`, with a high-visibility meta flag (a host emitting 10⁶ observations to drown a real finding is itself suspicious → `RM-POL-0023`).
7. **`nonce` binding**: every stream is validated against the `Hello` nonce echoed from the `ScanRequest`; a mismatched/absent nonce voids the scan (replay/splice protection).
