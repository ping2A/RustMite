# 01 — System Architecture

## 1. Component inventory

```
                         ┌───────────────────────────────────────────┐
                         │              rustmite-server               │
                         │  axum HTTP/1.1+2, TLS, REST + WebSocket   │
                         │  ┌────────┬──────────┬──────────┬──────┐  │
                         │  │ Sched  │ Check    │ Findings │ Auth │  │
                         │  │ uler   │ compiler │ pipeline │ RBAC │  │
                         │  └────────┴──────────┴──────────┴──────┘  │
                         └───┬───────────────────────┬───────────────┘
                             │ sqlx                  │ notify sinks
                     ┌───────▼────────┐      ┌───────▼─────────────────┐
                     │  PostgreSQL 14+│      │ syslog / webhook /      │
                     │  jobs, findings│      │ SMTP / Splunk / Elastic │
                     │  baselines, kv │      │ / NDJSON file           │
                     └───────▲────────┘      └─────────────────────────┘
                             │ (nodes never touch the DB directly)
                             │ mTLS gRPC-over-HTTP2 or REST+TLS
        ┌────────────────────┴───────────┬────────────────────────────┐
┌───────▼────────┐              ┌────────▼───────┐          ┌─────────▼──────┐
│ rustmite-node A │              │ rustmite-node B │          │ rustmite-node C │
│ SSH pool       │              │ (DMZ)          │          │ (air-gap relay)│
│ probe cache    │              │                │          │                │
└───────┬────────┘              └────────────────┘          └────────────────┘
        │ SSH2
   ┌────▼─────────────────────────────────────────┐
   │ monitored hosts  (probe runs, exits, gone)   │
   └──────────────────────────────────────────────┘
```

### Processes

| Binary | Role | Runs as | Network |
|---|---|---|---|
| `rustmite-server` | Control plane, API, scheduler, check evaluation, storage | unprivileged service user | listens 443 (API), 8443 (node mTLS) |
| `rustmite-node` | Data plane worker; SSH to hosts; probe delivery; result normalisation | unprivileged service user | outbound 22 to hosts, outbound 8443 to server |
| `rustmite-probe` | Ephemeral collector on target | whatever the SSH account is (root recommended, degrades gracefully) | none (stdout/stdin only) |
| `rustmite-cli` | Operator tool; also a standalone single-host scanner | operator | outbound to server, or direct SSH |

**Design rule:** nodes are stateless except for (a) an in-memory SSH connection pool, (b) a local cache of probe binaries, (c) a sealed credential cache with TTL. A node can be destroyed and recreated at any time with no data loss.

## 2. Scan lifecycle (the critical path)

```
1.  Scheduler       → materialise job: (host_id, check_set_id, priority, deadline)
2.  Server          → INSERT INTO scan_jobs (state='queued')
3.  Node            → POST /v1/nodes/lease  {capacity: n}      (long-poll, 25s)
4.  Server          → SELECT ... FOR UPDATE SKIP LOCKED LIMIT n; state='leased'
5.  Node            → resolve credentials (vault), open/reuse SSH session
6.  Node            → fingerprint host: uname -m equivalent via probe-less handshake (§4)
7.  Node            → select probe build for (arch, kernel_class)
8.  Node            → two-stage loader: stage0 → memfd → stage1 (full probe)
9.  Node            → write ScanRequest (JSON, one line) to probe stdin
10. Probe           → run collectors, stream NDJSON observations to stdout
11. Node            → parse with bounded reader; normalise; hash; sign
12. Node            → POST /v1/nodes/results (chunked NDJSON, ≤8 MB per chunk)
13. Server          → evaluate check set over observations → findings
14. Server          → diff vs baseline → drift findings
15. Server          → dedupe/suppress → alerts → sinks
16. Server          → state='complete'; retention policy applied
```

Steps 10–12 are streamed, not buffered: a host with 400k files must not require 400k files' worth of RAM on the node.

### 2.1 Where check evaluation happens

**Decision: server-side, over observations — with a probe-side pre-filter.**

Rationale:
- Checks change constantly; probes are versioned binaries. Server-side evaluation lets you add a check without redeploying probes.
- Full evidence retention makes retro-hunting possible ("re-run the new check against last week's observations").

But shipping every file's metadata from a 2M-inode host is untenable. Therefore:
- The `ScanRequest` carries a **collection plan**: which collectors to run, path scopes, depth limits, and a set of **pre-filter predicates** (a restricted subset of the expression language, see `05` §4.6) that the probe applies to drop obviously-uninteresting observations at the source.
- Observations that any enabled check *could* match are always returned. The check compiler computes the union of required collectors and the minimal pre-filter set — this is a compile step on the server (`05` §5).

## 3. Deployment topologies

| Topology | Description | When |
|---|---|---|
| **All-in-one** | server + node + Postgres in one container/VM | ≤ 100 hosts, evaluation, labs |
| **Split** | 1 server, N nodes in different network zones | Standard. Nodes placed close to their hosts (latency, firewall scope) |
| **HA** | 2+ servers behind L4 LB, Postgres primary/replica, nodes fail over | Production ≥ 1000 hosts |
| **Relay / air-gap** | Node in isolated segment, results couriered as signed NDJSON bundles | OT / classified networks |
| **Standalone CLI** | `rustmite-cli scan --host x --checks all --out result.json` — no server | IR engagements, one-off triage |

The standalone CLI mode is not an afterthought: it is the mode a responder uses at 03:00. It must be able to run every check locally against a single host with only a config file.

## 4. Host fingerprinting handshake (pre-probe)

Before a probe can be selected, the node needs `(arch, endianness, kernel version class, exec-capable tmpfs)`. Sending a wrong-arch binary is a wasted round trip and leaves noise.

Order of preference:

1. **SSH server version string** (free, from the banner) → coarse OS hint only.
2. **SFTP subsystem `stat` of `/proc/sys/kernel/osrelease`** and read of `/proc/version` — zero command execution, works if SFTP is enabled.
3. **Single `exec` of a POSIX-minimal probe-free command** — the only sanctioned shell invocation in the entire system:
   ```sh
   uname -srm; echo "---"; cat /proc/sys/kernel/osrelease 2>/dev/null; id -u
   ```
   Output is parsed defensively; it is *hinting*, never a detection input.
4. **Arch probing by trial** — if all else fails, attempt `x86_64` then `aarch64`, detecting `ENOEXEC`/`Exec format error`.

Cache the result keyed by `(host_id, ssh_host_key_fp)` with a TTL of 7 days; invalidate on any exec failure.

> Note the asymmetry: the *fingerprint* may use shell; *detection* never does. Record in the finding evidence which path was used, because a host that suddenly loses SFTP or returns a different arch is itself suspicious.

## 5. Concurrency model

- **Node**: Tokio multi-thread runtime. One `tokio::task` per host scan. A `Semaphore` caps concurrent SSH sessions (`max_concurrent_scans`, default 64, target 200+). A second semaphore caps concurrent *probe transfers* (bandwidth control, default 8).
- **Per-host serialisation**: never two concurrent scans of the same host. Enforced by a `DashMap<HostId, ()>` guard on the node and a DB unique partial index on the server (`07` §4.3).
- **Backpressure**: node reports `capacity = max_concurrent - in_flight` in every lease call; the server hands out no more than capacity.
- **Server**: axum + Tokio; check evaluation is CPU-bound and runs on `rayon` or a dedicated blocking pool, never on the async reactor.
- **Deadlines**: every scan carries an absolute deadline. Node aborts the SSH channel, best-effort cleanup, and reports `ScanOutcome::Timeout` with partial observations.

## 6. Data flow volumes (sizing targets)

| Item | Typical | Worst case | Handling |
|---|---|---|---|
| Probe binary | 2.5–6 MB per arch (stripped, LTO, `opt-level="z"` for small arches) | 8 MB | Compressed with `zstd` in transit (`04` §4), cached per node |
| Observations per host | 5–40k | 2M (large file tree) | Streamed NDJSON, pre-filtered, zstd-compressed on the SSH channel |
| Findings per host per sweep | 0–50 | 5k (broken baseline) | Rate-limit + collapse into one "excessive findings" alert above a threshold |
| Scan duration | 3–20 s (standard set) | 10 min (incident set with full-filesystem hashing) | Separate queues/priorities |

## 7. Failure semantics

Failures are **first-class results**, never silent retries. `ScanOutcome`:

```rust
pub enum ScanOutcome {
    Complete,
    Partial { failed_collectors: Vec<CollectorId> },
    Timeout { elapsed_ms: u64 },
    ProbeCrashed { signal: Option<i32>, exit: Option<i32>, stderr_tail: String },
    DeliveryFailed(DeliveryError),   // noexec, no writable tmpfs, disk full, ENOEXEC
    AuthFailed(AuthError),
    HostKeyChanged { expected: String, got: String },   // ← ALWAYS high severity
    Unreachable(std::io::Error),
}
```

Rules:
- `HostKeyChanged` raises a **critical** finding immediately (`RM-POL-0001`) and the scan is refused. Never auto-accept a changed host key.
- Three consecutive `ProbeCrashed` or `DeliveryFailed` on a previously-healthy host raises `RM-POL-0002` ("host resisting inspection") at high severity. A rootkit killing the probe must look like an incident, not like flaky infrastructure.
- `AuthFailed` after previously succeeding → medium finding + credential rotation hint.
- Retries use exponential backoff with jitter, capped at 3, and each attempt is recorded.

## 8. Scheduling

Three independent schedules per host group:

| Sweep | Default cadence | Check types |
|---|---|---|
| `pulse` | 5 min | `process`, `decloak`, small `recon` — cheap, high-signal |
| `standard` | 1 h | + `file`, `user`, `dir`, `log`, `policy` |
| `deep` | 24 h | + full-filesystem hashing, entropy sweep, drift baseline refresh, `incident`-class |

Implementation: a leader-elected scheduler (Postgres advisory lock `pg_try_advisory_lock`) materialises jobs into `scan_jobs`. Jitter each host's slot by `hash(host_id) % period` to avoid thundering herds. Never let a `deep` sweep starve `pulse`: separate priority classes in the lease query (`ORDER BY priority DESC, scheduled_at ASC`).

## 9. Observability of the platform itself

- `tracing` + `tracing-subscriber` with JSON output; one span per scan carrying `host_id`, `job_id`, `node_id`.
- Prometheus metrics on `/metrics`: `rustmite_scans_total{outcome}`, `rustmite_scan_duration_seconds` (histogram), `rustmite_findings_total{severity,check_id}`, `rustmite_node_capacity`, `rustmite_ssh_pool_size`, `rustmite_probe_bytes_transferred_total`.
- A **coverage** metric is mandatory: `rustmite_hosts_without_successful_scan{age_bucket}`. The most common real-world failure of this class of product is silent loss of coverage.
