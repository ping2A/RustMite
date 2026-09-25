# 03 — The Probe Runtime

The probe is the only RustMite code that executes on an untrusted machine. It has three jobs: gather facts without being lied to, stay within a tiny resource envelope, and leave nothing behind.

## 1. Invocation contract

```
stage1 binary, argv[0] deliberately set by the loader (see 04 §5)
stdin   ← one line of JSON: ScanRequest   (then EOF)
stdout  → NDJSON stream: one Envelope per line
stderr  → human-readable diagnostics only, capped at 64 KiB, never parsed for detection
exit    → 0 = ran to completion (findings may still exist); 1 = fatal; 2 = bad request
```

No command-line flags carry secrets or scan parameters (they would appear in the host's own `/proc/*/cmdline` and in process accounting). Everything arrives on stdin.

### 1.1 `ScanRequest`

```rust
pub struct ScanRequest {
    pub schema: u16,                 // = 1
    pub scan_id: Uuid,               // v7
    pub nonce: [u8; 32],             // echoed in every Envelope; detects replay/splicing
    pub deadline_ms: u32,            // wall clock budget, probe self-terminates
    pub mode: ProbeMode,             // Scan | Respond | Selftest
    pub plan: CollectionPlan,
    pub limits: Limits,
    pub issued_at: u64,              // unix ms
    pub issuer_sig: Option<Signature>, // ed25519 over the canonical request, node's key
}

pub struct CollectionPlan {
    pub collectors: Vec<CollectorSpec>,
    pub scopes: PathScopes,
    pub prefilters: Vec<CompiledPredicate>,  // 05 §4.6
    pub ioc: IocSet,                         // hashes, path globs, strings for aho-corasick
}

pub struct Limits {
    pub max_rss_bytes: u64,          // default 24 MiB → RLIMIT_AS / RLIMIT_DATA / RLIMIT_RSS
    pub max_observations: u32,       // default 500_000
    pub max_output_bytes: u64,       // default 64 MiB
    pub max_files_examined: u32,     // default 2_000_000
    pub max_bytes_hashed: u64,       // default 8 GiB
    pub nice: i8,                    // default 19 → setpriority
    pub io_idle: bool,               // default true
    pub max_transfer_bps: u64,       // 0 = unlimited; node paces SSH probe delivery
    pub max_cpu_pct: u8,             // 0 = nice-only soft hint
    pub max_open_files: u32,         // default 256 → RLIMIT_NOFILE
}
```

Operators set these from **Settings → Agent limits** (persisted in `.dev/probe-limits.json`). Each lease embeds `probe_limits`.

- **Agentless probe:** the node writes them into `ScanRequest.limits` before pushing the probe (RLIMIT / nice / cooperative `Budget`).
- **AgentLite:** the same envelope caps `max_observations` / `max_files_examined` / `max_output_bytes`, applies `nice`/`ionice`/`ulimit` on the remote shell, and paces SSH result transfer via `max_transfer_bps`.

`deadline_ms` remains the wall-clock time limit (fleet `scan_timeout_secs` / check-set default).

`issuer_sig` is optional and exists only so a host operator *can* verify what was asked of their machine (transparency, useful in regulated environments). It is not a security control for RustMite itself.

## 2. Startup sequence

```rust
fn main() -> ! {
    // 1. Harden self BEFORE doing anything observable.
    self_protect();
    // 2. Read stdin fully (bounded to 1 MiB), parse ScanRequest.
    // 3. Apply limits (RLIMIT_AS, RLIMIT_NOFILE, RLIMIT_FSIZE=0 in Scan mode).
    // 4. Arm the deadline (see §4).
    // 5. Emit Envelope::Hello { probe_version, arch, kernel, boot_id, euid, caps, capabilities_detected }.
    // 6. Run collectors in plan order, honouring budget.
    // 7. Emit Envelope::Summary { per-collector status, counters, elapsed }.
    // 8. Exit(0). No cleanup of self needed — the loader owns that (04 §6).
}
```

### 2.1 `self_protect()`

| Step | Syscall | Why |
|---|---|---|
| Drop scheduling priority | `setpriority(PRIO_PROCESS, 0, nice)` + `sched_setscheduler(0, SCHED_IDLE)` | G3: never impact production |
| Drop I/O priority | `ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE)` | full-filesystem walks must not starve the host |
| Memory ceiling | `setrlimit(RLIMIT_AS, limits.max_rss_bytes)` | a runaway probe on an appliance is a customer incident |
| No core dumps | `prctl(PR_SET_DUMPABLE, 0)` | avoids writing scan parameters to disk on crash |
| No new privileges | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | defence in depth |
| Clear environment | overwrite `environ` | do not leak node-side env into `/proc/self/environ` |
| Disable write in scan mode | `setrlimit(RLIMIT_FSIZE, 0)` | **hard guarantee** the scan cannot modify the host. Any accidental write returns `EFBIG`/`SIGXFSZ`. Skipped in `Respond` mode. |
| Ignore SIGPIPE | `signal(SIGPIPE, SIG_IGN)` | node may close early; handle `EPIPE` gracefully |

`RLIMIT_FSIZE = 0` is a strong, auditable claim you can make to a customer: *"the scanner is physically incapable of writing to your filesystem."* Implement it.

### 2.2 Capability detection

Emit in `Hello` a structured record of what the probe can actually do on this kernel:

```json
{"kind":"hello","kernel":"3.10.0-1160.el7.x86_64","arch":"x86_64","euid":0,
 "caps":{"memfd_create":true,"statx":false,"sock_diag":true,"bpf_prog_iter":false,
         "map_files":true,"cgroup_v2":false,"kallsyms_readable":false,
         "tracefs_readable":true,"proc_sched_debug":true,"audit_netlink":true}}
```

The server uses this to mark checks `NotApplicable` rather than `Pass` — see `05` §6.

## 3. Output format

NDJSON, one `Envelope` per line, ≤ 256 KiB per line:

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Envelope {
    Hello(Hello),
    Obs { c: CollectorId, n: u32, d: Observation },  // short keys: volume matters
    CollectorStatus { c: CollectorId, status: CollectorStatus, reason: Option<String>, stats: Stats },
    Summary(Summary),
    Error { c: Option<CollectorId>, code: ErrCode, msg: String },
}
```

Rules:
- Every line carries `nonce` implicitly by being on the stream started by `Hello`; the node validates the `Hello` nonce and rejects the stream otherwise.
- Numbers that can exceed 2^53 (inode numbers, byte counts) serialise as strings. JSON in the node is parsed by `serde_json` into typed structs, never `Value`, so this is explicit.
- Paths are emitted as **raw bytes, base64-encoded**, when they are not valid UTF-8. Linux paths are byte strings; a rootkit will use invalid UTF-8 precisely to break naive tooling. `PathBytes` newtype in `rustmite-proto` handles this: serialise as `{"s":"/etc/passwd"}` or `{"b":"L2V0Yy9..."}`.

## 4. Budget and deadline enforcement

Single-threaded by default (predictable footprint on 1-core appliances); an optional worker pool for hashing on hosts with ≥4 cores, capped at `min(4, ncpu/2)`.

```rust
pub struct Budget {
    deadline: Instant,
    observations: AtomicU32,
    bytes_out: AtomicU64,
    files: AtomicU32,
    bytes_hashed: AtomicU64,
}
impl Budget {
    /// Checked at every loop iteration in every collector. Non-negotiable.
    pub fn check(&self) -> Result<(), BudgetExceeded>;
}
```

The deadline is enforced two ways: cooperative `Budget::check()` calls, and a hard backstop using `timer_create`/`SIGALRM` (or a watchdog thread on a `SCHED_IDLE` thread) that calls `exit_group` after `deadline + 5 s`. A probe must never become the thing that needs killing.

When a budget is exhausted, the collector emits `CollectorStatus { status: Truncated, stats }` — the scan is `Partial`, never silently short.

## 5. Collector scheduling order

Order matters, because a truncated scan should still contain the highest-signal data:

1. `decloak.process` (hidden PIDs) — Trivial cost, highest signal
2. `process.inventory`
3. `modules` (LKM) and `ebpf`
4. `net.sockets` + `decloak.socket`
5. `persistence.*` (ld.so.preload, cron, systemd, authorized_keys)
6. `log.integrity`
7. `user.accounts`
8. `dir.hidden` / `fs.anomaly`
9. `file.targeted` (scoped paths, setuid inventory)
10. `entropy` / `file.sweep` (High cost)
11. `recon.*` (inventory, last)

## 6. Error handling doctrine

- **No `unwrap`, `expect`, `panic!`, or indexing that can panic** in `rustmite-probe`, `rustmite-collect`, `rustmite-analyze`, `rustmite-sys`. Enforced by `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::integer_arithmetic)]` in those crates. A panic on a customer's production appliance is a product-ending event.
- `panic = "abort"` in the probe profile so any escaped panic dies immediately and visibly rather than unwinding through raw syscall wrappers.
- Every collector is independently fallible. One collector's `Err` must never abort the scan; it produces `CollectorStatus::Failed` and the scan continues.
- All parsing (`/proc/*/stat`, `utmp`, ELF, shadow) treats input as attacker-controlled: bounded reads, no trust in declared lengths, explicit `checked_*` arithmetic.

## 7. Reading `/proc` safely

`/proc` is a hostile-adjacent interface even on a clean box. Rules for every collector:

1. **Open by directory fd, then `openat` relative** (`open("/proc/1234", O_DIRECTORY)` once, then `openat(dfd, "stat")`). Prevents PID-reuse races between reads and avoids TOCTOU on the path.
2. **Validate identity across reads**: read `starttime` (field 22 of `/proc/<pid>/stat`) first and last; if it changed, the PID was recycled — discard the record.
3. **Bounded reads**: `/proc` files report `st_size == 0`; read with a growing buffer capped at 4 MiB (`/proc/<pid>/maps` on a large JVM is genuinely megabytes).
4. **`/proc/<pid>/stat` parsing is not whitespace splitting.** `comm` (field 2) is `(`-delimited and may itself contain spaces, parentheses and newlines. Parse by finding the **last** `)` in the line, then split the remainder. Getting this wrong is the single most common bug in process parsers and is directly exploitable for evasion: a process named `(1 (R 0` breaks naive parsers.
5. **Never follow symlinks blindly**: use `readlinkat` to *read* `exe`, `cwd`, `root`, `fd/*` — never `open` them, or you may open an attacker-chosen device/FIFO and block forever. If you must open, use `O_NOFOLLOW | O_NONBLOCK | O_PATH` and `statx` the `O_PATH` fd.
6. **Never read FIFOs/devices** during file sweeps: `statx` first, act only on `S_IFREG`.

## 8. Modes

| Mode | Purpose | Writes allowed | Extra auth |
|---|---|---|---|
| `Scan` | Normal collection | No (`RLIMIT_FSIZE=0`) | none |
| `Selftest` | Emit capability report + run collectors against an empty plan; used for onboarding and CI | No | none |
| `Respond` | Execute an authorised containment action | Yes, narrowly | Requires `issuer_sig` + an `ActionGrant` (`09` §3) |

`Respond` is a separate code path with its own audit envelope. It must be feature-gated (`--features respond`) so a build can be produced that is *provably* incapable of modifying the host — several customer segments will demand exactly that binary.

## 9. Probe self-tests (run in CI, not on hosts)

- Round-trip: every `Observation` variant serialises and deserialises identically.
- Fixture replay: for each fixture tree in `fixtures/`, the full collector set produces a byte-identical NDJSON stream against a golden file (modulo timestamps/nonce). This is the regression net.
- Fuzz: `cargo-fuzz` targets for `/proc/*/stat`, `maps`, `utmp`, ELF headers, `authorized_keys`, `shadow`, and the `ScanRequest` deserialiser.
- Footprint: assert peak RSS < 24 MiB over the largest fixture; assert zero filesystem writes via a `FsSource` that panics on write in test builds.
