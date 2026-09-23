# 02 — Cargo Workspace, Crate Graph and Build Targets

## 1. Workspace layout

```
rustmite/
├── Cargo.toml                  # [workspace], resolver = "2"
├── rust-toolchain.toml         # pinned stable, MSRV enforced
├── deny.toml                   # cargo-deny: licences, advisories, pure-Rust policy
├── crates/
│   ├── rustmite-sys/            # raw Linux syscall + /proc primitives (no_std-able, no libc)
│   ├── rustmite-proto/          # wire types, JSON schemas, IDs, versioning
│   ├── rustmite-collect/        # collectors (the detection data sources)
│   ├── rustmite-analyze/        # pure analysis: entropy, ELF, hashing, parsers
│   ├── rustmite-probe/          # the target-side binary
│   ├── rustmite-loader/         # stage0 loader binary (tiny)
│   ├── rustmite-expr/           # check expression language: parser, typing, evaluator
│   ├── rustmite-checks/         # check manifests, compiler, evaluation over observations
│   ├── rustmite-transport/      # SSH client, delivery, session pool
│   ├── rustmite-node/           # node daemon
│   ├── rustmite-server/         # control plane
│   ├── rustmite-store/          # sqlx repositories + migrations
│   ├── rustmite-crypto/         # signing, vault sealing, key types
│   ├── rustmite-notify/         # alert sinks
│   └── rustmite-cli/            # operator CLI + standalone scanner
├── checks/                     # the detection catalog as data (TOML/JSON manifests)
├── fixtures/                   # recorded /proc + /sys trees for tests
├── xtask/                      # build orchestration: cross-compile matrix, embed probes
└── docs/                       # this document set
```

## 2. Crate responsibilities and dependency direction

```
rustmite-sys ──────────────┐
      ▲                   ▼
rustmite-analyze ──► rustmite-collect ──► rustmite-probe ──► rustmite-loader (build dep)
      ▲                   │
      └───────────────────┴──► rustmite-proto ◄──── rustmite-expr ◄── rustmite-checks
                                   ▲                                      ▲
                     rustmite-transport ──► rustmite-node ──────────────────┘
                                   ▲
        rustmite-crypto ──► rustmite-store ──► rustmite-server ──► rustmite-notify
                                                   ▲
                                            rustmite-cli
```

Hard rules:
- `rustmite-sys`, `rustmite-analyze`, `rustmite-collect`, `rustmite-probe` must compile with **zero** `libc` in `cargo tree`, **zero** `build.rs` invoking a C compiler, and no `std::process::Command`.
- `rustmite-proto` is `no_std + alloc` compatible so the probe and the server share exactly one definition of every wire type. Never duplicate a struct.
- No crate depends on a crate to its right in the diagram.

### 2.1 `rustmite-sys` — the foundation

Wraps `rustix` (linux_raw backend) and adds what `rustix` does not cover.

```rust
// crates/rustmite-sys/src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod syscalls {
    /// Does a process with this PID exist, from the kernel's point of view,
    /// without consulting /proc at all?
    pub fn pid_exists(pid: i32) -> PidProbe;
    pub fn sched_getscheduler(pid: i32) -> Result<i32, Errno>;
    pub fn getpgid(pid: i32) -> Result<i32, Errno>;
    pub fn getsid(pid: i32) -> Result<i32, Errno>;
    pub fn sched_getaffinity_raw(pid: i32, buf: &mut [u8]) -> Result<usize, Errno>;
    pub fn sched_getattr(pid: i32, buf: &mut [u8]) -> Result<(), Errno>;
    pub fn kill0(pid: i32) -> Result<(), Errno>;
    pub fn bpf(cmd: u32, attr: &mut [u8]) -> Result<i64, Errno>;
    pub fn memfd_create(name: &CStr, flags: u32) -> Result<OwnedFd, Errno>;
    pub fn ioctl_getflags(fd: BorrowedFd) -> Result<u32, Errno>;   // FS_IOC_GETFLAGS
    pub fn getdents64_raw(fd: BorrowedFd, buf: &mut [u8]) -> Result<usize, Errno>;
    pub fn statx_full(dirfd: BorrowedFd, path: &CStr) -> Result<Statx, Errno>;
    pub fn listxattr(path: &CStr, buf: &mut [u8]) -> Result<usize, Errno>;
    pub fn getxattr(path: &CStr, name: &CStr, buf: &mut [u8]) -> Result<usize, Errno>;
    pub fn init_module_absent_check() -> ...;
}

pub mod procfs {
    /// A trait so every collector is testable against a recorded tree.
    pub trait ProcSource: Send + Sync {
        fn read(&self, path: &str) -> Result<Vec<u8>, Errno>;
        fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno>;
        /// MUST use raw getdents64, never libc readdir.
        fn list_dir_raw(&self, path: &str) -> Result<Vec<DirEnt>, Errno>;
        fn statx(&self, path: &str) -> Result<Statx, Errno>;
        fn open_ro(&self, path: &str) -> Result<OwnedFd, Errno>;
    }
    pub struct LiveProc;                 // real kernel
    pub struct FixtureProc { root: PathBuf }  // tests (12-testing.md §2)
}
```

**Every collector takes `&dyn ProcSource`.** This is the single most important architectural decision for testability: it is what makes it possible to unit-test "detect Diamorphine" without running Diamorphine.

### 2.2 `rustmite-analyze` — pure functions

No I/O. Input `&[u8]` / structs, output structs. Contains: Shannon entropy, sliding-window entropy, ELF parsing wrapper, packer heuristics, hash computation, `utmp` record parsing, `/etc/shadow` parsing, `authorized_keys` parsing, SSH key fingerprinting, `dpkg` md5sums parsing, RPM sqlite reading, cron parsing, systemd unit parsing. 100% unit-testable, 100% fuzzable.

### 2.3 `rustmite-collect` — collectors

One module per collector (see `06-detection-modules.md`). Uniform interface:

```rust
pub trait Collector {
    const ID: CollectorId;
    /// Cheap-to-run collectors may be scheduled in `pulse`.
    fn cost(&self) -> CollectorCost;   // Trivial | Low | Medium | High | Forensic
    fn required_caps(&self) -> Caps;   // e.g. CAP_SYS_PTRACE-ish needs, root-only reads
    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError>;
}

pub struct CollectCtx<'a> {
    pub proc: &'a dyn ProcSource,
    pub fs:   &'a dyn FsSource,
    pub plan: &'a CollectionPlan,     // scopes, depth limits, pre-filters
    pub budget: &'a Budget,            // deadline + byte/observation caps
    pub euid: u32,
}
```

`ObservationSink` writes NDJSON to stdout in the probe and to a `Vec` in tests. Collectors **never** buffer their whole output.

## 3. Dependency policy

### 3.1 Probe-side (strictly audited — every addition needs justification)

| Crate | Version line | Purpose | Notes |
|---|---|---|---|
| `rustix` | 1.x | raw syscalls | `default-features=false`, `features=["linux_raw","fs","process","net","mm","thread","event"]`. **Must not** enable `use-libc`. |
| `linux-raw-sys` | 0.9+ | constants/structs | transitive from rustix; use directly for `statx`, `bpf`, netlink structs |
| `serde` / `serde_json` | 1.x | wire format | `serde` with `derive`; consider `serde_json::to_writer` only (no `Value` in hot paths) |
| `sha2`, `sha1`, `md-5` | RustCrypto | hashes | `md-5`/`sha1` are for IOC-matching compatibility only, never for integrity |
| `blake3` | 1.x | fast baseline hashing | `default-features=false` to avoid `cc`; verify no C fallback is pulled in |
| `goblin` | 0.9+ | ELF parsing | `default-features=false, features=["elf32","elf64","endian_fd","alloc"]` |
| `zstd`-alternative: `ruzstd` (decode) + `zstd-safe`? | — | **Problem:** `zstd` crate is C. Use **`lz4_flex`** (pure Rust) for probe→node compression instead. | Decision recorded in §6 |
| `hex`, `base64` | — | encoding | |
| `smallvec`, `hashbrown` | — | allocation control | |
| `ed25519-dalek` | 2.x | *verification only* in the probe (verify the ScanRequest is from a legitimate node) | never holds a private key |
| `aho-corasick` | 1.x | multi-pattern IOC string matching | pure Rust |

Explicitly **banned** in the probe: `libc`, `nix`, `procfs` (the crate — it uses libc and is not hostile-input hardened), `openssl`, `ring` (contains assembly/C), `zstd`, `flate2` with `zlib` backend, anything with `build.rs` that compiles C.

### 3.2 Node / server side

| Crate | Purpose |
|---|---|
| `tokio` (full) | runtime |
| `russh` + `russh-keys` | **pure-Rust SSH2 client**. The key enabling dependency for "pure Rust". Verify supported KEX/ciphers cover legacy hosts (`04` §2.3) |
| `axum`, `tower`, `tower-http` | HTTP server |
| `rustls` + `tokio-rustls` + `rustls-pemfile` | TLS (pure Rust, no OpenSSL) |
| `sqlx` (postgres, runtime-tokio-rustls, macros, migrate) | DB, compile-time-checked queries |
| `serde`, `serde_json`, `toml` | config + wire |
| `clap` (derive) | CLI |
| `tracing`, `tracing-subscriber`, `tracing-opentelemetry` (opt) | logs |
| `metrics` + `metrics-exporter-prometheus` | metrics |
| `argon2`, `password-hash` | operator password storage |
| `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `zeroize`, `secrecy` | crypto + vault |
| `sha-crypt`, `md5-crypt`, `bcrypt`, `pbkdf2` | shadow-hash auditing (`06` §20) |
| `governor` | rate limiting |
| `uuid` (v4, v7) | IDs — prefer **v7** for time-sortable DB keys |
| `time` or `jiff` | timestamps (avoid `chrono` default features) |
| `jsonschema` | validating user-supplied check manifests |
| `notify` | hot-reload of check catalog in dev |
| `dashmap` | per-host scan guards |

### 3.3 Enforcement

`deny.toml` must include:
```toml
[bans]
multiple-versions = "warn"
deny = [
  { name = "openssl-sys" }, { name = "native-tls" },
  { name = "ring" },        # audit: contains C/asm; use rustls' aws-lc alternative only if pure-rust feature set is used
]
[licenses]
allow = ["MIT","Apache-2.0","BSD-3-Clause","BSD-2-Clause","ISC","Unicode-3.0","Zlib"]
```
Plus a custom `xtask check-pure` that runs `cargo tree -p rustmite-probe --target <t> --edges normal` and fails on any of: `libc`, `cc`, `*-sys`.

## 4. Build targets

`xtask build-probes` cross-compiles the matrix using `cargo-zigbuild`-free, pure-Rust linking where possible; otherwise `cross` with musl toolchains. Because the probe has no C dependencies, **`rust-lld` can link every target**, which is the preferred path — no C toolchain needed at all.

```toml
# .cargo/config.toml (excerpt)
[target.x86_64-unknown-linux-musl]
rustflags = ["-C","target-feature=+crt-static","-C","link-self-contained=yes","-C","linker=rust-lld"]
```

| Target triple | Covers | Priority |
|---|---|---|
| `x86_64-unknown-linux-musl` | modern servers/cloud | P0 |
| `aarch64-unknown-linux-musl` | ARM servers, Graviton, RPi 4/5, appliances | P0 |
| `armv7-unknown-linux-musleabihf` | embedded, RPi 2/3, routers | P1 |
| `arm-unknown-linux-musleabi` | ARMv6, older embedded | P2 |
| `i686-unknown-linux-musl` | legacy 32-bit x86 | P1 |
| `mips-unknown-linux-musl`* | routers/IoT (big-endian) | P2 (tier-3, may need `-Zbuild-std`) |
| `mipsel-unknown-linux-musl`* | routers/IoT (little-endian) | P2 |
| `mips64el-unknown-linux-muslabi64`* | networking gear | P3 |
| `riscv64gc-unknown-linux-musl` | emerging | P2 |
| `powerpc64le-unknown-linux-musl` | POWER servers | P3 |
| `s390x-unknown-linux-musl`* | mainframe Linux | P3 |

\* Tier-3 targets require `-Z build-std=std,panic_abort` on nightly or a pinned nightly in `rust-toolchain.toml` for the probe only. Isolate that in `xtask` so the rest of the workspace stays on stable.

### 4.1 Size optimisation (matters on 32 MB embedded hosts)

```toml
[profile.probe]
inherits = "release"
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
overflow-checks = true   # keep: correctness on hostile input beats 2% speed
```
Target: ≤ 3 MB for `armv7`, ≤ 6 MB for `x86_64`. Use `cargo-bloat` in CI and fail the build if the binary grows >15% in one commit.

### 4.2 Kernel compatibility classes

The probe must run on kernels from **2.6.32** upward. Implement a runtime capability probe rather than compile-time splits:

| Feature | Minimum kernel | Fallback |
|---|---|---|
| `memfd_create` | 3.17 | write to tmpfs + immediate `unlink` after exec |
| `statx` | 4.11 | `fstatat` (loses btime) |
| `sock_diag` netlink | 3.3 (inet_diag older) | `/proc/net/tcp` only (lose differential) |
| `bpf()` syscall | 3.18; `PROG_GET_NEXT_ID` 4.13 | skip eBPF collector, report `Unsupported` |
| `/proc/*/map_files` | 3.3 | skip |
| cgroup v2 `cgroup.procs` | 4.5 | cgroup v1 `tasks` |
| `getrandom` | 3.17 | `/dev/urandom` |

Every unsupported capability produces an explicit `CollectorReport { status: Unsupported, reason }` — **never a silent pass**. A "clean" result on a host where half the collectors silently skipped is the worst possible outcome.

## 5. Probe embedding

Probes are not fetched at runtime from the internet. `xtask` builds the matrix, compresses each with `lz4_flex`, and generates `crates/rustmite-node/src/probes/generated.rs`:

```rust
pub static PROBES: &[EmbeddedProbe] = &[
    EmbeddedProbe { arch: Arch::X86_64, sha256: hex!("…"),
                    version: env!("CARGO_PKG_VERSION"),
                    compressed: include_bytes!("x86_64.lz4"), uncompressed_len: 5_812_224 },
    // …
];
```

For nodes that must stay small, support an out-of-band probe directory (`--probe-dir`) with the same manifest + signature verification. Node verifies the SHA-256 **and** an ed25519 release signature before ever sending bytes to a host.

## 6. Recorded decisions (ADR summary)

| # | Decision | Rationale | Rejected alternative |
|---|---|---|---|
| ADR-1 | `rustix` linux_raw, no libc, in probe | LD_PRELOAD/libc-trojan immunity is a *detection* property | `nix`/`libc` (simpler, but hookable) |
| ADR-2 | Server-side check evaluation with probe-side pre-filters | Add checks without redeploying probes; enables retro-hunting | Probe-side rules engine (faster, but frozen at probe version) |
| ADR-3 | `russh` for SSH | Only mature pure-Rust SSH2 client | `libssh2` bindings (C) |
| ADR-4 | `lz4_flex` not `zstd` | `zstd` crate is a C binding; LZ4 is pure Rust and fast enough | `zstd` (better ratio) |
| ADR-5 | PostgreSQL, no message broker | `SELECT … FOR UPDATE SKIP LOCKED` is sufficient to 10k hosts and removes an operational component | RabbitMQ/NATS |
| ADR-6 | No probe-side private key / result signing | A key on a hostile host is not a secret; SSH channel is the authenticity boundary | Probe-signed results (false assurance) |
| ADR-7 | Nine check types mirroring Sandfly | Operator familiarity; the taxonomy is genuinely good | Flat check list |
| ADR-8 | `ProcSource` trait everywhere | Rootkit-detection logic must be testable without rootkits | Direct `std::fs` calls |
