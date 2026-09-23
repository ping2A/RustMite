# 14 — Implementation Guide for the LLM

Read this last, keep it open while coding. It encodes the conventions and the traps that will otherwise cost days.

## 1. Conventions
- **Edition 2021+, resolver 2.** Pin the toolchain in `rust-toolchain.toml`. The probe's tier-3 targets may need a pinned nightly *isolated to `xtask build-probes`*; the rest of the workspace stays on stable.
- **Error handling:** `thiserror` for library error enums; `anyhow` only in binaries/`xtask`, never in `rustmite-proto/sys/collect/analyze/probe`.
- **No `unsafe`** except in `rustmite-sys` (raw syscalls, unavoidable) and, if ever, tightly-reviewed hot paths. Every `unsafe` block carries a `// SAFETY:` comment. Deny `unsafe` in all other crates via `#![forbid(unsafe_code)]`.
- **Panic-free crates:** `rustmite-probe`, `rustmite-collect`, `rustmite-analyze`, `rustmite-sys` set `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::integer_arithmetic, clippy::unreachable)]`. Use `get()`, `checked_*`, `?`.
- **Time:** `time`/`jiff`, UTC internally, RFC3339 on the wire. Never `chrono` with default features.
- **IDs:** UUIDv7 for DB keys (time-sortable), v4 where sortability is irrelevant.
- **Logging:** `tracing` only; never `println!` in library/daemon code (the probe uses stdout for data — a stray `println!` corrupts the NDJSON stream; this is a real footgun — route probe diagnostics to stderr only).

## 2. The traps (each has bitten a real implementation)

1. **`/proc/<pid>/stat` `comm` parsing.** Field 2 is wrapped in `()`, may contain spaces, `)`, and even newlines. Parse by locating the **last** `)` in the buffer, take fields 1..that as pid, `comm` = between first `(` and last `)`, split the rest by spaces. Naive `split_whitespace().nth(n)` is wrong and evadable. Fuzz this. (`03` §7.4)
2. **Using libc/`std::fs::read_dir` in the probe.** `std::fs::read_dir` → `getdents` under the hood but via libc; more importantly other crates' `readdir` can be `LD_PRELOAD`-hooked. Use raw `getdents64` through `rustix` for `/proc` enumeration. This is the entire point of ADR-1. Guard it with `xtask check-pure`.
3. **PID-reuse races in decloak.** Always double-pass and validate `starttime`. A single-pass diff produces false hidden-PIDs on any busy host and will destroy operator trust. (`06` §2.3)
4. **Silent skips.** Every collector that can't run must emit `Unsupported`/`NotApplicable` with a reason. A "clean" scan where half the collectors silently no-op'd is the worst outcome. The server must treat coverage as a first-class metric. (`05` §6)
5. **`serde_json::Value` on the ingest hot path.** Parse into typed structs; `Value` on a 2M-observation stream blows memory and loses type safety on hostile input. Stream line-by-line. (`07` §6)
6. **Numbers > 2^53 in JSON.** Inodes, byte counts, some timestamps. Serialise as strings. Test with real large inode numbers.
7. **Paths are bytes.** Do not assume UTF-8 anywhere near the filesystem. Rootkits use invalid-UTF-8 names deliberately. `PathBytes` everywhere; validate UTF-8 only at the display boundary.
8. **Opening `/proc/<pid>/fd/*` targets or file-sweep entries.** `statx` first; never `open` a path that could be a FIFO/device (blocks forever) — use `O_NOFOLLOW|O_NONBLOCK|O_PATH`. (`03` §7.5–6)
9. **`zstd`/`flate2(zlib)`/`openssl`/`ring` sneaking in as C deps.** They pull C. Use `lz4_flex`, `rustls`, RustCrypto. The `deny.toml` + pure-Rust gate must run in CI, not just be documented.
10. **Probe stdout pollution.** Any `dbg!`/`println!`/library that writes to stdout corrupts the result stream. Isolate: the probe writes data to fd 1 exclusively via one `ObservationSink`; everything else goes to fd 2.
11. **`rusqlite` for rpm DB.** It bundles SQLite C. Either parse the rpm DB format directly, use a pure-Rust sqlite reader, or mark rpm verification `Unsupported`. Do not silently break the pure-Rust guarantee for one collector. (`06` §13)
12. **Regex ReDoS.** Use the `regex` crate (linear-time, no backtracking); cap compiled program size; never build a regex from unbounded attacker input without a size limit. (`05` §4.5)
13. **Blocking the async reactor with check evaluation or hashing.** CPU-bound work → `rayon`/`spawn_blocking`, never on Tokio worker threads.
14. **Forwarding the SSH agent** to a monitored host. Never. (`04` §2.2)
15. **Trusting probe-side signatures for authenticity.** The authenticity boundary is the SSH channel + node signature. A key in a dropped binary is not a secret. (ADR-6, `10` §4)

## 3. Ordering within a milestone
For any collector: (1) define its observation variant in `rustmite-proto`; (2) write the hostile synthetic fixture + clean fixtures; (3) implement against `ProcSource`; (4) golden-output test; (5) write the check manifest(s) with +/− fixtures; (6) fuzz its parser; (7) lab assertion if it targets a rootkit technique. Never implement a collector before its fixtures exist (you cannot verify it otherwise).

## 4. Definition of Done (per PR)
- `cargo test` (unit + fixture + check-manifest) green.
- `cargo clippy -D warnings` with the panic-free set on probe crates.
- `xtask check-pure` green for every probe target touched.
- `cargo-deny check` green.
- New parser → new fuzz target. New check → +/− fixtures. New collector → golden output.
- No `println!`/`dbg!` in probe/daemon code. No new `unsafe` outside `rustmite-sys` without SAFETY review.
- Size budget respected (probe binaries).
- Docs: if behaviour diverges from this spec, update the relevant `docs/NN-*.md` in the same PR — the spec is the source of truth for the next agent.

## 5. How to hand work to sub-agents
Each `docs/NN-*.md` is a self-contained work package. Good decompositions:
- Agent A: M0 (`rustmite-proto` + `rustmite-sys` + fixture harness) — unblocks everyone.
- Agent B: probe runtime shell (`03`) once M0 exists.
- Agent C: each collector in `06` (parallelisable *after* the fixture harness and its proto types exist).
- Agent D: transport (`04`) — independent of collectors.
- Agent E: server/store/API (`07`,`08`) — depends only on proto types.
- Agent F: check engine (`05`) — depends on proto + observation variants.
Shared contract for all: the wire types in `07` and the `ProcSource` trait in `02` §2.1. Freeze those first; churn there ripples everywhere.

## 6. Minimal first vertical slice (prove the concept in a week)
`rustmite-cli scan --host H` that: SSHes (russh, pinned key) → Method-A memfd-delivers a probe running only `decloak.process` + `entropy` → streams NDJSON back → evaluates 5 checks (RM-PROC-0001, -0004, -0005, RM-FILE-0002, RM-KERN-0001) locally → prints findings. This exercises every architectural seam (transport, probe, differential detection, check eval) against the diamorphine lab VM. Get this green, then widen.

## 7. What "good" looks like at 1.0
- A single static probe per arch, no libc, delivered to memory, gone in seconds, that catches Diamorphine/Reptile/LD_PRELOAD/eBPF hiders by *disagreement between kernel interfaces*, with graded confidence and honest coverage accounting — and never panics, never writes, never lies about what it couldn't check.
- A server that lets an analyst add a check as a text file and retro-hunt it across a month of history without touching a single host.
- An operator who can say to their auditor: *"the scanner is provably incapable of modifying our hosts, leaves a login record every time, and here is the tamper-evident log of everything it ever did."*
