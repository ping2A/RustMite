# 00 — Overview, Threat Model and Constraints

## 1. Problem statement

Linux workloads that matter most are frequently the ones that cannot run an EDR agent:

- **Embedded / appliance / telecom**: no package manager, read-only rootfs, 32 MB RAM, vendor support voided by third-party software.
- **Legacy**: CentOS 6, Ubuntu 14.04, kernels 2.6/3.x where modern agents do not build.
- **Change-controlled**: financial, medical, industrial systems where installing a daemon requires a six-month approval cycle.
- **Ephemeral cloud**: containers and short-lived instances where agent install/registration overhead exceeds instance lifetime.

Meanwhile the Linux threat landscape is dominated by techniques that are *invisible to the host's own tooling*: LKM and eBPF rootkits that hide PIDs, ports, files and modules; `LD_PRELOAD` userland rootkits that hook `readdir`; fileless execution via `memfd_create`; deleted-binary processes; SSH-key-based lateral movement; log wiping.

RustMite addresses both halves: **zero-install access** plus **detection that does not trust the host's own view of itself**.

## 2. Product goals

| Goal | Concretely |
|---|---|
| G1 Agentless | No persistent artefact on the target. Probe lives in tmpfs/anonymous memory for the duration of a scan only. |
| G2 Portable | One static binary per architecture. Targets: x86_64, aarch64, armv7, armv5te, i686, mips, mipsel, mips64, riscv64, ppc64le. No libc dependency at runtime. |
| G3 Non-intrusive | Probe must be schedulable at low priority, bounded in memory and CPU, killable, and safe on a 2.6.32 kernel with 64 MB RAM. |
| G4 Differential detection | Every hiding-related check compares ≥2 independent kernel interfaces. |
| G5 Forensic output | Findings carry full evidence (hashes, paths, timestamps, raw field values) sufficient for IR without a second visit. |
| G6 Drift & posture | Per-host baselines, file integrity, package verification, configuration policy checks. |
| G7 Identity hygiene | SSH key inventory and cross-host correlation; credential hash auditing. |
| G8 Response | Optional, explicitly authorised containment actions (kill, quarantine, key revocation). |
| G9 Scale | A single node handles ≥200 concurrent host scans; the platform scales by adding nodes. |

## 3. Non-goals

- **Not** a real-time/continuous kernel-level monitor. RustMite is a *point-in-time, high-frequency poller*. If you need continuous syscall telemetry, that requires an agent; say so rather than faking it.
- **Not** an antivirus. There is no signature-scanning engine over file content beyond hashes, entropy, ELF structure and YARA-optional (see `06` §14).
- **Not** a vulnerability scanner. Package CVE matching is explicitly out of scope for v1.
- **Not** a Windows/macOS product.
- **Not** a replacement for the host's own audit trail. RustMite deliberately leaves an SSH login record; see `10-security-model.md` §6.

## 4. Non-negotiable constraints

1. **Pure Rust.** All crates in the dependency graph must be Rust source. `cc`-building crates are forbidden in `rustmite-probe` and `rustmite-sys`; they are discouraged elsewhere. Verify with `cargo tree` + a CI deny-list (`12-testing.md` §7).
2. **No libc in the probe.** The probe makes raw `syscall` instructions via `rustix` with the `linux_raw` backend (`default-features = false, features = ["linux_raw", ...]`). Rationale: immunity to `LD_PRELOAD`/`ld.so.preload` userland rootkits and to a trojaned `libc.so`. This is a *detection* requirement, not a portability preference.
3. **No shelling out.** The probe must never execute `ps`, `ls`, `netstat`, `lsmod`, `find`, `stat`, `md5sum`, or any host binary. Those binaries are exactly what an attacker replaces. Every fact comes from a syscall or a `/proc`/`/sys` read done by the probe itself.
4. **Single static binary.** `x86_64-unknown-linux-musl` style targets with `-C target-feature=+crt-static`. No dynamic loader, no `.so` dependency, no `/lib` requirement.
5. **Bounded footprint.** Probe: ≤ 24 MB RSS default cap, ≤ 60 s default wall clock, `SCHED_IDLE`/`nice 19` and `ionice idle` self-configuration, `RLIMIT_AS` self-imposed.
6. **Read-only by default.** The probe performs no writes to the target filesystem in scan mode. Response actions are a separate, separately-authorised binary mode (`09-response-actions.md`).
7. **Deterministic output.** Same host state → same JSON (modulo timestamps). Stable field ordering, stable check IDs.

## 5. Trust model

### 5.1 Trust boundaries

```
┌──────────────┐  TLS 1.3 + mTLS   ┌────────────┐  SSH2 (ed25519)  ┌──────────────┐
│ rustmite-     │◄─────────────────►│ rustmite-   │◄────────────────►│ monitored    │
│ server       │                   │ node       │                  │ host         │
│ (trusted)    │                   │ (trusted)  │                  │ (UNTRUSTED)  │
└──────────────┘                   └────────────┘                  └──────────────┘
       │                                  │
       │ Postgres (trusted)               │ credential vault (sealed)
```

The monitored host is **always** treated as potentially adversarial. Concretely:

- **Probe output is untrusted input.** It is parsed with strict, size-bounded, non-panicking deserialisation. A malicious host may return 4 GB of JSON, 10⁶ findings, embedded ANSI escapes, path traversal, invalid UTF-8, or deeply nested structures. See `07-data-model.md` §6 (Hardened ingest).
- **Probe-side signing is security theatre and must not be implemented.** Any key inside a binary dropped on an attacker's machine is an attacker's key. Authenticity comes from the SSH channel: the node knows it spoke to *that host key* over an encrypted, integrity-protected channel. The **node** then signs the normalised result for the server (`10-security-model.md` §4).
- **A kernel rootkit can defeat any userland probe.** The spec's answer is differential detection (Prime Directive, `README.md`) plus explicit "confidence" grading on findings (`07-data-model.md` §3.4).

### 5.2 What the platform protects

| Asset | Protection |
|---|---|
| SSH credentials for fleet | Sealed vault, per-host keys, no plaintext at rest, memory zeroization (`zeroize`) |
| Scan results | Signed node→server, TLS in transit, RLS/row-scoped in DB |
| The node itself | Runs unprivileged; probe output never executed, never shell-interpolated |
| The fleet | RustMite is a high-value lateral-movement target by design. See `10-security-model.md` §2 for the required hardening posture. |

### 5.3 Explicit residual risks (document these in the product README)

1. A kernel rootkit that hooks *every* interface consistently is undetectable by RustMite.
2. A host that blocks the SSH login, or an attacker who notices and kills the probe, converts detection into a **scan failure** — failures must therefore be alertable first-class events, not silently retried (`01-architecture.md` §7).
3. SSH credentials with `root` on the fleet are a crown-jewel; `10` §2 requires per-host key separation and optional restricted-command / sudo-scoped accounts.

## 6. Feature parity map vs. Sandfly

| Sandfly capability | RustMite equivalent | Spec location |
|---|---|---|
| Agentless SSH-delivered scanning | Two-stage `memfd` probe loader | `04` |
| "Sandfly" module types (process/file/user/directory/log/policy/incident/recon/custom) | `CheckType` enum, identical nine types | `05` §2 |
| 1100+ checks | Catalog of 120 seed checks + expression engine for user-defined checks | `11`, `05` §4 |
| `sandfly-processdecloak` | `decloak` collector, 6 independent PID sources | `06` §2 |
| `sandfly-entropyscan` | `entropy` collector + ELF/packer analysis | `06` §5 |
| SSH key monitoring / stolen-key detection | Key inventory + cross-host fingerprint correlation graph | `06` §19 |
| Password auditing | `/etc/shadow` hash audit + optional offline wordlist test | `06` §20 |
| Drift detection | Per-host signed baseline + diff engine + package DB verification | `06` §21 |
| Incident response | `rustmite-probe --mode respond` with interlocks | `09` |
| Recon modules (passive inventory for ML/SIEM) | `recon` check type, full host inventory to SIEM sink | `06` §22, `08` §7 |
| Server/node architecture, dockerised | `rustmite-server` + `rustmite-node`, containerised | `01` |
| JSON export, API | REST + WS + NDJSON export | `08` |

## 7. Glossary

| Term | Meaning |
|---|---|
| **Host** | A monitored Linux system, identified by a stable `host_id` (UUID) plus SSH host-key fingerprint. |
| **Node** | A `rustmite-node` worker process that owns SSH connectivity to a set of hosts. |
| **Probe** | The static binary executed on the host for the duration of one scan. |
| **Collector** | A probe-side unit that gathers one category of facts (processes, sockets, modules…). Produces `Observation`s. |
| **Check** | A server-defined rule evaluated over observations; the analogue of a "sandfly". Produces `Finding`s. |
| **Observation** | Raw structured fact from a collector. Not a verdict. |
| **Finding** | A check that fired: verdict + severity + evidence. |
| **Alert** | A finding (or correlated group) that crossed notification policy. |
| **Baseline** | A stored, signed snapshot of a host's file/config state used for drift diffing. |
| **Sweep** | One scheduled execution of a check set across a host group. |
| **Decloak** | Detection of entities hidden from the host's normal enumeration interfaces. |
