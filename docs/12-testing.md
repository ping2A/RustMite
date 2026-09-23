# 12 — Testing, Fixtures and the Rootkit Lab

A detection product is only as trustworthy as its test suite. The central idea (`02` §2.1): because every collector reads through `ProcSource`/`FsSource`, we can test rootkit detection **without running rootkits**, by replaying recorded/synthetic `/proc` and `/sys` trees. Then we validate against *real* rootkits in an isolated lab.

## 1. Test pyramid

```
        ┌─────────────────────────┐
        │  Rootkit lab (QEMU VMs)  │   real Diamorphine/Reptile/bpf rootkits  (few, slow, gated)
        ├─────────────────────────┤
        │  E2E: sshd matrix        │   probe delivery on real SSH servers      (containers)
        ├─────────────────────────┤
        │  Golden fixture replay   │   full collector set vs recorded trees     (many, fast)
        ├─────────────────────────┤
        │  Check-manifest tests    │   each check: +fixture fires, −fixture doesn't
        ├─────────────────────────┤
        │  Unit + property + fuzz  │   parsers, entropy, ELF, utmp, expr engine (thousands)
        └─────────────────────────┘
```

## 2. Fixture model (`fixtures/`)

A fixture is a directory tree that `FixtureProc`/`FixtureFs` serve as if it were `/`:

```
fixtures/
  clean-ubuntu2204/
    proc/{1,842,...}/{stat,status,maps,cmdline,cgroup,...}
    proc/{modules,net/tcp,net/tcp6,net/unix,sys/kernel/pid_max,...}
    sys/module/*/...
    etc/{passwd,shadow,ld.so.preload,crontab,...}
    manifest.toml        # metadata: kernel class, caps present, expected outcomes
    golden.ndjson        # expected collector output (03 §9)
  diamorphine-hidden-pid/     # synthetic: a PID present via syscall-source but absent from proc listing
  reptile-magic-dir/          # dir link-count mismatch + hidden file referenced by exe
  hidden-port-bpfdoor/        # sock_diag has a listener /proc/net/tcp omits
  trojaned-ls/                # dpkg md5sum mismatch
  memfd-exec/                 # exe symlink -> /memfd:...
  timestomp/                  # statx btime>mtime
  ...
```

### 2.1 Synthetic hostile fixtures
For decloak tests, `FixtureProc` supports **two views** that intentionally disagree:
- a "listing" view (`list_dir_raw("/proc")`) that omits the hidden PID (models the rootkit hook), and
- a "syscall" view where `sched_getscheduler(hidden_pid)` returns Ok (models the still-scheduled task).
This lets the decloak collector produce a `HiddenProcess` observation deterministically, in a unit test, with no kernel module. Every rootkit *technique* gets such a fixture, independent of any specific rootkit binary.

### 2.2 Recording real trees
An `xtask record` helper snapshots a live (clean) host's `/proc`/`/sys`/relevant `/etc` into a fixture (secrets scrubbed) to build realistic negative fixtures across distros/kernels.

## 3. Check-manifest tests
Every check in the catalog (`11`) declares fixtures:
```toml
[test]
fires_on = ["diamorphine-hidden-pid"]
silent_on = ["clean-ubuntu2204","clean-centos7","clean-embedded-armv7"]
```
CI asserts: the check fires on each positive fixture, and does **not** fire on any negative fixture. A new check without both is rejected. A change that makes a check fire on a clean fixture (false positive) fails CI.

## 4. Property & fuzz testing (`proptest` + `cargo-fuzz`)
Mandatory fuzz targets (attacker-controlled inputs):
- `/proc/<pid>/stat` parser — especially the `comm`/`)` edge cases (`03` §7.4). Property: never panics; correctly extracts fields for any `comm` containing `)`, spaces, newlines.
- `/proc/<pid>/maps`, `status`, `cgroup`.
- ELF header parser (goblin wrapper) on random/truncated bytes.
- `utmp`/`wtmp` record parser.
- `/etc/shadow`, `authorized_keys`, sshd_config, crontab, systemd unit parsers.
- `ScanRequest` and `Envelope` deserialisers.
- The expression-engine parser and evaluator (must be total; property: bounded steps, no panic, no infinite loop).
- The node's bounded NDJSON reader against giant/inf/malformed streams.

Property tests: entropy(all-same-byte)==0, entropy(uniform random)≈8, entropy monotonicity on mixing; hash round-trips; path bytes round-trip through serde for arbitrary `Vec<u8>`.

## 5. Rootkit lab (gated, real malware)

Isolated, **offline** QEMU/KVM VMs, snapshotted, no network egress. Automated by `xtask lab`:
- Deploy each rootkit into a VM snapshot: **Diamorphine**, **Reptile**, **beurk**/**vlany** (LD_PRELOAD), an **eBPF** hiding PoC (TripleCross/bpfdoor-style), a custom "hidden port" module.
- Run the full RustMite probe against the VM over SSH.
- Assert: the corresponding RM-* checks fire, with expected confidence; clean snapshots stay silent.
- Record probe footprint (RSS, duration) to catch regressions.

Safety: the lab is a separate repo/CI lane, requires explicit opt-in, runs only in a sandboxed runner, never on developer machines by default, and stores no live malware in the main repo (fetch-at-test from a controlled internal mirror).

## 6. SSH transport matrix (E2E, containers)
Docker-compose matrix (`04` §9): OpenSSH old+new, Dropbear, `noexec /tmp`, SFTP-only, `rbash`/`ForceCommand`, no-`base64`, big-endian (via `qemu-user`), memfd-blocked (seccomp). Assert correct delivery-method selection, cleanup, and `ScanOutcome`. Chaos tests: kill probe mid-stream, drop TCP, rotate host key.

**Current harness (M2):** `docker/ssh-matrix/` + `cargo xtask ssh-matrix {up,test,down}`.
- `openssh-modern` (:2222) — Method A (`memfd` via stage-0 loader).
- `openssh-noexec-tmp` (:2223) — `/tmp` noexec; Method B via `/run/rustmite-exec`.
- Host-key mismatch → exit 2 / `RM-POL-0001` refusal.

## 7. Pure-Rust & footprint gates (CI)
- `xtask check-pure`: `cargo tree -p rustmite-probe --target <each>` must contain **no** `libc`, `cc`, `*-sys`. Fail otherwise.
- `cargo-deny check` (licences, advisories, bans).
- `cargo-bloat`/size budget per probe target; fail on >15% growth.
- `clippy -D warnings` with the panic-free lint set (`03` §6) on probe crates.
- MSRV build; the full cross-compile matrix builds in CI.
- `cargo-fuzz` smoke run (short) per PR; long fuzz nightly.

## 8. Performance & scale tests
- Node soak: 200+ concurrent simulated hosts (fake SSH servers streaming recorded golden output) → assert capacity, memory flat, no fd leaks.
- Server: ingest N million observations; check evaluator throughput (findings/sec); `SKIP LOCKED` dispatch under contention.
- Large-host test: a 2M-inode fixture → assert probe stays under RSS cap and completes or `Truncated` cleanly.

## 9. Determinism / golden tests
Full-collector replay against every fixture must produce byte-identical `golden.ndjson` (modulo timestamp/nonce fields, which are normalised out by the harness). Golden files are the primary regression net; updating one requires an explicit reviewed change.

## 10. Definition of "tested" for a collector
A collector is not "done" until it has: (a) ≥1 hostile synthetic fixture proving detection, (b) ≥3 clean fixtures across distros proving no FP, (c) a fuzz target for each parser it uses, (d) a golden output, and (e) at least one real-rootkit lab assertion if it targets a rootkit technique.
