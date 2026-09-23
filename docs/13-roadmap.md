# 13 — Roadmap & Milestones

Each milestone has a demoable outcome and hard acceptance criteria. Do not advance until the current milestone's criteria pass in CI.

## M0 — Foundations (`rustmite-proto`, `rustmite-sys`)
**Build:** wire types (`07` §2–3) as `no_std+alloc`; `PathBytes`; `rustix` linux_raw wrappers + `ProcSource`/`FsSource` traits with `Live` and `Fixture` impls; the fixture harness (`12` §2).
**Accept:**
- `xtask check-pure` passes for a stub `rustmite-probe` (no libc/cc/*-sys).
- Round-trip serde tests for every wire type.
- `FixtureProc` serves a recorded clean tree; a trivial collector reads it.
- Fuzz targets for `/proc/stat` and `Envelope` build and run.

## M1 — Minimal probe (decloak + entropy)
**Build:** `rustmite-probe` `main` (`03` §2), `self_protect`, budget/deadline, NDJSON output; collectors `decloak.process` (`06` §2) and `entropy`+`file.elf` (`06` §5); `Hello` capability detection.
**Accept:**
- Static binary for x86_64-musl + aarch64-musl; RSS < 24 MiB on the largest fixture; zero filesystem writes asserted.
- `decloak.process` fires on `diamorphine-hidden-pid` fixture with confidence high; silent on 3 clean fixtures.
- entropy: UPX-packed sample >7.7; native binary <6.5; `-elf`-style gating works.
- Panic-free lints enforced; fuzzers green.

## M2 — Transport & delivery
**Build:** `rustmite-transport` with `russh`; host-key pinning; two-stage `memfd` loader (`04` §4); delivery-method fallback A→D; bounded result reader; `rustmite-loader` stage0.
**Accept:**
- Probe delivered and run via Method A on modern OpenSSH; Method B on `noexec /tmp`; Method D degrade path produces `RM-POL-0021`.
- SSH transport matrix (`12` §6) green, including Dropbear and no-`base64`.
- Host-key change → scan refused + `RM-POL-0001`.
- No fd/session leaks under chaos tests.

## M3 — Node
**Build:** `rustmite-node` daemon; lease loop; per-host serialisation; result normalisation + node signing; delivery reports; metrics/tracing.
**Accept:**
- Node scans 200 simulated hosts concurrently; memory flat; capacity accounting correct.
- Hostile-stream ingest (`07` §6) survives giant/malformed input without OOM/panic.

## M4 — Server + storage + API core
**Build:** `rustmite-server`, `rustmite-store` (Postgres + migrations), scheduler (`SKIP LOCKED`), findings pipeline, minimal REST (`hosts`, `scans`, `findings`), auth/RBAC, one sink (webhook/syslog).
**Accept:**
- End-to-end: schedule → node → probe → observations stored → findings → webhook alert.
- Coverage endpoint reports applicable/na/pass/fired.
- `HostKeyChanged`/`ProbeCrashed` produce first-class failure findings, not silent retries.

## M5 — Full collector set
**Build:** collectors `06` §3,4,6,7,8,9,10,11,12,15,16,17,18,22 (process inventory, sockets+decloak, modules, ebpf, preload, scheduled, services, accounts, logs, sessions, container, mounts, recon).
**Accept:**
- Each collector: hostile fixture fires, ≥3 clean fixtures silent, parser fuzzed, golden output committed.
- Rootkit lab (`12` §5) fires expected checks for Diamorphine, Reptile, an LD_PRELOAD kit, and an eBPF hider.

## M6 — Check engine + catalog + hunting
**Build:** `rustmite-expr` (parser/typer/evaluator, total+sandboxed), `rustmite-checks` (manifest load, compile, plan, evaluate), catalog `11` as data, check compilation → collection plans + pre-filters, `/v1/hunt`, allowlists/suppression, correlation/incidents.
**Accept:**
- All ~120 seed checks pass their +/− fixture tests.
- Compiler produces minimal collection plans (a `/etc`-only check set does not trigger a full-FS walk).
- Retro-hunt over stored observations returns expected hits; expression fuzzer green (total, bounded).
- Adding a check file changes behaviour at next sweep with no probe rebuild.

## M7 — Drift, SSH-key graph, credential audit, baselines
**Build:** `06` §13,14,19,20,21; signed baselines + diff engine; SSH key placement graph + cross-host correlation; shadow-hash posture audit (+ opt-in bounded offline audit, gated); package-DB verification (dpkg; rpm best-effort).
**Accept:**
- Baseline capture → introduce a change → drift finding tied to the object; package-attributable change auto-downgraded.
- Trojaned-`ls` fixture → `RM-FILE-0004`.
- Cross-host reused key → `RM-USER-0008`/`RM-INC-0004`.
- Shadow hashes never persisted in cleartext (asserted); cracking path elevated-role + audited.

## M8 — Response actions + hardening + productionisation
**Build:** `Respond` probe mode (feature-gated), `ActionGrant` flow (`09`), rollback, kill-switch; vault + KMS (`10` §3); mTLS node channel; hash-chained audit log; full sink set; WebSocket stream; OpenAPI; SBOM + reproducible probe builds; HA topology; standalone `rustmite-cli`.
**Accept:**
- Scan-only build compiles with no write code paths (feature check in CI); `RLIMIT_FSIZE=0` verified.
- Destructive action requires signed single-use grant + two-person; target re-verified at execution; rollback works; every action in tamper-evident audit log.
- `cargo-deny`, pure-Rust gate, size budgets, MSRV, full cross-compile matrix all green in release CI.
- Standalone `rustmite-cli scan` runs the full flow against one host with only a config file.

## Post-1.0 backlog
- YARA-X server-side scanning of returned high-entropy files.
- Container-per-namespace deep scans.
- ML/anomaly layer over recon inventory (per-host and per-segment baselining).
- macOS/BSD probe (large effort; separate `ProcSource`-equivalent).
- STIX/TAXII IOC sync; ATT&CK Navigator export.
- Web console UI (separate frontend; API is UI-ready from M4).
- **Auditd / Elastic-Defend-style LPE sequences.** Snapshot checks cover SUID/GTFOBins posture and live elevation aftermath (`RM-PROC-0015`–`0019`, `RM-FILE-0006`/`0015`). Full Elastic [Linux LPE detection framework](https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework) parity (exec→`uid_change`→confirm, `unshare`→root, descendant-of) needs continuous process-event ingest (auditd/eBPF) + sequence correlation — not expressible from SSH pulse scans alone.
