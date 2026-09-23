# RustMite — Agentless Linux Intrusion Detection & Forensics Platform (Pure Rust)

**Document set version:** 1.0
**Target audience:** an autonomous coding agent (LLM) implementing the system from scratch.
**Language constraint:** 100% safe-by-default Rust. No Go, no C, no Python, no shell-out to system binaries for detection logic (see [`docs/00-overview.md` §Non-negotiable constraints](00-overview.md)).

---

## What this project is

RustMite is an **agentless** endpoint detection, forensics and drift-monitoring platform for Linux hosts — modelled on the capability set of [Sandfly Security](https://sandflysecurity.com/), including a native reimplementation of [`sandfly-processdecloak`](https://github.com/sandflysecurity/sandfly-processdecloak) and `sandfly-entropyscan`.

"Agentless" means: **nothing is installed on the monitored host.** For every scan, a scanner node connects over SSH, delivers a signed, statically-linked probe binary into volatile memory, executes it, streams structured JSON results back, and removes all trace of the probe. There is no daemon, no persistent service, no package, no kernel module on the target.

The system is designed for hosts where a conventional EDR agent is impossible or unwelcome: embedded devices, telecom equipment, appliances, medical/industrial systems, 10-year-old distributions, hardened cloud images, and anything under change control.

---

## How an implementing agent should use this document set

Read the documents in order. Each one is self-contained enough to be handed to a sub-agent as a work package, but they share vocabulary defined in `00-overview.md` and types defined in `07-data-model.md`.

| # | Document | Purpose |
|---|---|---|
| 00 | [`00-overview.md`](00-overview.md) | Product goals, threat model, trust boundaries, non-goals, glossary |
| 01 | [`01-architecture.md`](01-architecture.md) | Components, data flow, deployment topologies, failure modes |
| 02 | [`02-workspace-layout.md`](02-workspace-layout.md) | Cargo workspace, crate graph, dependency policy, build targets |
| 03 | [`03-probe-runtime.md`](03-probe-runtime.md) | The ephemeral probe: raw-syscall runtime, collectors, limits, output |
| 04 | [`04-ssh-transport.md`](04-ssh-transport.md) | SSH layer, two-stage memfd loader, arch detection, cleanup, credentials |
| 05 | [`05-check-engine.md`](05-check-engine.md) | Check manifest format, expression language, scheduling, targeting |
| 06 | [`06-detection-modules.md`](06-detection-modules.md) | **Core technical spec.** Every collector and detection algorithm |
| 07 | [`07-data-model.md`](07-data-model.md) | Wire types, JSON schemas, PostgreSQL schema, migrations |
| 08 | [`08-api.md`](08-api.md) | REST + WebSocket API, auth, RBAC, OpenAPI contract |
| 09 | [`09-response-actions.md`](09-response-actions.md) | Incident response actions and their safety interlocks |
| 10 | [`10-security-model.md`](10-security-model.md) | Credential vault, signing, least privilege, audit, supply chain |
| 11 | [`11-detection-catalog.md`](11-detection-catalog.md) | Starter catalog of 120 concrete checks with ATT&CK mapping |
| 12 | [`12-testing.md`](12-testing.md) | Fixture model, rootkit lab, QEMU matrix, fuzzing, CI |
| 13 | [`13-roadmap.md`](13-roadmap.md) | Milestones M0–M8 with acceptance criteria |
| 14 | [`14-implementation-guide.md`](14-implementation-guide.md) | Coding conventions, definition of done, ordering, pitfalls |
| 15 | [`15-how-it-works.md`](15-how-it-works.md) | **Start here for intuition** — diagrams of scan flow, memfd delivery, collectors → findings |
| 16 | [`16-operator-console.md`](16-operator-console.md) | Embedded web console: findings, hosts, RPL Hunt, checks |
| 17 | [`17-rpl-clickhouse-noise.md`](17-rpl-clickhouse-noise.md) | RPL hunting APIs, ClickHouse index, Noise XX transport |
| 18 | [`18-all-detections.md`](18-all-detections.md) | **Complete check catalog** generated from `checks/*.toml` |

### Suggested build order

```
M0 rustmite-proto + rustmite-sys        (types, raw syscalls)
M1 rustmite-probe minimal              (process decloak + entropy, JSON to stdout)
M2 rustmite-transport                  (SSH + two-stage loader)
M3 rustmite-node                       (job execution, result normalisation)
M4 rustmite-server + Postgres          (jobs, findings, API)
M5 full collector set                 (docs/06 modules 5–18)
M6 check engine + catalog             (docs/05, docs/11)
M7 drift, SSH key graph, pw audit     (docs/06 modules 19–22)
M8 response actions + hardening       (docs/09, docs/10)
```

Do not start M1 before the fixture harness in [`12-testing.md` §2](12-testing.md) exists. Every collector in this spec is testable against a recorded `/proc` tree, and collectors written without that harness are unverifiable.

---

## Prime directive for the detection logic

> **RustMite does not try to determine the truth about a compromised host. It determines whether the host is telling a consistent story.**

A kernel-mode rootkit can lie to any userland process, including the probe. Every detection module in `06-detection-modules.md` is therefore built as a **differential**: gather the same fact from two or more independent kernel interfaces that a rootkit author must remember to hook in the same way, and report the disagreement. Disagreement is signal; agreement is merely the absence of that particular signal.

This principle is why, for example, hidden-process detection reads `/proc` via `getdents64`, probes PIDs via `sched_getscheduler`, cross-references `/proc/sched_debug`, walks cgroup `cgroup.procs`, and diffs socket inodes from `sock_diag` netlink against `/proc/net/tcp` — five sources, one question.

---

## Attribution and licensing note for the implementer

RustMite is a **clean-room functional equivalent**, not a port. Do not copy source code from Sandfly Security's repositories, which are published under their own terms. Behaviour, output field names and algorithm descriptions in this document set were derived from public documentation and from first principles about the Linux kernel interfaces involved. Implement from this specification and from kernel documentation (`man 5 proc`, `man 2 …`, `Documentation/filesystems/proc.rst`), not from third-party source.

Recommended licence for the resulting project: Apache-2.0 OR MIT (Rust ecosystem default). The detection catalog in `11-detection-catalog.md` is original to this spec.

---

## Sources consulted for the capability baseline

- [Sandfly Security — product overview](https://sandflysecurity.com/)
- [Sandfly documentation — sandfly types](https://docs.sandflysecurity.com/docs/sandfly-types)
- [Sandfly documentation — getting started](https://docs.sandflysecurity.com/docs/getting-started)
- [sandfly-processdecloak (GitHub)](https://github.com/sandflysecurity/sandfly-processdecloak)
- [Linux Stealth Rootkit Process Decloaking Tool — sandfly-processdecloak](https://sandflysecurity.com/blog/linux-stealth-rootkit-process-decloaking-tool-sandfly-processdecloak)
- [sandfly-entropyscan (mirror)](https://github.com/timb-machine-mirrors/sandflysecurity-sandfly-entropyscan)
- [unhide(8) manual page](https://manpages.ubuntu.com/manpages/jammy/man8/unhide.8.html)
- [SANS Internet Storm Center — Sandfly Security review](https://isc.sans.edu/diary/29998)
- [The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools (ACM DTRAP)](https://dl.acm.org/doi/full/10.1145/3688808)
