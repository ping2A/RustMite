# 15 — How RustMite Works (Technical Overview)

This document is a visual walkthrough of the running system. For deep specs see
[`01-architecture.md`](01-architecture.md), [`03-probe-runtime.md`](03-probe-runtime.md),
[`04-ssh-transport.md`](04-ssh-transport.md), and [`05-check-engine.md`](05-check-engine.md).

---

## 1. One-sentence model

**Nothing stays on the host.** A trusted node opens SSH, drops a signed static probe into
anonymous memory, the probe streams raw facts (`Observation`s) back, the server turns those
facts into verdicts (`Finding`s), then the probe exits and leaves no filesystem footprint.

---

## 2. Big picture

```mermaid
flowchart LR
  subgraph Control["Trusted control plane"]
    CLI["rustmite-cli"]
    SRV["rustmite-server<br/>scheduler · checks · API"]
    DB[(PostgreSQL)]
    SINK["Alert sinks<br/>webhook / syslog / NDJSON"]
    CLI --> SRV
    SRV <--> DB
    SRV --> SINK
  end

  subgraph Data["Trusted data plane"]
    NODE["rustmite-node<br/>SSH pool · probe cache · signing"]
  end

  subgraph Target["Untrusted host"]
    SSH["sshd"]
    MEM["memfd probe<br/>rustmite-probe"]
    PROC["/proc · /sys · FS<br/>raw syscalls"]
    SSH --> MEM
    MEM --> PROC
  end

  SRV <-->|"mTLS lease / results"| NODE
  NODE <-->|"SSH2 + host-key pin"| SSH
  MEM -.->|"NDJSON observations"| NODE
```

| Layer | Trust | Job |
|---|---|---|
| Server + DB | Trusted | Schedule, evaluate checks, store, alert |
| Node | Trusted | Reach hosts, deliver probe, normalise + sign results |
| Host | **Untrusted** | May lie, kill the probe, or return hostile data |

---

## 3. End-to-end scan lifecycle

```mermaid
sequenceDiagram
  autonumber
  participant Sched as Scheduler
  participant Srv as rustmite-server
  participant Node as rustmite-node
  participant Host as Monitored host
  participant Probe as rustmite-probe

  Sched->>Srv: Materialise scan job (host, check set)
  Node->>Srv: Lease jobs (capacity-aware long-poll)
  Srv-->>Node: Job + collection plan
  Node->>Host: SSH connect (pinned host key)
  Node->>Host: Two-stage memfd delivery
  Host->>Probe: exec from anonymous fd
  Node->>Probe: ScanRequest on stdin (JSON line)
  loop Collectors
    Probe->>Host: Raw syscalls / ProcSource / FsSource
    Probe-->>Node: NDJSON Observation lines
  end
  Probe-->>Node: Exit (no files left)
  Node->>Srv: Signed result chunks
  Srv->>Srv: Evaluate checks → Findings
  Srv->>Srv: Baseline / key-graph / cred correlate
  Srv->>Srv: Alerts → sinks
```

Streaming is mandatory: observations are never buffered as a full host dump on the node.

---

## 4. Probe delivery (why memfd)

The probe must not land on a writable, executable disk path the attacker can inspect or
tamper with. Delivery prefers anonymous memory:

```mermaid
flowchart TD
  A["Node selects probe build<br/>(arch + kernel class)"] --> B["Stage 0: tiny loader<br/>rustmite-loader"]
  B --> C{"Writable + exec<br/>tmpfs available?"}
  C -->|yes Method A| D["Write loader → memfd_create<br/>exec loader from fd"]
  C -->|noexec /tmp Method B| E["Alternate staging<br/>(e.g. home tmpfs / pipe)"]
  C -->|no exec path Method D| F["Degrade: RM-POL-0021<br/>limited / no full probe"]
  D --> G["Stage 1: full probe<br/>loaded into new memfd"]
  E --> G
  G --> H["Probe runs collectors<br/>stdout = NDJSON only"]
  H --> I["Process exits → memory gone"]
```

Host-key change at connect time aborts the scan and raises **RM-POL-0001** — never auto-trust.

---

## 5. Inside the probe: collectors → observations

```mermaid
flowchart TB
  REQ["ScanRequest<br/>collection plan + limits + budget"] --> REG["Collector registry"]
  REG --> C1["decloak.process"]
  REG --> C2["process.inventory"]
  REG --> C3["net.sockets"]
  REG --> C4["file.integrity / entropy / …"]
  REG --> C5["ssh.keys / cred.audit / …"]

  subgraph Sources["Fixture-testable I/O"]
    PS["ProcSource<br/>Live or Fixture"]
    FS["FsSource<br/>Live or Fixture"]
    RAW["rustmite-sys<br/>getdents64, sched_*, openat…"]
  end

  C1 --> PS
  C2 --> PS
  C3 --> PS
  C4 --> FS
  C5 --> FS
  PS --> RAW
  FS --> RAW

  C1 & C2 & C3 & C4 & C5 --> OBS["Observation tagged union<br/>HiddenProcess, Account, IntegrityMismatch…"]
  OBS --> OUT["stdout NDJSON<br/>(diagnostics → stderr only)"]
```

**Prime directive in practice:** hiding checks ask the same question through several kernel
interfaces and report *disagreement*.

```mermaid
flowchart LR
  Q["Which PIDs exist?"] --> A["A: getdents64 /proc"]
  Q --> B["B: sched_getscheduler sweep"]
  Q --> C["C: sched_debug / tasks"]
  Q --> D["D: cgroup.procs"]
  Q --> E["E: openat /proc/pid/stat"]
  A & B & C & D & E --> DIFF["hidden = (B∪C∪D∪E) \\ A<br/>confirmed across 2 passes"]
  DIFF --> HP["Observation::HiddenProcess"]
```

---

## 6. Server-side: observations → findings

Checks are **data** (`checks/RM-*.toml`). Adding a check does not rebuild the probe.

```mermaid
flowchart LR
  OBS["Stored Observations"] --> ENG["rustmite-checks<br/>+ rustmite-expr"]
  MAN["Check manifests<br/>match + where"] --> ENG
  ENG --> FIND["Findings<br/>severity · evidence · ATT&CK"]

  OBS --> BASE["Baseline diff"]
  BASE --> DRIFT["RM-DRIFT-* / RM-USER-0004…"]

  OBS --> KEY["SSH key graph<br/>fingerprint ↔ host,user"]
  KEY --> INC["RM-INC-0004 lateral movement"]

  OBS --> CRED["Shadow fingerprints<br/>never raw hashes"]
  CRED --> DUP["RM-CRED-0002 duplicates"]

  FIND & DRIFT & INC & DUP --> ALERT["Notify sinks"]
```

| Concept | Meaning |
|---|---|
| **Observation** | Raw fact from a collector (not a verdict) |
| **Check** | Rule: `match` stream + `where` expression |
| **Finding** | A check that fired, with evidence |
| **Collection plan** | Union of collectors required by the enabled check set |

---

## 7. Crate map (code ↔ runtime)

```mermaid
flowchart TB
  subgraph Probe_side["On the host (ephemeral)"]
    probe["rustmite-probe"]
    loader["rustmite-loader"]
    collect["rustmite-collect"]
    analyze["rustmite-analyze"]
    sys["rustmite-sys"]
    proto1["rustmite-proto"]
    probe --> collect --> analyze
    collect --> sys
    probe --> proto1
    loader --> probe
  end

  subgraph Node_side["On the node"]
    node["rustmite-node"]
    transport["rustmite-transport"]
    crypto["rustmite-crypto"]
    node --> transport
    node --> crypto
  end

  subgraph Server_side["On the server / CLI"]
    server["rustmite-server"]
    checks["rustmite-checks"]
    expr["rustmite-expr"]
    store["rustmite-store"]
    notify["rustmite-notify"]
    cli["rustmite-cli"]
    server --> checks --> expr
    server --> store
    server --> notify
    cli --> collect
    cli --> checks
    cli --> transport
  end

  transport -.->|"SSH delivers"| loader
  node -.->|"signed results"| server
```

---

## 8. Standalone paths (no full cluster)

Useful for IR and fixture development:

```mermaid
flowchart TD
  subgraph Fixture["Offline / CI"]
    FX["fixtures/* tree"] --> CLI1["rustmite-cli scan-fixture"]
    CLI1 --> COL1["collectors over FixtureProc/Fs"]
    COL1 --> CHK1["local CheckEngine"]
    CHK1 --> OUT1["JSON findings"]
  end

  subgraph Live["Single host"]
    CFG["examples/scan.toml"] --> CLI2["rustmite-cli scan-config"]
    CLI2 --> TR["rustmite-transport SSH"]
    TR --> PR["live probe"]
    PR --> CHK2["local or server eval"]
  end
```

```bash
# Differential detection against a recorded rootkit fixture
cargo run -p rustmite-cli -- scan-fixture --fixture fixtures/diamorphine-hidden-pid

# Package integrity (trojaned ls)
cargo run -p rustmite-cli -- scan-fixture --fixture fixtures/trojaned-ls
```

---

## 9. Trust & data hygiene (short)

```mermaid
flowchart LR
  HOST["Host output"] -->|"hostile by default"| PARSE["Bounded typed parse<br/>no serde_json::Value hot path"]
  PARSE --> NODE_SIG["Node signs normalised result"]
  NODE_SIG --> SRV["Server verifies node, not probe"]

  SHADOW["/etc/shadow"] --> FP["hash_fingerprint only<br/>raw zeroized"]
  FP --> STORE["DB never stores cleartext hashes"]
```

- Probe-side signatures are **not** used for authenticity (key would be on the attacker’s machine).
- Authenticity = SSH channel + pinned host key + node signature to the server.
- Paths are bytes (`PathBytes`); UTF-8 is only assumed at display time.

---

## 10. Where to read next

| If you want… | Read |
|---|---|
| Failure modes, scheduling, topologies | [`01-architecture.md`](01-architecture.md) |
| Probe budgets, panic-free rules, stdout discipline | [`03-probe-runtime.md`](03-probe-runtime.md) |
| Method A/B/D loader details | [`04-ssh-transport.md`](04-ssh-transport.md) |
| Check TOML + expression language | [`05-check-engine.md`](05-check-engine.md) |
| Every collector algorithm | [`06-detection-modules.md`](06-detection-modules.md) |
| Wire types + Postgres | [`07-data-model.md`](07-data-model.md) |
| Seed check IDs | [`11-detection-catalog.md`](11-detection-catalog.md) |
