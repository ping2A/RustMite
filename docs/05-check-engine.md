# 05 — Check Engine

The check engine turns raw `Observation`s into `Finding`s. It is RustMite's analogue of Sandfly's "sandflies": versioned, data-defined rules that operators can read, edit, and extend without recompiling anything.

## 1. Design goals

- **Data, not code.** A check is a manifest (TOML/JSON), not a Rust function. Adding a check = adding a file; it takes effect at the next sweep with no probe or binary redeploy (ADR-2).
- **Auditable.** Every check has a stable ID, a version, an author, a rationale, ATT&CK mapping, references, and false-positive notes.
- **Composable.** Checks are expressions over a typed observation model, with reusable named predicates.
- **Safe to evaluate on hostile data.** The evaluator is total (no panics, no unbounded loops), sandboxed (no I/O, no host access), and bounded (per-check time/step budget).
- **Retro-huntable.** Because checks evaluate server-side over stored observations, a new check can be run against historical scans.

## 2. Check types (nine, mirroring Sandfly)

```rust
pub enum CheckType { Process, File, User, Directory, Log, Policy, Incident, Recon, Custom }
```

| Type | Semantics | Default sweep | Default enabled |
|---|---|---|---|
| Process | running-executable threats, hiding, masquerade | pulse | yes |
| File | malicious/altered files | standard | yes |
| User | account-level compromise | standard | yes |
| Directory | hidden/suspicious dirs | standard | yes |
| Log | missing/altered audit logs | standard | yes |
| Policy | misconfig / posture (SSH, sysctl, perms) | deep | **no** (opt-in; noisy, environment-specific) |
| Incident | deep, higher-impact IR modules | on-demand | no |
| Recon | passive inventory for SIEM/ML | deep | yes (no alerts, feed only) |
| Custom | operator-authored | any | as configured |

This taxonomy is inherited deliberately — it maps cleanly to operator mental models and to the collector set in `06` §23.

## 3. Check manifest schema

```toml
id = "RM-PROC-0007"                     # stable, unique, namespaced; RM-<TYPE>-<NNNN>
version = 3                              # bump on any semantic change
name = "Fake kernel thread (bracketed comm with real exe)"
type = "process"
severity = "high"                       # info|low|medium|high|critical
confidence = "high"                     # baseline confidence if it fires
enabled = true
cost = "trivial"                        # informs sweep placement
requires_caps = ["proc_exe_readable"]   # gates NotApplicable vs Pass (see §6)
attack = ["T1014", "T1055"]             # MITRE ATT&CK technique IDs
platforms = ["linux"]                   # future-proofing
kill_chain = "defense-evasion"

# The rule. Evaluated per observation of the bound collector(s).
match = "process"                        # observation stream this check consumes
where = '''
  process.comm matches "^\\[.*\\]$"      # looks like a kernel thread
  and process.exe != null                # but has a real executable
  and process.exe != ""
'''

# What to put in the finding.
title = "Process '{{process.comm}}' masquerades as a kernel thread"
evidence_fields = ["pid","comm","exe","cmdline","uid","starttime"]

# Operator guidance embedded in the finding.
rationale = "Real kernel threads have no exe link. A bracketed comm with a backing executable indicates a userland process disguising itself."
false_positives = "None known on standard distros. Some embedded init systems spawn bracketed userland helpers; add to allowlist if confirmed benign."
references = ["https://man7.org/linux/man-pages/man5/proc.5.html"]

# Optional suppression/allowlist hooks.
allowlist_key = "{{host_id}}:{{process.exe}}"
```

### 3.4 Confidence & severity are separate axes
- **Severity** = how bad if true.
- **Confidence** = how sure we are it's true (driven by differential agreement, `06`).
Alerts route on a policy combining both (`08` §5). A `critical`/`low-confidence` finding and a `medium`/`high-confidence` finding get different treatment.

## 4. Expression language (`rustmite-expr`)

A small, total, typed expression language. **Not** a general scripting language — no loops the user writes, no recursion, no host access.

### 4.1 Types
`null, bool, int (i64), float (f64), string, bytes, ipaddr, duration, timestamp, list<T>, map<string,V>`. Observations are typed records; fields are accessed as `process.exe`, `socket.local_port`, `file.entropy`.

### 4.2 Operators & functions
- Comparison: `== != < <= > >= in`
- Boolean: `and or not`
- Arithmetic: `+ - * / %` (checked; div-by-zero → error → check yields no match, logged)
- String: `matches <regex>` (regex is `regex` crate, **compiled once, size/complexity-capped, no catastrophic backtracking** since `regex` is linear-time), `contains`, `starts_with`, `ends_with`, `lower()`, `len()`
- Path: `path_under("/tmp")`, `basename()`, `is_world_writable(mode)`, `is_setuid(mode)`
- Collections: `any(list, pred)`, `all(list, pred)`, `count(list)`, `len()`
- Enrichment lookups (server-side only): `in_baseline(...)`, `known_hash(sha256)`, `pkg_owns(path)`, `geoip(ip).country`, `ioc_match(sha256)`, `key_seen_on_other_hosts(fp)`
- Time: `now()`, `age(ts)`, `ts > now() - 7d`

### 4.3 Named predicates (reuse)
```toml
[predicates]
suspicious_dir = 'path_under("/tmp") or path_under("/dev/shm") or path_under("/var/tmp") or basename(file.path) starts_with "."'
external_ip = 'not (socket.remote_ip in ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"])'
```
Referenced as `@suspicious_dir` inside `where`.

### 4.4 Grammar (EBNF sketch)
```
expr    := or
or      := and ("or" and)*
and     := cmp ("and" cmp)*
cmp     := unary (COMPOP unary)?
unary   := "not" unary | postfix
postfix := primary ("." IDENT | "(" args? ")" | "matches" STRING)*
primary := LITERAL | IDENT | "@" IDENT | "(" expr ")" | list | map
```

### 4.5 Evaluation safety
- Compiled to a typed AST at load time; **type errors fail the manifest load**, not the sweep (a bad check never breaks a scan).
- Step-bounded interpreter (`max_steps` per observation, default 10_000).
- Regex compiled once at load, cached; `regex` crate guarantees linear time (no ReDoS). Cap pattern size and compiled-program size.
- Totally sandboxed: the evaluator sees only the observation record + read-only enrichment tables passed in. It cannot perform I/O.

### 4.6 Pre-filter subset (probe-side)
A **restricted** subset of the language compiles to `CompiledPredicate` bytecode shipped in the `ScanRequest` (`03`/`04`). Restrictions: no enrichment functions (probe has no DB), no cross-observation state, regex allowed but size-capped harder, output is only "keep/drop". The compiler (§5) computes, for the active check set, a conservative pre-filter: **keep any observation that could possibly match any enabled check** (must never drop a would-match observation). If in doubt, keep. This trims the 2M-file case without losing detections.

## 5. Check compilation & planning

At sweep planning time, the server:
1. Loads enabled checks for the target host group.
2. Type-checks and compiles each `where` expression.
3. Computes the **union of required collectors** (from each check's `match` + functions used) → the `CollectionPlan.collectors`.
4. Computes **path scopes** (union of `path_under`/glob constraints) → `plan.scopes` so a check that only cares about `/etc` doesn't trigger a full-FS walk.
5. Derives conservative **pre-filters** → `plan.prefilters`.
6. Bundles the **IOC set**.
7. Emits a signed `ScanRequest`.

Result: probes do the minimum collection that the active checks require, and nothing more. Enabling one "hash every file" check is visibly expensive in the plan and can be gated to `deep` sweeps.

## 6. Applicability (never silently pass)

For each check, given the probe's `Hello.caps`:
- If a required capability is missing (`requires_caps`), the check result is **`NotApplicable(reason)`**, surfaced distinctly from `Pass`.
- The server tracks per-host **effective coverage**: "of the N enabled checks, M were applicable, K passed, F fired, U not-applicable." A host trending toward low applicability (e.g. because it stopped exposing `sock_diag`) is itself flagged (`RM-POL-0022`).

This directly addresses the classic failure of scanners reporting "clean" when they simply couldn't look.

## 7. Evaluation pipeline (server)

```
observations (per scan) ──► [check evaluator]
                                 │  per enabled check, per matching observation
                                 ▼
                            raw findings
                                 │
             ┌───────────────────┼─────────────────────┐
             ▼                   ▼                     ▼
        baseline diff       correlation           suppression/allowlist
        (drift findings)    (group related        (per-host, per-check,
                             findings into an       time-boxed, audited)
                             incident)
                                 │
                                 ▼
                             alerts ──► notify sinks (08 §5)
```

- **Evaluation is parallel** across checks and observations (`rayon`), CPU-bound, off the async reactor.
- **Deterministic ordering** of findings by `(check_id, primary_key)` for stable diffs and dedupe.
- **Correlation**: a light rule set groups co-occurring findings on a host into one incident (e.g. hidden process + hidden port owned by it + entropy hit on its exe → single "active rootkit" incident at critical). Correlation is itself expressed as checks over findings (`match = "finding"`).

## 8. Suppression, allowlisting, tuning

- **Allowlist** entries: `(check_id, allowlist_key, scope, expires_at, author, reason)`. Scope = host / group / global. Always time-boxed by default; permanent requires elevated role. Every allowlist application is recorded in the finding ("suppressed by rule X").
- **Baseline-aware suppression**: findings that merely reflect a known, package-attributable change are auto-downgraded.
- **Tuning workflow**: an operator marks a finding false-positive → generates a proposed allowlist entry → review → apply. Never silent global disable.

## 9. Check catalog management

- Catalog lives in `checks/` as versioned files, loaded into `check_definitions` (`07` §4). Built-in catalog (`11`) ships read-only; operator checks live alongside with a separate namespace (`RM-CUST-*`).
- **Signing**: built-in catalog releases are ed25519-signed; the server verifies signature + version monotonicity before activation, preventing a tampered catalog from silently disabling detections.
- **Hot reload** in dev via `notify`; explicit versioned publish in prod.
- **Testing**: every check ships with ≥1 positive and ≥1 negative fixture (`12` §3). CI fails a check that has no test or whose test regresses.
