# 06 — Detection Modules (Collectors & Algorithms)

This is the technical heart of RustMite. Each module below is a collector in `rustmite-collect`, producing `Observation`s that server-side checks (`05`, `11`) turn into findings. Every hiding-related module follows the Prime Directive: **gather one fact from multiple independent kernel interfaces and report disagreement.**

Notation: `P(x)` = read via `/proc` path x (through `ProcSource`); `S(name)` = raw syscall. "Δ" marks a differential.

---

## 1. Module index

| § | Collector ID | Type | Cost | Detects |
|---|---|---|---|---|
| 2 | `decloak.process` | process | Trivial | LKM/eBPF/LD_PRELOAD hidden processes |
| 3 | `process.inventory` | process/recon | Low | full process facts; deleted/memfd binaries; masquerading |
| 4 | `net.sockets` + `decloak.socket` | process | Low | hidden ports/connections, backdoor listeners |
| 5 | `entropy` + `file.elf` | file | High | packed/encrypted binaries (sandfly-entropyscan parity) |
| 6 | `modules.lkm` | file/process | Low | hidden/unsigned/tainting kernel modules |
| 7 | `ebpf` | process | Low | malicious eBPF programs & hidden maps |
| 8 | `persistence.preload` | file | Trivial | `/etc/ld.so.preload`, `LD_PRELOAD` rootkits |
| 9 | `persistence.scheduled` | file/user | Low | cron, at, systemd timers, anacron backdoors |
| 10 | `persistence.services` | file | Low | malicious systemd units, init scripts, udev, dbus |
| 11 | `persistence.accounts` | user | Low | backdoor accounts, sudoers, PAM, authorized_keys |
| 12 | `fs.anomaly` + `dir.hidden` | dir/file | Medium | hidden dirs, world-writable, timestomping, immutable malware |
| 13 | `file.integrity` | file | Medium→High | drift vs package DB and baseline |
| 14 | `file.ioc` | file | Medium | hash/path/YARA-lite IOC matches, setuid inventory |
| 15 | `log.integrity` | log | Low | wiped/truncated/holed logs, utmp tampering |
| 16 | `user.sessions` | user/log | Low | live intruder sessions, orphan roots, shell histories |
| 17 | `container.escape` | policy | Low | container-aware checks, escape indicators |
| 18 | `mount.anomaly` | policy | Trivial | bind-mount hiding, overlay tricks, `/proc` remounts |
| 19 | `ssh.keys` | user | Low | SSH key inventory + cross-host lateral-movement graph |
| 20 | `cred.audit` | user | Low→High | weak/duplicate/absent password hashes |
| 21 | `drift.baseline` | policy | High | signed baseline diff engine |
| 22 | `recon.inventory` | recon | Low | passive full-host inventory for SIEM/ML |

---

## 2. `decloak.process` — hidden process detection (sandfly-processdecloak parity, extended)

### 2.1 Principle

An LKM rootkit (Diamorphine, Reptile, etc.) hides a process by removing its `/proc/<pid>` entry from the directory listing (hooking `getdents`/`readdir` on procfs) while the task still exists in the kernel scheduler. A `LD_PRELOAD` rootkit hides it only from libc `readdir` callers — which is why the probe never uses libc. We therefore ask the same question — *"which PIDs exist?"* — through interfaces that a rootkit author must all hook identically:

**Six independent PID sources:**

| # | Source | Interface | What a rootkit must hook to defeat it |
|---|---|---|---|
| A | procfs listing | `getdents64` on `/proc` (raw syscall, not libc) | procfs `readdir` (they do) |
| B | PID liveness probe | `S(sched_getscheduler(pid))` / `S(getpgid)` / `S(kill(pid,0))` across full PID space | the scheduler syscalls (they usually don't) |
| C | scheduler debug | `P(/proc/sched_debug)` and `P(/proc/<pid>/task)` | sched_debug seq_file |
| D | cgroup membership | `P(/sys/fs/cgroup/**/cgroup.procs)` (v2) / `tasks` (v1) | cgroupfs |
| E | PID-max sweep of `/proc/<pid>/stat` direct open | `openat(/proc, "<pid>/stat")` for every pid — a hidden entry often still `open`s even when hidden from listing | both listing *and* lookup (harder) |
| F | thread/global via `/proc/<pid>/status` reverse | walk each visible task's `Threads`, `NSpid`, parent/child; find referenced PIDs not independently listed | consistent PID-namespace lies |

### 2.2 Algorithm

```
1.  pid_max = P(/proc/sys/kernel/pid_max)   (default 32768; may be 4194304)
2.  A = set of pids from getdents64("/proc")            [raw]
3.  For pid in 1..=pid_max:                              [source B + E, the bruteforce]
        r = sched_getscheduler(pid)
        if r is Ok OR errno == EPERM:                    # EPERM ⇒ exists but not ours
            B.insert(pid)
        else if errno == ESRCH:                          # definitively absent
            continue
        # cross-check with a second syscall to reduce false positives:
        if getpgid(pid) succeeds or EPERM: B.insert(pid)
        # source E: try to open /proc/<pid>/stat directly
        if openat("/proc", "<pid>/stat") ok: E.insert(pid); parse comm
4.  C = pids referenced in /proc/sched_debug + each /proc/<pid>/task/*
5.  D = pids in every cgroup.procs / tasks file
6.  hidden = (B ∪ C ∪ D ∪ E) \ A            # exist to the kernel, absent from /proc listing
7.  For each h in hidden: gather whatever is still readable (comm from stat if E hit,
        exe link, cgroup path, uid) → Observation{ kind: HiddenProcess, sources_hit }
8.  Also compute:  listing_only = A \ (B ∪ E)   # in listing but scheduler denies existence
        → "phantom" entries, indicates a *faking* rootkit or a race; re-verify with starttime.
```

### 2.3 False-positive control (this is where naive tools fail)

- **PID reuse race.** Between step 2 and step 3 a process may exit and its PID be reused. Mitigation: for every candidate `hidden` PID, re-read source A (listing) *and* re-probe B; require the PID to be **absent from listing in two passes** and **present via syscall in two passes**, and require a stable `starttime` if any per-pid file is readable. Only a PID that is consistently listing-absent / kernel-present across passes is reported. `sandfly-processdecloak`'s blog explicitly notes it "takes measures to limit" false positives; this is that measure, specified.
- **Very high `pid_max`** (4194304): full sweep is 4M syscalls. Bound it: sweep `1..=pid_max` only in `deep`/`incident` mode; in `pulse` mode sweep `1..=min(pid_max, 65536)` plus every PID referenced by sources C/D/F (rootkits overwhelmingly use low PIDs, and referenced-PID coverage catches high ones cheaply). Emit `coverage: {swept_max, mode}` so the finding states exactly what was checked.
- **PID namespaces / containers.** Inside the host scan, a container's PIDs appear via `/proc/<pid>/status` `NSpid`. Distinguish "hidden" from "in another namespace": a PID in another netns/pidns is present in host `/proc` under its host PID. Map via `NSpid` before declaring hidden. Report the namespace inode (`readlink /proc/<pid>/ns/pid`).
- **Kernel threads** (pids with no `exe`, `comm` in `[...]`): not hidden, but track them — some rootkits masquerade as `[kworker/...]` (§3.4).

### 2.4 Output

```json
{"kind":"hidden_process","pid":31337,"sources_present":["sched","cgroup","openat_stat"],
 "sources_absent":["proc_listing"],"comm":"kdevtmpfsi","exe":"/tmp/.x/miner",
 "uid":0,"starttime":88123,"cgroup":"/system.slice/....","passes_confirmed":2,
 "confidence":"high","note":"present to scheduler and cgroup, absent from /proc listing"}
```

Confidence grading: `high` if ≥2 non-listing sources agree across 2 passes; `medium` if a single source; `low`/suppressed if unstable (likely race).

### 2.5 Related decloaks reusing the same pattern

- **Thread hiding**: compare `/proc/<pid>/task` count with `Threads:` in `status` and with `/proc/<pid>/stat` num_threads (field 20).
- **Reptile-style** hides by PID and by a magic prefix on files/dirs — cross-checked in §12.

---

## 3. `process.inventory` — full process facts + masquerade detection

For every visible (and every decloaked) PID, gather:

| Field | Source | Detection use |
|---|---|---|
| `comm` (field 2 of stat) | `/proc/<pid>/stat` (parse via last `)`, see `03` §7.4) | masquerade: `comm` says `sshd` but `exe` is `/tmp/x` |
| `exe` | `readlink /proc/<pid>/exe` | **`(deleted)` suffix** ⇒ running-but-unlinked binary (classic fileless/anti-forensic). High signal. |
| memfd exe | `readlink` target matches `/memfd:` or `anon_inode` | **fileless execution** (attacker's own `memfd_create`) — very high signal |
| `cmdline` | `/proc/<pid>/cmdline` (NUL-separated) | argv[0] vs comm vs exe mismatch |
| `cwd`, `root` | readlink | process chrooted into `/tmp`, or `root` != `/` |
| `uid/gid` (real,eff,saved,fs) | `status` Uid/Gid | setuid escalation; euid 0 with ruid non-0 |
| `ppid`, session, tty | stat | orphaned (`ppid==1`) network daemons; no-tty root shells |
| `environ` | `/proc/<pid>/environ` | `LD_PRELOAD`, `LD_LIBRARY_PATH`, `HISTFILE=/dev/null` set on a live process |
| `maps` | `/proc/<pid>/maps` | injected `rwx` regions, unbacked executable memory, deleted-file mappings |
| open fds | `/proc/<pid>/fd/*` readlink | sockets, deleted files held open, `/dev/mem` access, raw sockets |
| start time | stat field 22 | timeline; correlation with auth events |
| capabilities | `status` Cap* | non-root process holding `CAP_SYS_MODULE`/`CAP_SYS_PTRACE`/`CAP_BPF` |
| SELinux/AppArmor ctx | `/proc/<pid>/attr/current` | confinement anomalies |
| nsproxy inodes | readlink `ns/*` | container membership, netns hiding |

### 3.4 Masquerade & anomaly signals (checks in `11`)

- **exe/comm/argv0 triangle mismatch** (e.g. `comm=kworker`, `exe=/usr/bin/python3`, in `/tmp`).
- **Fake kernel thread**: `comm` bracketed like `[kworker/0:2]` but has a non-null `exe` link (real kthreads have empty `exe`). Very reliable rootkit tell.
- **Deleted/`memfd` executable** running.
- **`rwx` and unbacked-exec regions** in `maps` (code injection / packed unpackers).
- **Executable running from suspicious dir**: `/tmp`, `/dev/shm`, `/var/tmp`, `/run`, a user home, a `.`-prefixed dir, a world-writable path.
- **Env-based hooking present** on a live process.
- **Root process with `ppid==1`, no controlling tty, listening socket, started after last patch window.**

---

## 4. `net.sockets` + `decloak.socket` — hidden ports & backdoors

### 4.1 Sources (Δ)

| Source | Interface |
|---|---|
| netlink `sock_diag` (`INET_DIAG`, `UNIX_DIAG`, `PACKET_DIAG`, `NETLINK_DIAG`) | `S(socket(AF_NETLINK, ..., NETLINK_SOCK_DIAG))` — enumerate all sockets with owning inode |
| `/proc/net/{tcp,tcp6,udp,udp6,raw,unix,packet}` | procfs text |
| per-process `/proc/<pid>/fd/*` socket inodes | ties socket inode → PID |

### 4.2 Algorithm

```
1. K = sockets from sock_diag (kernel-authoritative), each with inode, state, local/remote, uid.
2. T = sockets parsed from /proc/net/*   (what a rootkit typically edits to hide a port).
3. hidden_ports = K \ T                  # kernel knows the socket, procfs text hides it
   phantom_ports = T \ K                 # appears in text only (rare; faking)
4. For each socket inode in K, find owning PID by matching /proc/<pid>/fd/* symlinks
   (socket:[inode]). Unowned listener sockets (no visible PID) ⇒ hidden-process backdoor.
5. Cross-reference owning PID against decloak.process hidden set.
```

### 4.3 Findings

- **Hidden listener**: kernel has a `LISTEN` socket on port N that `/proc/net/tcp` omits → backdoor.
- **Backdoor port / unexpected listener**: any listener not in the host's allowed-port baseline (`05` policy).
- **Reverse shell / C2 egress**: `ESTABLISHED` outbound from an unusual process (shell, `/tmp` binary) to an external IP.
- **Raw / packet sockets** owned by non-standard processes (sniffers).
- **Orphan socket** (owning inode maps to no visible PID) → strong hidden-process corroboration.
- **Promiscuous interfaces**: read `/sys/class/net/*/flags` and `IFF_PROMISC` via netlink.

Normalise addresses (hex→ip), resolve nothing (no DNS from the probe), include remote IP/ASN enrichment server-side only.

---

## 5. `entropy` + `file.elf` — packed/encrypted binary detection (sandfly-entropyscan parity)

### 5.1 Shannon entropy

For a file (or a process's `exe`, or a memory region), compute byte-frequency Shannon entropy on a 0.0–8.0 scale:

```
H = -Σ (p_i * log2(p_i))   over 256 byte values
```

- Whole-file entropy flags packed/encrypted content: **> 7.0** is suspicious for an ELF (native code averages ~5.8–6.3; UPX/encrypted ≈ 7.7–8.0).
- **Sliding-window entropy** (e.g. 256-byte windows) locates an encrypted/packed *section* inside an otherwise-normal binary (appended payloads, infected hosts). Report max window, and the offset.
- To cut false positives (compressed media, archives look high-entropy but are benign), gate on file type: only alarm at high entropy when the file **is an ELF** (see 5.2) or is executable/setuid, or lives in a sensitive path. This mirrors sandfly-entropyscan's `-elf` flag behaviour.

### 5.2 ELF analysis (`goblin`)

- Confirm ELF magic and parse headers. An ELF with entropy > 7.2 and few sections, or a single huge `PT_LOAD` `rwx` segment, or a non-standard entry point in a writable segment → packer/injection.
- **Packer fingerprints**: UPX section names (`UPX0/UPX1`), absent section header table, suspicious `p_flags` (`RWX`), `.text` writable, mismatch between `e_shoff` and file size, tiny section count with large segments.
- **Static vs dynamic, stripped, interpreter path** (`PT_INTERP` pointing somewhere odd, e.g. `/tmp/ld`).
- **Anomalous** `e_machine` vs host arch (cross-arch dropper).

### 5.3 Hashing

For every flagged file (and, in inventory mode, every executable in scope) compute: **SHA-256** (primary), and on request MD5/SHA-1 (IOC-feed compatibility only — never for integrity), plus **BLAKE3** for fast baseline diffs. Stream the hash; never load the file fully. Respect `max_bytes_hashed`. Skip files > 2 GiB and non-regular files (parity with sandfly-entropyscan, and safety).

### 5.4 Process memory entropy

Optionally hash/entropy-scan a process's anonymous `rwx` regions from `/proc/<pid>/mem` (root only, careful bounded reads with `pread`) to catch in-memory-only packed payloads. High cost, `incident` mode only.

### 5.5 Output

```json
{"kind":"file_entropy","path":"/tmp/.x/miner","is_elf":true,"entropy":7.94,
 "max_window_entropy":7.99,"window_offset":4096,"packer":"upx?","size":1048576,
 "sha256":"…","mode":"0755","uid":0,"suspicious":true}
```

---

## 6. `modules.lkm` — kernel module inspection

### 6.1 Sources (Δ)

| Source | Interface |
|---|---|
| `/proc/modules` | text list of loaded modules |
| `/sys/module/*` | directory per module (name, refcnt, taint, sections, params) |
| `/proc/kallsyms` | symbol table (if readable; often restricted) |
| kernel taint | `/proc/sys/kernel/tainted` bitmask |

### 6.2 Algorithm

```
1. M_proc = names from /proc/modules
2. M_sys  = dirnames in /sys/module that expose `initstate` (loadable only;
                                          built-ins like `8250` are excluded)
3. hidden_module = symmetric difference   → very high signal (Diamorphine hides itself from
                                            /proc/modules but its unhook is imperfect)
4. Parse /proc/sys/kernel/tainted (bitmask): O=out-of-tree module, F=force-loaded,
   E=unsigned module, P=proprietary module, R=force-unloaded (a bare G means clean/GPL).
   A newly-set 'O' (out-of-tree) or 'E' (unsigned) bit vs baseline is a rootkit indicator.
5. For each **loadable** module in /sys/module/* (those with an `initstate` attribute):
   compare against `/proc/modules`. Built-in modules appear under `/sys/module` without
   `initstate` and never appear in `/proc/modules` — exclude them from the Δ (they are
   not a finding; e.g. `8250`, compiled-in `ext4`).
6. Flag: loadable modules with no /sys entry, modules whose .text is in an unusual range,
   modules absent from the distro's shipped module set, zero-refcount hook modules.
7. /proc/kallsyms sanity: look for symbols pointing into module address space that hook
   syscall table entries where readable; detect known rootkit symbol names
   (aho-corasick over a curated list: diamorphine, reptile, khook, etc.) — heuristic only.
```

### 6.3 Findings
Hidden module (Δ), unsigned/out-of-tree module appearing since baseline, tainted-kernel transition, known-rootkit symbol/name match, module hooking syscall table (where observable).

---

## 7. `ebpf` — malicious eBPF detection

Modern rootkits (e.g. bpfdoor-style, TripleCross) live in eBPF rather than LKMs.

### 7.1 Sources

- `bpf(BPF_PROG_GET_NEXT_ID)` → iterate program IDs → `BPF_PROG_GET_FD_BY_ID` → `BPF_OBJ_GET_INFO_BY_FD` (name, type, tag, load time, attach type, run count).
- Same for **maps** (`BPF_MAP_GET_NEXT_ID`) and **links** (`BPF_LINK_GET_NEXT_ID`).
- `/sys/fs/bpf/*` pinned objects.
- `/proc/<pid>/fd` referencing `bpf-prog`/`bpf-map` anon inodes → owning process.

### 7.2 Algorithm & findings (Δ)

```
1. Enumerate all prog IDs via bpf() syscall (kernel-authoritative).
2. Enumerate progs referenced by visible process fds.
3. orphan_prog = kernel-listed progs with no owning visible process, esp. types
   BPF_PROG_TYPE_KPROBE / TRACEPOINT / XDP / SCHED_CLS / CGROUP_SKB / SOCKET_FILTER
   attached but unowned  → hidden eBPF backdoor.
4. Flag: XDP/tc programs on network interfaces (traffic hiding / C2), kprobe programs
   attached to sys_getdents/tcp4_seq_show/... (the classic hiding hooks),
   programs loaded from anonymous fds, recently-loaded progs vs baseline.
5. Read /sys/kernel/debug/tracing/kprobe_events & uprobe_events (if tracefs readable)
   for unexpected probes.
```

Requires kernel ≥ 4.13 for iteration; on older kernels emit `Unsupported`.

---

## 8. `persistence.preload` — LD_PRELOAD / linker hijack

The cheapest, highest-value userland-rootkit check.

- Read **`/etc/ld.so.preload`** (existence alone is suspicious on most systems; content lists injected `.so`s). Hash and resolve each listed library; flag if in `/tmp`, world-writable, unsigned, or absent from package DB.
- Scan process `environ` for `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` on live processes (§3).
- Check **`/etc/ld.so.conf`, `/etc/ld.so.conf.d/*`** for injected directories.
- Check the dynamic linker cache anomalies where feasible.
- Read `~/.bashrc`, `/etc/profile.d/*`, `/etc/environment` for exported `LD_*` (see §9/§11 overlap).

Because the probe itself uses **no libc**, it reads `/etc/ld.so.preload` truthfully even when the host's libc is subverted — the reason ADR-1 exists.

---

## 9. `persistence.scheduled` — cron/at/timers

| Location | Parse |
|---|---|
| `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*` | cron syntax; flag commands fetching+executing (`curl|sh`, base64, `/tmp` paths) |
| `/var/spool/cron/crontabs/*` (per-user) | user crontabs, esp. root and system accounts |
| `/etc/anacrontab` | anacron |
| `at`/`atd` spool `/var/spool/cron/atjobs` | one-shot persistence |
| systemd timers: `*.timer` units + their `.service` | `OnCalendar`, transient timers |

Findings: new/modified cron since baseline, cron referencing suspicious paths or network fetch-exec, cron owned by unexpected user, hidden entries (compare crontab file mtime vs content), `@reboot` persistence.

---

## 10. `persistence.services` — init/systemd/udev/dbus

- **systemd units**: enumerate `/etc/systemd/system/**`, `/run/systemd/system/**`, `/usr/lib/systemd/system/**`, and `.wants`/`.requires` symlinks. Parse `ExecStart*`, `User=`, `Environment=`. Flag: units in `/tmp`/`/dev/shm`, ExecStart to suspicious paths, masquerading unit names, unit not owned by a package, `DynamicUser` abuse, drop-ins (`*.conf` in `*.service.d/`) altering a legit service.
- **SysV/init**: `/etc/init.d/*`, `/etc/rc*.d/*`.
- **udev rules**: `/etc/udev/rules.d/*`, `/lib/udev/rules.d/*` with `RUN+=` executing payloads.
- **D-Bus services**: `/usr/share/dbus-1/system-services/*`, `Exec=` lines.
- **PAM**: `/etc/pam.d/*` and `/lib*/security/*.so` — injected PAM modules (`pam_exec`, unknown `.so`) that capture passwords or add backdoor auth. Hash PAM modules; compare to package DB.
- **NSS**: `/etc/nsswitch.conf` + `libnss_*.so` anomalies.
- **MOTD / update-motd.d**, `/etc/profile.d/*`, shell rc files as exec-on-login persistence.

---

## 11. `persistence.accounts` — account & auth backdoors

- **`/etc/passwd`**: UID 0 accounts other than `root` (privilege backdoor), accounts with valid shells that should be `nologin`, new system accounts, mismatched `passwd`/`shadow`.
- **`/etc/shadow`**: accounts with empty password field (login with no password), `*`/`!` vs a real hash on service accounts, aging anomalies. (Hash strength → §20.)
- **`/etc/sudoers` + `/etc/sudoers.d/*`**: `NOPASSWD:ALL`, wildcard rules, non-admin users granted root, `!authenticate`.
- **`authorized_keys`** for every user (from `passwd` home dirs + `AuthorizedKeysFile` in sshd_config): inventory keys, flag keys with forced-command bypass, `from=` absence, keys added since baseline, keys whose fingerprints appear on other hosts (→ §19 graph), options like `command=` that spawn shells.
- **`/root/.ssh/`**, root shell histories, `/etc/passwd`-writable checks.
- **Group membership**: `/etc/group` — unexpected members of `sudo`,`wheel`,`docker`(=root-equivalent),`lxd`.

---

## 12. `fs.anomaly` + `dir.hidden` — filesystem hiding & tampering

### 12.1 Hidden directories/files
- Directories used to stash tools: `.`-prefixed dirs in `/`, `/tmp`, `/dev`, `/var/tmp`, `/dev/shm`; dirs with space/newline/unicode-trick names; files under `/dev` that are regular files (should be device nodes) — a classic rootkit stash (`/dev/.hidden`).
- **Reptile-style magic-prefix hiding** (Δ): the rootkit hides any file whose name contains a magic tag. Detect by comparing the byte count from `getdents64` (`d_reclen` sum) against the number of entries actually returned, and by cross-referencing `statx` on names guessed from other sources (a file referenced by a process's `exe`/`fd` but absent from its parent dir listing → hidden).
- **link count Δ**: a directory's `st_nlink` implies a subdirectory count (nlink = 2 + #subdirs on ext-like FS); compare with the number of subdirs actually listed. Mismatch ⇒ hidden subdirectories. Same trick as `unhide`'s filesystem checks, adapted.

### 12.2 Timestomping & immutability
- **`statx` btime vs mtime/ctime**: mtime far older than ctime, or btime after mtime, or timestamps with zeroed sub-second precision / round numbers → timestomp. Compare against neighbouring files in the same directory.
- **Immutable/append-only flags** (`FS_IOC_GETFLAGS`, `FS_IMMUTABLE_FL`/`FS_APPEND_FL`) on malware (attackers set immutable to resist deletion) or on logs (append-only removed to allow wiping).
- **World-writable** executables, setuid files, files in `$PATH` writable by non-root.

### 12.3 Suspicious files
Regular files in `/dev`, `/proc`-shadowing, ELF files in `/tmp`/`/dev/shm`, dotfiles that are ELF, sockets/FIFOs in web roots.

---

## 13. `file.integrity` — package DB & baseline verification

- **dpkg**: parse `/var/lib/dpkg/info/*.md5sums`; recompute (MD5 here only because that's what dpkg stores) for critical binaries (`/bin`,`/sbin`,`/usr/bin`,`/usr/sbin`,`/lib*`), flag mismatches → trojaned system binary (`ls`, `ps`, `sshd`, `sudo`…). This catches replaced coreutils that the probe deliberately never trusts for detection.
- **rpm**: read `/var/lib/rpm` (Berkeley DB or sqlite `rpmdb.sqlite`) to get expected digests; verify. (Pure-Rust sqlite read via `rusqlite`? — `rusqlite` bundles C. Prefer a pure-Rust sqlite reader or parse the rpm db format directly; document the tradeoff. Fallback: mark rpm verification `Unsupported` if no pure-Rust reader is acceptable.)
- **Critical-file allowlist hashing**: independent of package DB, hash a curated set (`sshd`, `sshd_config`, `pam` modules, `ld.so`, `libc`, `/etc/passwd`,…) and diff vs the **RustMite baseline** (§21).
- Flag any system binary whose on-disk hash changed without a corresponding package update event.

---

## 14. `file.ioc` — indicator matching & setuid inventory

- **Hash IOC**: match file SHA-256/MD5 against the `IocSet` in the plan (threat-intel feeds pushed from the server).
- **Path/glob IOC**: known rootkit paths (`/usr/bin/..2`, `/lib/libudev.so.`, `/etc/rc.modules`, etc.).
- **String IOC**: `aho-corasick` multi-pattern scan over flagged files / process cmdlines / scripts (C2 domains, wallet addresses, known loader strings). Bounded bytes per file.
- **YARA-lite (optional)**: a minimal pure-Rust rule subset, or integrate `yara-x` (Rust rewrite of YARA) on the *node/server* side over files the probe returned — keeps C out of the probe. Recommended: run YARA-X server-side on high-entropy/flagged files the probe uploads on request, not in the probe.
- **Setuid/setgid inventory**: walk bounded roots (`/bin`, `/usr/bin`, `/tmp`, `/home`, …); emit `FileMeta` for setuid/setgid and world-writable executables. Feeds `RM-FILE-0005`/`0006`/`0015` (Elastic LPE SUID/GTFOBins posture). Diff vs baseline for *new* setuid root binaries once drift is wired.

### 14.1 Elastic Linux LPE framework — what maps today

Source: [Elastic Security Labs — Linux privilege escalation detection framework](https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework).

| Elastic pattern | RustMite adaptation | IDs |
|---|---|---|
| SUID/SGID helper privilege shape (`euid=0`, `ruid≠0`) | Live process snapshot | RM-PROC-0015 |
| Uncommon / GTFOBins SUID abuse | Process + on-disk setuid | RM-PROC-0018, RM-FILE-0015 |
| SUID shell `bash -p` | Cmdline + euid | RM-PROC-0017 |
| Exec from writable path then elevate | Root exe still in `/tmp` etc. | RM-PROC-0016 |
| Python escalate from staging cwd | Elevated python + cwd | RM-PROC-0019 |
| Dangerous capabilities | CapEff bits on non-root | RM-PROC-0012 |
| Setuid in non-standard path | `file.ioc` inventory | RM-FILE-0006 |
| Exec→`uid_change`→`whoami` sequences | **Needs auditd/eBPF stream** | backlog |
| `unshare`→root / descendant-of | **Needs continuous events** | backlog |

---

## 15. `log.integrity` — log & audit tampering

- **utmp/wtmp/btmp** (`/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp`): parse the binary `utmp` record format (pure Rust in `rustmite-analyze`); detect: zeroed records (log wiping leaves gaps), records out of chronological order, truncated files, impossible sessions.
- **journald**: `/var/log/journal/**/*.journal` — detect truncation, missing sequence numbers, files with holes.
- **Syslog files** (`/var/log/{auth.log,secure,messages,syslog}`): detect suspicious size drops vs baseline, `\0` holes (selective line deletion often leaves NULs or gaps), mtime older than newest expected event, missing files that should exist.
- **`lastlog`** anomalies.
- **Shell histories**: `HISTFILE` unset/`/dev/null` on live processes (§3), zero-length or symlinked-to-null histories for root, histories with `history -c`/`unset HISTFILE` markers.
- **Immutable/append-only removed** from a log (§12.2 overlap): a log that lost its append-only flag is being prepped for tampering.

---

## 16. `user.sessions` — live intruder & session anomalies

- Parse utmp for **current logins**; cross-reference with process sessions (§3) — a login with no corresponding process tree, or a shell process with no login record, is an inconsistency.
- **Root shells without tty**, root logins from unexpected source IPs (from wtmp/auth.log), concurrent root sessions.
- **Orphaned network processes** owned by users with `nologin` shells.
- **`.bash_history` forensic parse** (server-side enrichment): commands indicative of post-exploitation (`wget`,`curl|sh`,`chmod +x /tmp`,`nc -e`,`chattr +i`).

---

## 17. `container.escape` — container awareness

Detect whether the scanned host *is* a container and whether escape indicators exist:
- Read `/proc/1/cgroup`, `/.dockerenv`, `/run/.containerenv`, namespace inodes.
- Escape indicators: a process with host-PID-namespace membership from inside a container, `/var/run/docker.sock` mounted, privileged container (`CAP_SYS_ADMIN` + host devices), `release_agent`/cgroup-escape setups, host `/` bind-mounted inside.
- For hosts *running* containers, optionally enumerate containers via `/proc` cgroup paths and scan each namespace (advanced, `incident` mode).

---

## 18. `mount.anomaly` — mount-based hiding

- Parse `/proc/self/mountinfo` and `/proc/mounts` (Δ against `/proc/<pid>/mountinfo` of pid 1).
- **Bind-mount hiding**: a bind mount over `/proc/<pid>` (hides a process from anything reading that path), over a log, or over a binary. Detect by comparing mountinfo entries whose target is inside `/proc`.
- **Overlay/tmpfs over system dirs**, `/proc` mounted with `hidepid`, unexpected `tmpfs` on `/dev/shm` with exec.
- Newly appeared mounts vs baseline.

---

## 19. `ssh.keys` — key inventory & lateral-movement graph

### Probe side
Collect, for every user: `~/.ssh/authorized_keys*`, `~/.ssh/id_*.pub` and known_hosts, host keys `/etc/ssh/ssh_host_*`, and sshd config (`AuthorizedKeysFile`, `TrustedUserCAKeys`, `Match` blocks). Fingerprint every key (SHA-256, MD5-legacy) in `rustmite-analyze`.

### Server side (the value-add)
Build a **bipartite graph**: `key_fingerprint ↔ (host, user)`. Then:
- **Stolen/replayed key detection**: the same *private*-key fingerprint authorised on an unusual set of hosts, or a personal key suddenly authorised on a server it never was → lateral movement / credential theft (Sandfly's "stolen SSH credentials / lateral movement" capability).
- **Unknown authorized key**: a key not present in any managed inventory added to `authorized_keys`.
- **Key with dangerous options** (`command=` shell, no `from=` restriction).
- **Weak keys**: RSA < 2048, DSA (deprecated), keys without passphrase where detectable.
- **Host-key reuse across hosts** (cloned images) → identity confusion.
- Cross-reference authentication events (auth.log) with key fingerprints to attribute logins.

---

## 20. `cred.audit` — password hash auditing

Probe returns `/etc/shadow` hashes (root-only; the hashes never leave the node/server boundary unencrypted; treat as secrets, `zeroize`). Server-side `rustmite-analyze` + crypto crates:

- **Hash scheme posture**: flag DES/`crypt`, MD5 (`$1$`), or unsalted → weak-by-design (`sha-crypt`/`bcrypt`/`yescrypt`/`argon2` expected).
- **Empty/`!`/`*` anomalies**: account that should be locked but has a hash; account with empty hash (passwordless login).
- **Duplicate hashes**: two accounts sharing a password (shared-credential risk).
- **Optional offline audit**: test each hash against a bounded wordlist + common patterns (`bcrypt`,`sha-crypt`,`md5-crypt`,`pbkdf2` crates) to surface *weak passwords proactively* (Sandfly's password-auditing capability). This is opt-in, rate-limited, and results store only "weak: yes/no + reason", never the recovered plaintext by default. Governed by explicit operator authorisation (`10` §7) — cracking hashes is sensitive.

---

## 21. `drift.baseline` — file integrity & configuration drift

- **Baseline creation**: on an operator-blessed "known good" scan, the server stores a signed baseline: hashes of a configured path set, setuid inventory, package list, listening ports, kernel modules, cron/systemd unit set, account list, SSH key set, sysctl posture.
- **Diff engine**: every subsequent `deep` scan diffs against the baseline → `Added/Removed/Changed` findings, each tied to the responsible object. Suppress expected churn (package updates correlated with the package DB's own change events).
- **Signed & tamper-evident**: baselines are Merkle-hashed; a host cannot be quietly re-baselined without an audited operator action.
- Config drift specifics: `sshd_config` weakening (PasswordAuth on, PermitRootLogin yes, weak KEX), `sysctl` security regressions (`kernel.kptr_restrict`, `randomize_va_space`, `dmesg_restrict`, `unprivileged_bpf_disabled`), firewall rule changes.

---

## 22. `recon.inventory` — passive inventory for SIEM/ML

Pure inventory, no verdicts, streamed to SIEM sinks for trend/anomaly analytics (Sandfly's "recon" type):
OS/kernel/arch, uptime/boot_id, full package list + versions, listening services, users/groups, scheduled tasks, kernel modules, network interfaces + routes, mounted filesystems, installed shells/interpreters, container runtime, cloud metadata presence, hardware summary. Emit as structured `recon.*` observations with stable schema so downstream ML can baseline "normal" per host and per fleet segment.

---

## 23. Collector → check-type mapping (for `05`/`11`)

| Sandfly-style type | Collectors feeding it |
|---|---|
| process | 2,3,4 |
| file | 5,13,14,12 |
| user | 11,16,19,20 |
| directory | 12 |
| log | 15 |
| policy | 17,18,21, sshd/sysctl posture |
| incident | deep variants of 2,3,5 + memory scan 5.4 |
| recon | 22 |
| custom | user-authored via the expression engine (`05` §4) over any observation |
