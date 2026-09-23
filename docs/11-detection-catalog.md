# 11 — Detection Catalog (Seed Set)

A starter catalog of concrete checks. Each ships as a manifest (`05` §3) with a positive and negative fixture (`12` §3). IDs are stable; `RM-<TYPE>-NNNN`. Severity `S`, Confidence `C`, ATT&CK technique(s). This is the seed; the expression engine (`05` §4) lets operators grow it toward the 1000+ that a mature deployment carries.

Legend — S/C: Info·Low·Med·High·Crit / Lo·Md·Hi.

## Process (RM-PROC)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-PROC-0001 | Hidden process: kernel-present, `/proc`-listing-absent (≥2 sources, 2 passes) | Crit | Hi | T1014 | decloak.process |
| RM-PROC-0002 | Hidden process: single-source, unconfirmed (needs review) | High | Md | T1014 | decloak.process |
| RM-PROC-0003 | Thread-count mismatch (task dir vs status vs stat) | High | Md | T1014 | decloak.process |
| RM-PROC-0004 | Process running deleted executable (`exe` = `(deleted)`) | High | Hi | T1070.004 | process.inventory |
| RM-PROC-0005 | Fileless execution: exe backed by memfd/anon_inode | Crit | Hi | T1620 | process.inventory |
| RM-PROC-0006 | exe/comm/argv0 masquerade mismatch | High | Md | T1036 | process.inventory |
| RM-PROC-0007 | Fake kernel thread: bracketed comm with real exe | High | Hi | T1014,T1036 | process.inventory |
| RM-PROC-0008 | Executable running from `/tmp`,`/dev/shm`,`/var/tmp`,dotdir | High | Md | T1059 | process.inventory |
| RM-PROC-0009 | Live process with `LD_PRELOAD`/`LD_AUDIT` in environ | High | Hi | T1574.006 | process.inventory |
| RM-PROC-0010 | `rwx`/unbacked-exec memory regions (injection/unpacker) | Med | Md | T1055 | process.inventory |
| RM-PROC-0011 | Root process, `ppid==1`, no tty, listening, post-baseline start | Med | Md | T1543 | process+socket |
| RM-PROC-0012 | Non-root process holding CAP_SYS_MODULE/PTRACE/SYS_ADMIN/BPF | Med | Md | T1548 | process.inventory |
| RM-PROC-0013 | Process chrooted/cwd into suspicious dir | Med | Md | T1059 | process.inventory |
| RM-PROC-0014 | High-entropy process image (packed) — see RM-FILE-0002 on exe | High | Md | T1027.002 | entropy(mem) |
| RM-PROC-0015 | euid=0 with ruid≠0 outside known SUID helpers (active elevation) | High | Md | T1548.001 | process.inventory |
| RM-PROC-0016 | Root process exe under `/tmp`/`/dev/shm`/`/home` (exec→elevate aftermath) | High | Md | T1068 | process.inventory |
| RM-PROC-0017 | Privileged shell `bash`/`sh -p` as root (SUID shell abuse) | Crit | Hi | T1548.001 | process.inventory |
| RM-PROC-0018 | GTFOBins binary with euid=0 / ruid≠0 (`find`, `python`, …) | High | Hi | T1548.001 | process.inventory |
| RM-PROC-0019 | Elevated Python from staging cwd | High | Md | T1068 | process.inventory |

## File (RM-FILE)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-FILE-0001 | High whole-file entropy ELF (>7.2) in sensitive/suspicious path | High | Md | T1027.002 | entropy+elf |
| RM-FILE-0002 | Packer fingerprint (UPX/section anomalies/rwx segment) | High | Hi | T1027.002 | file.elf |
| RM-FILE-0003 | High-entropy window inside otherwise-normal binary (appended payload) | High | Md | T1027 | entropy |
| RM-FILE-0004 | System binary hash ≠ package DB (trojaned coreutils/sshd/sudo) | Crit | Hi | T1554 | file.integrity |
| RM-FILE-0005 | Setuid/setgid root binary inventory (opt-in; noisy) | Low | Hi | T1548.001 | file.ioc |
| RM-FILE-0006 | Setuid binary in staging/non-standard path | High | Hi | T1548.001 | file.ioc |
| RM-FILE-0007 | Known-malicious hash (IOC feed) | Crit | Hi | — | file.ioc |
| RM-FILE-0008 | Known rootkit path present | High | Hi | T1014 | file.ioc |
| RM-FILE-0009 | ELF file in `/tmp`/`/dev/shm` | Med | Md | T1105 | fs.anomaly |
| RM-FILE-0010 | Regular file masquerading as device node under `/dev` | High | Hi | T1014 | fs.anomaly |
| RM-FILE-0011 | Immutable flag on file in writable malware path | Med | Md | T1222 | fs.anomaly |
| RM-FILE-0012 | Timestomp: btime>mtime or ctime≫mtime vs siblings | Med | Md | T1070.006 | fs.anomaly |
| RM-FILE-0013 | Interpreter path (`PT_INTERP`) outside `/lib`,`/usr/lib` | High | Md | T1574 | file.elf |
| RM-FILE-0014 | String IOC (C2 domain/wallet/loader) in flagged file | High | Md | — | file.ioc |
| RM-FILE-0015 | GTFOBins binary with setuid bit (`find`, `bash`, `python`, …) | Crit | Hi | T1548.001 | file.ioc |

## User (RM-USER)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-USER-0001 | UID 0 account other than `root` | Crit | Hi | T1136 | persistence.accounts |
| RM-USER-0002 | Passwordless account (empty shadow hash) with valid shell | Crit | Hi | T1078 | persistence.accounts |
| RM-USER-0003 | Service account given an interactive shell | High | Md | T1136 | persistence.accounts |
| RM-USER-0004 | New account vs baseline | Med | Md | T1136 | drift |
| RM-USER-0005 | `sudoers` NOPASSWD:ALL / wildcard / non-admin→root | High | Hi | T1548.003 | persistence.services(PAM/sudo) |
| RM-USER-0006 | `!authenticate` or unsafe sudoers directive | High | Md | T1548.003 | persistence |
| RM-USER-0007 | Unexpected member of sudo/wheel/docker/lxd | High | Md | T1078 | persistence.accounts |
| RM-USER-0008 | New/unknown `authorized_keys` entry | High | Md | T1098.004 | ssh.keys |
| RM-USER-0009 | authorized_keys with `command=` spawning shell / no `from=` | Med | Md | T1098.004 | ssh.keys |
| RM-USER-0010 | Root `.bash_history` empty/symlinked to /dev/null | Med | Md | T1070.003 | log.integrity |
| RM-USER-0011 | Injected PAM module (unknown `.so`, `pam_exec` backdoor) | Crit | Hi | T1556.003 | persistence.services |
| RM-USER-0012 | passwd/shadow mismatch (account in one not other) | Med | Md | T1136 | persistence.accounts |

## Credential audit (RM-CRED)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-CRED-0001 | Weak hash scheme (DES/MD5-crypt/unsalted) in use | High | Hi | T1110 | cred.audit |
| RM-CRED-0002 | Duplicate password hash across accounts | Med | Md | T1110 | cred.audit |
| RM-CRED-0003 | Account should be locked but has usable hash | Med | Md | T1078 | cred.audit |
| RM-CRED-0004 | Weak password recovered by bounded offline audit (opt-in) | High | Hi | T1110 | cred.audit |
| RM-CRED-0005 | Weak/deprecated SSH key (RSA<2048, DSA) | Med | Md | T1110 | ssh.keys |

## Directory (RM-DIR)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-DIR-0001 | Directory link-count > listed subdir count (hidden subdir) | High | Hi | T1014 | dir.hidden |
| RM-DIR-0002 | getdents byte-sum vs entry-count mismatch (magic-prefix hiding) | High | Hi | T1014 | dir.hidden |
| RM-DIR-0003 | Dotdir stash in `/`,`/dev`,`/tmp`,`/var/tmp`,`/dev/shm` | Med | Md | T1564.001 | dir.hidden |
| RM-DIR-0004 | Dir name with control/space/unicode trick | Med | Md | T1564 | dir.hidden |
| RM-DIR-0005 | File referenced by process exe/fd but absent from parent listing | Crit | Hi | T1014 | dir.hidden+process |

## Log (RM-LOG)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-LOG-0001 | wtmp/utmp zeroed or out-of-order records (log wiping) | High | Hi | T1070.002 | log.integrity |
| RM-LOG-0002 | Log file NUL holes / selective deletion | High | Md | T1070.002 | log.integrity |
| RM-LOG-0003 | Log size dropped sharply vs baseline | Med | Md | T1070.002 | drift+log |
| RM-LOG-0004 | Expected log file missing | High | Md | T1070.002 | log.integrity |
| RM-LOG-0005 | Append-only flag removed from a log | Med | Md | T1222 | log.integrity |
| RM-LOG-0006 | journald journal truncated / sequence gap | High | Md | T1070.002 | log.integrity |
| RM-LOG-0007 | HISTFILE=/dev/null on live root process | Med | Md | T1070.003 | process.inventory |

## Persistence — scheduled/services (RM-PERSIST)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-PERSIST-0001 | `/etc/ld.so.preload` present / lists suspicious lib | Crit | Hi | T1574.006 | persistence.preload |
| RM-PERSIST-0002 | Injected dir in ld.so.conf.d | High | Md | T1574 | persistence.preload |
| RM-PERSIST-0003 | Cron fetch-exec (`curl|sh`, base64, /tmp path) | High | Hi | T1053.003 | persistence.scheduled |
| RM-PERSIST-0004 | `@reboot` / new cron vs baseline | Med | Md | T1053.003 | persistence.scheduled |
| RM-PERSIST-0005 | systemd unit ExecStart in `/tmp`/`/dev/shm` | High | Hi | T1543.002 | persistence.services |
| RM-PERSIST-0006 | systemd drop-in altering legit service | High | Md | T1543.002 | persistence.services |
| RM-PERSIST-0007 | udev rule with `RUN+=` payload | High | Md | T1547 | persistence.services |
| RM-PERSIST-0008 | init.d/rc script not owned by a package | Med | Md | T1037 | persistence.services |
| RM-PERSIST-0009 | Shell rc / profile.d exports LD_* or fetch-exec | High | Md | T1546.004 | persistence.preload |
| RM-PERSIST-0010 | D-Bus service Exec to suspicious path | Med | Md | T1543 | persistence.services |
| RM-PERSIST-0011 | NSS module anomaly (nsswitch + libnss_*) | High | Md | T1556 | persistence.services |
| RM-PERSIST-0012 | at-job persistence | Med | Md | T1053.002 | persistence.scheduled |

## Kernel — modules/eBPF (RM-KERN)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-KERN-0001 | Hidden module: `/sys/module` vs `/proc/modules` mismatch | Crit | Hi | T1014 | modules.lkm |
| RM-KERN-0002 | Unsigned/out-of-tree module newly loaded (taint E/O) | High | Md | T1547.006 | modules.lkm |
| RM-KERN-0003 | Kernel taint transition vs baseline | Med | Md | T1014 | modules.lkm |
| RM-KERN-0004 | Known rootkit module name/symbol match | Crit | Hi | T1014 | modules.lkm |
| RM-KERN-0005 | Module hooking syscall table (where observable) | Crit | Hi | T1014 | modules.lkm |
| RM-KERN-0006 | Orphan eBPF prog (kernel-listed, unowned) of hooking type | Crit | Hi | T1014 | ebpf |
| RM-KERN-0007 | eBPF kprobe on getdents/tcp seq_show/etc (hiding hooks) | Crit | Hi | T1014 | ebpf |
| RM-KERN-0008 | XDP/tc program on interface not in baseline | High | Md | T1205 | ebpf |
| RM-KERN-0009 | Unexpected kprobe/uprobe in tracefs | High | Md | T1014 | ebpf |

## Network (RM-NET)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-NET-0001 | Hidden socket: sock_diag vs `/proc/net` mismatch | Crit | Hi | T1014 | decloak.socket |
| RM-NET-0002 | Listener owned by no visible PID (hidden-proc backdoor; root fd-walk only) | Crit | Hi | T1014 | net.sockets |
| RM-NET-0003 | Unexpected listening port vs allow-baseline | High | Md | T1571 | net.sockets |
| RM-NET-0004 | Established egress from shell/`/tmp` binary to external IP | High | Md | T1071 | net.sockets |
| RM-NET-0005 | Raw/packet socket owned by non-standard process (sniffer) | High | Md | T1040 | net.sockets |
| RM-NET-0006 | Interface in promiscuous mode | Med | Md | T1040 | net.sockets |

## Mount / container (RM-MNT, RM-CONT)

| ID | Check | S | C | ATT&CK | Collector |
|---|---|---|---|---|---|
| RM-MNT-0001 | Bind-mount over `/proc/<pid>` (process hiding) | Crit | Hi | T1564 | mount.anomaly |
| RM-MNT-0002 | Bind/overlay mount over a log or system binary | High | Md | T1564 | mount.anomaly |
| RM-MNT-0003 | New mount vs baseline | Low | Md | T1564 | drift |
| RM-CONT-0001 | Container escape indicator (host ns from container, docker.sock mounted) | Crit | Md | T1611 | container.escape |
| RM-CONT-0002 | Privileged container with host devices | High | Md | T1610 | container.escape |

## Policy / posture (RM-POL) — opt-in + platform-health

| ID | Check | S | C | Note |
|---|---|---|---|---|
| RM-POL-0001 | **SSH host key changed** since pinning | Crit | Hi | platform, always on |
| RM-POL-0002 | Host resisting inspection (3× probe crash/deliver-fail) | High | Md | platform |
| RM-POL-0020 | SSH weak KEX/cipher/host-key algo in use | Med | Hi | posture |
| RM-POL-0021 | Full-fidelity probe could not run (Method D degrade) | Med | Md | platform |
| RM-POL-0022 | Check applicability regressed (host exposing less) | Med | Md | platform |
| RM-POL-0023 | Observation flood (host emitted > cap) | Med | Md | platform |
| RM-POL-0030 | sshd_config: PermitRootLogin yes / PasswordAuth on | Med | Hi | posture |
| RM-POL-0031 | sysctl regression (randomize_va_space, kptr_restrict, dmesg_restrict, unprivileged_bpf_disabled) | Med | Hi | posture/drift |
| RM-POL-0032 | World-writable file in `$PATH` | Med | Md | posture |
| RM-POL-0033 | Firewall ruleset changed vs baseline | Low | Md | drift |

## Drift (RM-DRIFT)

| ID | Check | S | C | Note |
|---|---|---|---|---|
| RM-DRIFT-0001 | Critical-file hash changed without package event | High | Hi | file.integrity+drift |
| RM-DRIFT-0002 | Listening-port set changed vs baseline | Med | Md | drift |
| RM-DRIFT-0003 | Kernel-module set changed vs baseline | Med | Md | drift |
| RM-DRIFT-0004 | Account/SSH-key set changed vs baseline | Med | Md | drift |

## Correlation / incidents (RM-INC) — checks over findings (`05` §7)

| ID | Rule | Result |
|---|---|---|
| RM-INC-0001 | hidden process (RM-PROC-0001) + hidden port owned by it (RM-NET-0002) + high-entropy exe (RM-FILE-0002) | **Active rootkit** incident, Crit/Hi |
| RM-INC-0002 | ld.so.preload (RM-PERSIST-0001) + LD_PRELOAD on live proc (RM-PROC-0009) | **Userland rootkit** incident, Crit |
| RM-INC-0003 | log wiping (RM-LOG-0001) + new account (RM-USER-0004) + external egress (RM-NET-0004) | **Post-exploitation** incident |
| RM-INC-0004 | stolen-key placement (cross-host key, RM-USER-0008) + new login source | **Lateral movement** incident |

## Recon (RM-RECON) — no alerts, SIEM feed only
OS/kernel/arch, packages, services, users, modules, interfaces, mounts, containers, cloud metadata → structured inventory (`06` §22).

---

**Catalog growth path.** The seed above is ~120 checks. The expression engine + these collectors support easily 10× more by parameterising paths/IOCs/baselines per environment. Prioritise, in order: rootkit decloaks (highest signal, lowest FP), persistence, integrity/drift, then posture (noisiest, most environment-specific — ship disabled).

**Linux LPE (Elastic framework).** Snapshot-adapted rules: `RM-PROC-0012`/`0015`–`0019`, `RM-FILE-0005`/`0006`/`0015`. Sequence-based EDR rules (exec→uid_change, unshare→root) remain post-1.0 — see `06` §14.1 and `13` backlog.
