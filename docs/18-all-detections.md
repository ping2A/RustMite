# RustMite — Complete Detection Catalog

> Auto-generated from `checks/*.toml` on 2026-09-17.
> **70** check manifests. Regenerate: `python3 scripts/gen-detections-md.py`.

Source of truth for operators and LLM agents. Seed overview also in [`11-detection-catalog.md`](11-detection-catalog.md); module algorithms in [`06-detection-modules.md`](06-detection-modules.md).

## Summary

| Type | Count | Enabled |
|---|---:|---:|
| Process (RM-PROC) | 17 | 16 |
| File (RM-FILE) | 21 | 20 |
| User / credentials (RM-USER, RM-CRED) | 12 | 9 |
| Directory (RM-DIR) | 4 | 4 |
| Log (RM-LOG) | 4 | 4 |
| Policy (RM-POL) | 3 | 2 |
| Incident / correlation (RM-INC) | 9 | 7 |
| **Total** | **70** | **62** |

## Index

- [✓] [`RM-CRED-0001`](#rm-cred-0001) — Weak password hash algorithm
- [○] [`RM-CRED-0002`](#rm-cred-0002) — Duplicate password hash across accounts
- [✓] [`RM-CRED-0003`](#rm-cred-0003) — Account should be locked but password usable
- [✓] [`RM-CRED-0005`](#rm-cred-0005) — Weak or deprecated SSH key type
- [✓] [`RM-DIR-0001`](#rm-dir-0001) — Directory link-count mismatch (hidden subdir)
- [✓] [`RM-DIR-0002`](#rm-dir-0002) — getdents byte-sum mismatch
- [✓] [`RM-DIR-0003`](#rm-dir-0003) — Dotdir stash in sensitive mountpoint
- [✓] [`RM-DIR-0005`](#rm-dir-0005) — Open file absent from directory listing
- [✓] [`RM-DRIFT-0001`](#rm-drift-0001) — Critical-file hash changed without package event
- [✓] [`RM-FILE-0001`](#rm-file-0001) — High whole-file entropy ELF in suspicious path
- [✓] [`RM-FILE-0002`](#rm-file-0002) — Packer fingerprint / RWX segment
- [✓] [`RM-FILE-0003`](#rm-file-0003) — High-entropy window inside binary
- [✓] [`RM-FILE-0004`](#rm-file-0004) — System binary hash mismatch vs package DB
- [○] [`RM-FILE-0005`](#rm-file-0005) — Setuid/setgid root binary (inventory)
- [✓] [`RM-FILE-0006`](#rm-file-0006) — Setuid binary in non-standard or staging path
- [✓] [`RM-FILE-0007`](#rm-file-0007) — Known-malicious hash (IOC feed)
- [✓] [`RM-FILE-0008`](#rm-file-0008) — Known rootkit path present
- [✓] [`RM-FILE-0009`](#rm-file-0009) — ELF file in world-writable staging path
- [✓] [`RM-FILE-0010`](#rm-file-0010) — Regular file masquerading under /dev
- [✓] [`RM-FILE-0011`](#rm-file-0011) — Immutable flag on file in malware staging path
- [✓] [`RM-FILE-0012`](#rm-file-0012) — Timestomp indicator (btime after mtime)
- [✓] [`RM-FILE-0013`](#rm-file-0013) — Non-standard ELF interpreter path
- [✓] [`RM-FILE-0014`](#rm-file-0014) — String IOC in flagged file
- [✓] [`RM-FILE-0015`](#rm-file-0015) — GTFOBins binary with setuid bit
- [○] [`RM-INC-0004`](#rm-inc-0004) — Stolen SSH key placement across hosts
- [✓] [`RM-KERN-0001`](#rm-kern-0001) — Hidden kernel module (/sys/module vs /proc/modules)
- [✓] [`RM-KERN-0002`](#rm-kern-0002) — Unsigned or out-of-tree kernel module loaded
- [✓] [`RM-KERN-0004`](#rm-kern-0004) — Known rootkit module name
- [✓] [`RM-KERN-0006`](#rm-kern-0006) — Orphan eBPF program of hooking type
- [✓] [`RM-LOG-0001`](#rm-log-0001) — wtmp/utmp wiped or out-of-order
- [✓] [`RM-LOG-0002`](#rm-log-0002) — Log file NUL holes or selective deletion
- [✓] [`RM-LOG-0004`](#rm-log-0004) — Expected log file missing
- [✓] [`RM-LOG-0007`](#rm-log-0007) — HISTFILE=/dev/null on live process
- [✓] [`RM-NET-0001`](#rm-net-0001) — Hidden socket (sock_diag vs /proc/net mismatch)
- [✓] [`RM-NET-0002`](#rm-net-0002) — Listener with no visible owning PID
- [○] [`RM-NET-0003`](#rm-net-0003) — Unexpected listening socket
- [✓] [`RM-NET-0005`](#rm-net-0005) — Raw or packet socket owned by non-standard process
- [✓] [`RM-PERSIST-0001`](#rm-persist-0001) — ld.so.preload present
- [✓] [`RM-PERSIST-0002`](#rm-persist-0002) — Injected directory in ld.so configuration
- [✓] [`RM-PERSIST-0003`](#rm-persist-0003) — Cron fetch-and-exec pattern
- [✓] [`RM-PERSIST-0005`](#rm-persist-0005) — systemd ExecStart in staging path
- [✓] [`RM-PERSIST-0009`](#rm-persist-0009) — Shell profile exports LD_* or fetch-exec
- [✓] [`RM-POL-0001`](#rm-pol-0001) — SSH host key changed since pinning
- [✓] [`RM-POL-0021`](#rm-pol-0021) — Degraded inspection (pure-command fallback)
- [○] [`RM-POL-0032`](#rm-pol-0032) — World-writable file in PATH
- [✓] [`RM-PROC-0001`](#rm-proc-0001) — Hidden process (multi-source, confirmed)
- [✓] [`RM-PROC-0002`](#rm-proc-0002) — Hidden process (single-source, unconfirmed)
- [✓] [`RM-PROC-0004`](#rm-proc-0004) — Process running deleted executable
- [✓] [`RM-PROC-0005`](#rm-proc-0005) — Fileless execution via memfd/anon_inode
- [✓] [`RM-PROC-0006`](#rm-proc-0006) — Process comm/exe masquerade mismatch
- [✓] [`RM-PROC-0007`](#rm-proc-0007) — Fake kernel thread (bracketed comm with real exe)
- [✓] [`RM-PROC-0008`](#rm-proc-0008) — Executable running from staging directory
- [✓] [`RM-PROC-0009`](#rm-proc-0009) — Live process with LD_PRELOAD or LD_AUDIT
- [✓] [`RM-PROC-0010`](#rm-proc-0010) — Unbacked executable memory regions
- [○] [`RM-PROC-0011`](#rm-proc-0011) — Root daemon listening without TTY
- [✓] [`RM-PROC-0012`](#rm-proc-0012) — Non-root process holding dangerous capabilities
- [✓] [`RM-PROC-0013`](#rm-proc-0013) — Process cwd in suspicious directory
- [✓] [`RM-PROC-0015`](#rm-proc-0015) — Effective root with non-root real UID (SUID/helper elevation)
- [✓] [`RM-PROC-0016`](#rm-proc-0016) — Root process executing from writable staging path
- [✓] [`RM-PROC-0017`](#rm-proc-0017) — Privileged-mode shell (bash/sh -p) as root
- [✓] [`RM-PROC-0018`](#rm-proc-0018) — GTFOBins-style binary elevated (euid 0, ruid non-0)
- [✓] [`RM-PROC-0019`](#rm-proc-0019) — Python interpreter elevated to root from staging cwd
- [✓] [`RM-USER-0001`](#rm-user-0001) — UID 0 account other than root
- [✓] [`RM-USER-0002`](#rm-user-0002) — Passwordless account (empty shadow hash)
- [✓] [`RM-USER-0003`](#rm-user-0003) — Service account with interactive shell
- [○] [`RM-USER-0004`](#rm-user-0004) — New account vs baseline
- [✓] [`RM-USER-0005`](#rm-user-0005) — sudoers NOPASSWD ALL
- [✓] [`RM-USER-0006`](#rm-user-0006) — Unsafe sudoers directive
- [○] [`RM-USER-0008`](#rm-user-0008) — New or unknown authorized_keys entry
- [✓] [`RM-USER-0009`](#rm-user-0009) — authorized_keys forced command spawns shell

## Process (RM-PROC)

### RM-PROC-0001

| | |
|---|---|
| **Name** | Hidden process (multi-source, confirmed) |
| **File** | [`checks/RM-PROC-0001.toml`](../checks/RM-PROC-0001.toml) |
| **Type** | `process` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `hidden_process` |
| **ATT&CK** | T1014 |

**Title:** Hidden process pid {{hidden_process.pid}} (kernel-present, /proc-absent)

**Rationale:** Process visible to kernel PID probes but absent from /proc listing across ≥2 confirmation passes.

**False positives:** Transient PID reuse races if passes_confirmed is low; require ≥2.

```
hidden_process.passes_confirmed >= 2
```

### RM-PROC-0002

| | |
|---|---|
| **Name** | Hidden process (single-source, unconfirmed) |
| **File** | [`checks/RM-PROC-0002.toml`](../checks/RM-PROC-0002.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `hidden_process` |
| **ATT&CK** | T1014 |

**Title:** Unconfirmed hidden process pid {{hidden_process.pid}} (needs review)

**Rationale:** Process visible to one decloak source but not yet confirmed across multiple passes.

```
hidden_process.passes_confirmed == 1
```

### RM-PROC-0004

| | |
|---|---|
| **Name** | Process running deleted executable |
| **File** | [`checks/RM-PROC-0004.toml`](../checks/RM-PROC-0004.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1070.004 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) running deleted executable

**Rationale:** An exe symlink ending in (deleted) indicates the binary was removed after exec — common for fileless/malware staging.

```
process.exe_deleted == true
  or (process.exe != null and process.exe contains "(deleted)")
```

### RM-PROC-0005

| | |
|---|---|
| **Name** | Fileless execution via memfd/anon_inode |
| **File** | [`checks/RM-PROC-0005.toml`](../checks/RM-PROC-0005.toml) |
| **Type** | `process` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1620 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) executing from memfd/anon_inode

**Rationale:** Executable backed by memfd or anon_inode is a strong fileless-execution signal.

```
process.exe_memfd == true
```

### RM-PROC-0006

| | |
|---|---|
| **Name** | Process comm/exe masquerade mismatch |
| **File** | [`checks/RM-PROC-0006.toml`](../checks/RM-PROC-0006.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1036 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) comm does not match exe basename

**Rationale:** Comm diverging from exe basename outside trusted system paths may indicate masquerading. Ignores TASK_COMM_LEN truncation, systemd '(name)' comms, interpreter wrappers, and reverse-prefix renames (e.g. pipewire-pulse).

```
process.exe != null
  and process.exe != ""
  and process.comm != process.exe.basename()
  and not process.comm matches "^\\[.*\\]$"
  and not process.comm matches "^\\(.*\\)$"
  and not (
    process.comm.len() == 15
    and process.exe.basename() starts_with process.comm
  )
  and not (process.comm starts_with process.exe.basename())
  and not (
    process.exe.basename() starts_with "python"
    or process.exe.basename() starts_with "java"
    or process.exe.basename() starts_with "gjs"
    or process.exe.basename() starts_with "node"
    or process.exe.basename() starts_with "ruby"
    or process.exe.basename() starts_with "perl"
    or process.exe.basename() starts_with "php"
  )
  and not (
    process.exe.path_under("/usr")
    or process.exe.path_under("/lib")
    or process.exe.path_under("/bin")
    or process.exe.path_under("/sbin")
    or process.exe.path_under("/snap")
  )
```

### RM-PROC-0007

| | |
|---|---|
| **Name** | Fake kernel thread (bracketed comm with real exe) |
| **File** | [`checks/RM-PROC-0007.toml`](../checks/RM-PROC-0007.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1014, T1036 |

**Title:** Process '{{process.comm}}' masquerades as a kernel thread

**Rationale:** Real kernel threads have no exe link. A bracketed comm with a backing executable indicates a userland process disguising itself.

**False positives:** None known on standard distros. Some embedded init systems spawn bracketed userland helpers; allowlist if confirmed benign.

```
process.comm matches "^\[.*\]$"
  and process.exe != null
  and process.exe != ""
```

### RM-PROC-0008

| | |
|---|---|
| **Name** | Executable running from staging directory |
| **File** | [`checks/RM-PROC-0008.toml`](../checks/RM-PROC-0008.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1059 |

**Title:** Process '{{process.comm}}' executing from {{process.exe}}

**Rationale:** Long-lived processes executing directly from world-writable staging paths are uncommon on servers.

```
process.exe != null
  and (
    process.exe.path_under("/tmp")
    or process.exe.path_under("/dev/shm")
    or process.exe.path_under("/var/tmp")
    or process.exe.path_under("/home/")
  )
```

### RM-PROC-0009

| | |
|---|---|
| **Name** | Live process with LD_PRELOAD or LD_AUDIT |
| **File** | [`checks/RM-PROC-0009.toml`](../checks/RM-PROC-0009.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1574.006 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) has LD_PRELOAD/LD_AUDIT in environment

**Rationale:** LD_PRELOAD/LD_AUDIT on a live process is a strong userland hooking signal.

```
process.environ_flags contains "LD_PRELOAD"
  or process.environ_flags contains "LD_AUDIT"
```

### RM-PROC-0010

| | |
|---|---|
| **Name** | Unbacked executable memory regions |
| **File** | [`checks/RM-PROC-0010.toml`](../checks/RM-PROC-0010.toml) |
| **Type** | `process` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1055 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) has unbacked executable mappings

**Rationale:** Unbacked executable mappings are a stronger injection/shellcode signal than RWX alone (JIT runtimes like gnome-shell/java/gjs commonly have RWX).

```
process.unbacked_exec > 0
```

### RM-PROC-0011

| | |
|---|---|
| **Name** | Root daemon listening without TTY |
| **File** | [`checks/RM-PROC-0011.toml`](../checks/RM-PROC-0011.toml) |
| **Type** | `process` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory`, `net.sockets` |
| **ATT&CK** | T1543 |

**Title:** Root process '{{process.comm}}' (pid {{process.pid}}) listening without controlling TTY

**Rationale:** Disabled until listener baselines exist — sshd/cupsd/tailscaled/etc. always match on a normal host.

```
process.uid == 0
  and process.ppid == 1
  and process.tty == 0
  and process.listen_ports.len() > 0
```

### RM-PROC-0012

| | |
|---|---|
| **Name** | Non-root process holding dangerous capabilities |
| **File** | [`checks/RM-PROC-0012.toml`](../checks/RM-PROC-0012.toml) |
| **Type** | `process` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1548 |

**Title:** Non-root process '{{process.comm}}' (pid {{process.pid}}) holds dangerous capabilities

**Rationale:** CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_ADMIN, or CAP_BPF on a non-root process enables local privilege escalation. Snapshot of Elastic LPE capability posture.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
process.euid != 0
  and process.dangerous_caps == true
```

### RM-PROC-0013

| | |
|---|---|
| **Name** | Process cwd in suspicious directory |
| **File** | [`checks/RM-PROC-0013.toml`](../checks/RM-PROC-0013.toml) |
| **Type** | `process` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1059 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) cwd {{process.cwd}}

**Rationale:** Processes with working directories under staging paths are often dropper shells or malware.

```
process.cwd != null
  and (
    process.cwd.path_under("/tmp")
    or process.cwd.path_under("/dev/shm")
    or process.cwd.path_under("/var/tmp")
  )
```

### RM-PROC-0015

| | |
|---|---|
| **Name** | Effective root with non-root real UID (SUID/helper elevation) |
| **File** | [`checks/RM-PROC-0015.toml`](../checks/RM-PROC-0015.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1548.001 |

**Title:** Process '{{process.comm}}' running as euid 0 with ruid {{process.ruid}} (active privilege elevation)

**Rationale:** Elastic LPE framework: euid=0 with ruid≠0 is the SUID/SGID helper privilege shape. Excludes common distro helpers; remaining hits are uncommon SUID abuse or post-exploit elevation visible in a snapshot.

**False positives:** Legitimate uncommon setuid helpers (vendor agents). Allowlist by process.exe if confirmed.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
process.euid == 0
  and process.ruid != 0
  and not (
    process.comm == "sudo"
    or process.comm == "su"
    or process.comm == "pkexec"
    or process.comm == "passwd"
    or process.comm == "chpasswd"
    or process.comm == "unix_chkpwd"
    or process.comm == "sudoedit"
    or process.comm == "newuidmap"
    or process.comm == "newgidmap"
    or process.comm == "mount"
    or process.comm == "umount"
    or process.comm == "fusermount"
    or process.comm == "fusermount3"
    or process.comm == "polkit-agent-helper-1"
    or process.comm == "dbus-daemon-lau"
    or process.comm == "ssh-keysign"
    or process.comm == "snap-confine"
    or process.comm == "crontab"
    or process.comm == "chage"
    or process.comm == "chfn"
    or process.comm == "chsh"
    or process.comm == "gpasswd"
    or process.comm == "newgrp"
  )
```

### RM-PROC-0016

| | |
|---|---|
| **Name** | Root process executing from writable staging path |
| **File** | [`checks/RM-PROC-0016.toml`](../checks/RM-PROC-0016.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1068, T1059 |

**Title:** Root process '{{process.comm}}' executing from staging path {{process.exe}}

**Rationale:** Elastic exec-then-elevate aftermath: kernel/userland LPE PoCs often leave a root shell or payload running from /tmp, /dev/shm, or a home directory. Snapshot cannot see uid_change events, but a live root exe from a writable path is high signal.

**False positives:** Rare installer/bootstrap jobs. Prefer short TTL or allowlist.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
process.euid == 0
  and process.exe != null
  and (
    process.exe.path_under("/tmp")
    or process.exe.path_under("/dev/shm")
    or process.exe.path_under("/var/tmp")
    or process.exe.path_under("/run/user/")
    or process.exe.path_under("/home/")
  )
```

### RM-PROC-0017

| | |
|---|---|
| **Name** | Privileged-mode shell (bash/sh -p) as root |
| **File** | [`checks/RM-PROC-0017.toml`](../checks/RM-PROC-0017.toml) |
| **Type** | `process` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1548.001 |

**Title:** Privileged shell '{{process.comm}}' (pid {{process.pid}}) with -p — likely SUID shell abuse

**Rationale:** Elastic SUID misconfiguration case: bash/sh -p keeps effective privileges after setuid. Classic GTFOBins privileged-shell pattern.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
- https://gtfobins.github.io/gtfobins/bash/

```
process.euid == 0
  and (
    process.comm == "bash"
    or process.comm == "sh"
    or process.comm == "dash"
    or process.comm == "zsh"
  )
  and (
    process.cmdline contains "-p"
    or process.cmdline contains " -p"
  )
```

### RM-PROC-0018

| | |
|---|---|
| **Name** | GTFOBins-style binary elevated (euid 0, ruid non-0) |
| **File** | [`checks/RM-PROC-0018.toml`](../checks/RM-PROC-0018.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1548.001 |

**Title:** GTFOBins binary '{{process.comm}}' elevated (euid 0 / ruid {{process.ruid}})

**Rationale:** Elastic GTFOBins abuse detection adapted to snapshots: known dual-use binaries should not run with the SUID privilege shape. Covers find -exec root shells and similar misconfigurations.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
- https://gtfobins.github.io/

```
process.euid == 0
  and process.ruid != 0
  and (
    process.comm == "find"
    or process.comm == "nmap"
    or process.comm == "vim"
    or process.comm == "vi"
    or process.comm == "nano"
    or process.comm == "python"
    or process.comm == "python3"
    or process.comm == "perl"
    or process.comm == "ruby"
    or process.comm == "lua"
    or process.comm == "awk"
    or process.comm == "less"
    or process.comm == "more"
    or process.comm == "man"
    or process.comm == "env"
    or process.comm == "bash"
    or process.comm == "dash"
    or process.comm == "cp"
    or process.comm == "tar"
    or process.comm == "zip"
    or process.comm == "gdb"
    or process.comm == "strace"
    or process.comm == "tcpdump"
    or process.comm == "docker"
    or process.comm == "podman"
    or process.comm == "nsenter"
    or process.comm == "unshare"
  )
```

### RM-PROC-0019

| | |
|---|---|
| **Name** | Python interpreter elevated to root from staging cwd |
| **File** | [`checks/RM-PROC-0019.toml`](../checks/RM-PROC-0019.toml) |
| **Type** | `process` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **Collectors** | `process.inventory` |
| **ATT&CK** | T1068, T1059.006 |

**Title:** Python '{{process.comm}}' elevated from staging cwd {{process.cwd}}

**Rationale:** Elastic 'Suspicious UID Change to Root via Python' — many 2026 LPE PoCs finish as Python. Snapshot sees elevated python with staging cwd rather than uid_change events.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
process.euid == 0
  and process.ruid != 0
  and (
    process.comm starts_with "python"
    or process.comm == "python"
    or process.comm == "python3"
  )
  and process.cwd != null
  and (
    process.cwd.path_under("/tmp")
    or process.cwd.path_under("/var/tmp")
    or process.cwd.path_under("/dev/shm")
    or process.cwd.path_under("/home/")
    or process.cwd.path_under("/run/user/")
    or process.cwd.path_under("/var/www")
  )
```

## File (RM-FILE)

### RM-DRIFT-0001

| | |
|---|---|
| **Name** | Critical-file hash changed without package event |
| **File** | [`checks/RM-DRIFT-0001.toml`](../checks/RM-DRIFT-0001.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `integrity_mismatch` |
| **Collectors** | `file.integrity` |
| **ATT&CK** | T1554 |

**Title:** Critical file drift / integrity mismatch for {{integrity_mismatch.path}}

**Rationale:** Baseline and package-DB diffs both surface as integrity_mismatch; package-attributed changes are downgraded server-side.

```
integrity_mismatch.expected_hash != integrity_mismatch.actual_hash
```

### RM-FILE-0001

| | |
|---|---|
| **Name** | High whole-file entropy ELF in suspicious path |
| **File** | [`checks/RM-FILE-0001.toml`](../checks/RM-FILE-0001.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `file_entropy` |
| **ATT&CK** | T1027.002 |

**Title:** High-entropy ELF at {{file_entropy.path}} (entropy {{file_entropy.entropy}})

**Rationale:** Packed or encrypted ELF payloads often show Shannon entropy above ~7.2.

```
file_entropy.entropy > 7.2
  and file_entropy.is_elf == true
  and (
    file_entropy.path.path_under("/tmp")
    or file_entropy.path.path_under("/dev/shm")
    or file_entropy.path.path_under("/var/tmp")
    or file_entropy.path.path_under("/home")
  )
```

### RM-FILE-0002

| | |
|---|---|
| **Name** | Packer fingerprint / RWX segment |
| **File** | [`checks/RM-FILE-0002.toml`](../checks/RM-FILE-0002.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `elf_info` |
| **ATT&CK** | T1027.002 |

**Title:** Packed or anomalous ELF at {{elf_info.path}}

**Rationale:** RWX segments and known packer section/name fingerprints indicate packed malware.

```
elf_info.has_rwx_segment == true
  or elf_info.packer_hints_joined contains "upx"
  or elf_info.packer_hints contains "UPX"
```

### RM-FILE-0003

| | |
|---|---|
| **Name** | High-entropy window inside binary |
| **File** | [`checks/RM-FILE-0003.toml`](../checks/RM-FILE-0003.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `file_entropy` |
| **ATT&CK** | T1027 |

**Title:** High-entropy payload window in {{file_entropy.path}} (peak {{file_entropy.window_max}})

**Rationale:** Localized high-entropy regions inside an otherwise normal binary may indicate appended encrypted payloads.

```
file_entropy.window_max != null
  and file_entropy.window_max > 7.0
```

### RM-FILE-0004

| | |
|---|---|
| **Name** | System binary hash mismatch vs package DB |
| **File** | [`checks/RM-FILE-0004.toml`](../checks/RM-FILE-0004.toml) |
| **Type** | `file` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `integrity_mismatch` |
| **Collectors** | `file.integrity` |
| **ATT&CK** | T1554 |

**Title:** Integrity mismatch for {{integrity_mismatch.path}}

**Rationale:** Package-managed binaries should match the distribution hash; divergence suggests trojaning.

```
integrity_mismatch.expected_hash != integrity_mismatch.actual_hash
```

### RM-FILE-0005

| | |
|---|---|
| **Name** | Setuid/setgid root binary (inventory) |
| **File** | [`checks/RM-FILE-0005.toml`](../checks/RM-FILE-0005.toml) |
| **Type** | `file` |
| **Severity** | low |
| **Confidence** | high |
| **Enabled** | False |
| **Cost** | medium |
| **Match** | `file_meta` |
| **Collectors** | `file.ioc` |
| **ATT&CK** | T1548.001 |

**Title:** Setuid/setgid root binary {{file_meta.path}} (mode {{file_meta.mode}})

**Rationale:** Full setuid inventory for baseline/drift. Disabled by default (fires on every sudo/passwd). Prefer RM-FILE-0006, RM-FILE-0015, and drift once baselines exist.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
(file_meta.setuid == true or file_meta.setgid == true)
  and file_meta.uid == 0
```

### RM-FILE-0006

| | |
|---|---|
| **Name** | Setuid binary in non-standard or staging path |
| **File** | [`checks/RM-FILE-0006.toml`](../checks/RM-FILE-0006.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `file_meta` |
| **Collectors** | `file.ioc` |
| **ATT&CK** | T1548.001 |

**Title:** Setuid binary in suspicious path {{file_meta.path}}

**Rationale:** Elastic SUID misconfiguration class: setuid binaries outside package-managed paths (/bin, /usr/bin, …) are classic LPE footholds (copied bash -p, find, etc.).

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework

```
file_meta.setuid == true
  and (
    file_meta.path.path_under("/tmp")
    or file_meta.path.path_under("/var/tmp")
    or file_meta.path.path_under("/dev/shm")
    or file_meta.path.path_under("/home/")
    or file_meta.path.path_under("/opt")
    or file_meta.path.path_under("/root")
    or file_meta.path.path_under("/var/www")
  )
```

### RM-FILE-0007

| | |
|---|---|
| **Name** | Known-malicious hash (IOC feed) |
| **File** | [`checks/RM-FILE-0007.toml`](../checks/RM-FILE-0007.toml) |
| **Type** | `file` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `ioc_hit` |

**Title:** Known-malicious hash at {{ioc_hit.path}}

**Rationale:** File hash matches a configured malicious IOC feed entry.

```
ioc_hit.ioc_kind == "hash"
```

### RM-FILE-0008

| | |
|---|---|
| **Name** | Known rootkit path present |
| **File** | [`checks/RM-FILE-0008.toml`](../checks/RM-FILE-0008.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `ioc_hit` |
| **Collectors** | `file.ioc` |
| **ATT&CK** | T1014 |

**Title:** Known rootkit/IOC path {{ioc_hit.path}} ({{ioc_hit.ioc_value}})

**Rationale:** Path IOC match from file.ioc collector (known rootkit drop locations).

```
ioc_hit.ioc_kind == "path"
```

### RM-FILE-0009

| | |
|---|---|
| **Name** | ELF file in world-writable staging path |
| **File** | [`checks/RM-FILE-0009.toml`](../checks/RM-FILE-0009.toml) |
| **Type** | `file` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `file_entropy` |
| **ATT&CK** | T1105 |

**Title:** ELF in staging path {{file_entropy.path}}

**Rationale:** ELF binaries dropped under /tmp or /dev/shm are a common staging pattern.

```
file_entropy.is_elf == true
  and (
    file_entropy.path.path_under("/tmp")
    or file_entropy.path.path_under("/dev/shm")
    or file_entropy.path.path_under("/var/tmp")
  )
```

### RM-FILE-0010

| | |
|---|---|
| **Name** | Regular file masquerading under /dev |
| **File** | [`checks/RM-FILE-0010.toml`](../checks/RM-FILE-0010.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `file_meta` |
| **ATT&CK** | T1014 |

**Title:** Large regular file under {{file_meta.path}}

**Rationale:** Oversized regular files directly under /dev may masquerade as device nodes to evade casual inspection.

```
file_meta.path.path_under("/dev/")
  and not file_meta.path.path_under("/dev/shm")
  and file_meta.size > 4096
```

### RM-FILE-0011

| | |
|---|---|
| **Name** | Immutable flag on file in malware staging path |
| **File** | [`checks/RM-FILE-0011.toml`](../checks/RM-FILE-0011.toml) |
| **Type** | `file` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `file_meta` |
| **ATT&CK** | T1222 |

**Title:** Immutable file in staging path {{file_meta.path}}

**Rationale:** Immutable bits on files in writable staging directories may hinder incident cleanup.

```
file_meta.immutable == true
  and (
    file_meta.path.path_under("/tmp")
    or file_meta.path.path_under("/dev/shm")
    or file_meta.path.path_under("/var/tmp")
  )
```

### RM-FILE-0012

| | |
|---|---|
| **Name** | Timestomp indicator (btime after mtime) |
| **File** | [`checks/RM-FILE-0012.toml`](../checks/RM-FILE-0012.toml) |
| **Type** | `file` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `timestomp` |
| **ATT&CK** | T1070.006 |

**Title:** Timestomp suspected on {{timestomp.path}}

**Rationale:** Birth time newer than modification time can indicate timestomping on supported filesystems.

```
timestomp.btime_after_mtime == true
```

### RM-FILE-0013

| | |
|---|---|
| **Name** | Non-standard ELF interpreter path |
| **File** | [`checks/RM-FILE-0013.toml`](../checks/RM-FILE-0013.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `elf_info` |
| **ATT&CK** | T1574 |

**Title:** ELF {{elf_info.path}} uses interpreter {{elf_info.interp}}

**Rationale:** Dynamic linker paths outside standard lib directories may indicate hijacked interpreters.

```
elf_info.interp != null
  and not elf_info.interp.path_under("/lib")
  and not elf_info.interp.path_under("/usr/lib")
```

### RM-FILE-0014

| | |
|---|---|
| **Name** | String IOC in flagged file |
| **File** | [`checks/RM-FILE-0014.toml`](../checks/RM-FILE-0014.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `ioc_hit` |

**Title:** String IOC match in {{ioc_hit.path}} ({{ioc_hit.ioc_value}})

**Rationale:** File content matched a configured string IOC (C2, wallet, loader marker, etc.).

```
ioc_hit.ioc_kind == "string"
```

### RM-FILE-0015

| | |
|---|---|
| **Name** | GTFOBins binary with setuid bit |
| **File** | [`checks/RM-FILE-0015.toml`](../checks/RM-FILE-0015.toml) |
| **Type** | `file` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `file_meta` |
| **Collectors** | `file.ioc` |
| **ATT&CK** | T1548.001 |

**Title:** GTFOBins setuid binary {{file_meta.path}}

**Rationale:** Elastic GTFOBins SUID abuse: find/bash/python/etc. with the setuid bit enable trivial root shells (find -exec, bash -p). High confidence misconfiguration.

**References:**
- https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework
- https://gtfobins.github.io/

```
file_meta.setuid == true
  and (
    file_meta.path ends_with "/find"
    or file_meta.path ends_with "/nmap"
    or file_meta.path ends_with "/vim"
    or file_meta.path ends_with "/vi"
    or file_meta.path ends_with "/nano"
    or file_meta.path ends_with "/python"
    or file_meta.path ends_with "/python3"
    or file_meta.path ends_with "/perl"
    or file_meta.path ends_with "/ruby"
    or file_meta.path ends_with "/lua"
    or file_meta.path ends_with "/awk"
    or file_meta.path ends_with "/less"
    or file_meta.path ends_with "/more"
    or file_meta.path ends_with "/env"
    or file_meta.path ends_with "/bash"
    or file_meta.path ends_with "/dash"
    or file_meta.path ends_with "/sh"
    or file_meta.path ends_with "/cp"
    or file_meta.path ends_with "/tar"
    or file_meta.path ends_with "/gdb"
    or file_meta.path ends_with "/strace"
    or file_meta.path ends_with "/tcpdump"
    or file_meta.path ends_with "/docker"
    or file_meta.path ends_with "/podman"
    or file_meta.path ends_with "/nsenter"
    or file_meta.path ends_with "/unshare"
  )
```

### RM-PERSIST-0001

| | |
|---|---|
| **Name** | ld.so.preload present |
| **File** | [`checks/RM-PERSIST-0001.toml`](../checks/RM-PERSIST-0001.toml) |
| **Type** | `file` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `preload` |
| **ATT&CK** | T1574.006 |

**Title:** ld.so.preload present at {{preload.path}}

**Rationale:** /etc/ld.so.preload is rarely legitimate and is a common userland rootkit persistence mechanism.

```
preload.present == true
```

### RM-PERSIST-0002

| | |
|---|---|
| **Name** | Injected directory in ld.so configuration |
| **File** | [`checks/RM-PERSIST-0002.toml`](../checks/RM-PERSIST-0002.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `preload` |
| **ATT&CK** | T1574 |

**Title:** Suspicious ld.so config at {{preload.path}}

**Rationale:** Extra library search paths in ld.so.conf.d enable hijacked shared objects.

```
preload.present == true
  and preload.path contains "ld.so.conf"
```

### RM-PERSIST-0003

| | |
|---|---|
| **Name** | Cron fetch-and-exec pattern |
| **File** | [`checks/RM-PERSIST-0003.toml`](../checks/RM-PERSIST-0003.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `scheduled_task` |
| **ATT&CK** | T1053.003 |

**Title:** Suspicious scheduled task in {{scheduled_task.path}}: {{scheduled_task.command}}

**Rationale:** Cron/at entries that fetch remote content or decode payloads are common persistence.

```
scheduled_task.command contains "curl"
  or scheduled_task.command contains "wget"
  or scheduled_task.command contains "base64"
  or scheduled_task.command contains "/tmp/"
```

### RM-PERSIST-0005

| | |
|---|---|
| **Name** | systemd ExecStart in staging path |
| **File** | [`checks/RM-PERSIST-0005.toml`](../checks/RM-PERSIST-0005.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `service` |
| **ATT&CK** | T1543.002 |

**Title:** systemd unit {{service.name}} ExecStart uses staging path

**Rationale:** Services executing binaries from /tmp or /dev/shm are rarely legitimate.

```
service.exec_start != null
  and (
    service.exec_start contains "/tmp/"
    or service.exec_start contains "/dev/shm/"
  )
```

### RM-PERSIST-0009

| | |
|---|---|
| **Name** | Shell profile exports LD_* or fetch-exec |
| **File** | [`checks/RM-PERSIST-0009.toml`](../checks/RM-PERSIST-0009.toml) |
| **Type** | `file` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `service` |
| **ATT&CK** | T1546.004 |

**Title:** Suspicious shell startup hook in {{service.path}}

**Rationale:** Profile/rc hooks that export LD_* or pull remote content are common userland persistence.

```
service.exec_start != null
  and (
    service.exec_start contains "LD_PRELOAD"
    or service.exec_start contains "LD_AUDIT"
    or service.exec_start contains "curl "
    or service.exec_start contains "wget "
  )
  and (
    service.path.path_under("/etc/profile.d")
    or service.path contains "bashrc"
    or service.path contains "profile"
  )
```

## User / credentials (RM-USER, RM-CRED)

### RM-CRED-0001

| | |
|---|---|
| **Name** | Weak password hash algorithm |
| **File** | [`checks/RM-CRED-0001.toml`](../checks/RM-CRED-0001.toml) |
| **Type** | `user` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `shadow_entry` |
| **Collectors** | `cred.audit` |
| **ATT&CK** | T1110 |

**Title:** Weak hash algorithm '{{shadow_entry.algorithm}}' for account '{{shadow_entry.username}}'

**Rationale:** Legacy DES/MD5-crypt hashes are fast to crack offline.

```
shadow_entry.algorithm == "descrypt"
  or shadow_entry.algorithm == "md5crypt"
  or shadow_entry.algorithm == "sha1crypt"
```

### RM-CRED-0002

| | |
|---|---|
| **Name** | Duplicate password hash across accounts |
| **File** | [`checks/RM-CRED-0002.toml`](../checks/RM-CRED-0002.toml) |
| **Type** | `user` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | trivial |
| **Match** | `shadow_entry` |
| **Collectors** | `cred.audit` |
| **ATT&CK** | T1110 |

**Title:** Duplicate password hash (server correlates hash_fingerprint across accounts)

**Rationale:** Expression check is disabled; rustmite_checks::find_duplicate_shadow_hashes emits RM-CRED-0002 from fingerprints.

```
false
```

### RM-CRED-0003

| | |
|---|---|
| **Name** | Account should be locked but password usable |
| **File** | [`checks/RM-CRED-0003.toml`](../checks/RM-CRED-0003.toml) |
| **Type** | `user` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `shadow_entry` |
| **Collectors** | `cred.audit` |
| **ATT&CK** | T1078 |

**Title:** Active password hash on account '{{shadow_entry.username}}' (review lock policy)

**Rationale:** Accounts expected to be locked should not expose usable password hashes.

```
shadow_entry.locked == false
  and shadow_entry.empty_password == false
  and shadow_entry.algorithm != "!"
```

### RM-CRED-0005

| | |
|---|---|
| **Name** | Weak or deprecated SSH key type |
| **File** | [`checks/RM-CRED-0005.toml`](../checks/RM-CRED-0005.toml) |
| **Type** | `user` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `authorized_key` |
| **Collectors** | `ssh.keys` |
| **ATT&CK** | T1110 |

**Title:** Weak SSH key {{authorized_key.key_type}} ({{authorized_key.bits}} bits) for {{authorized_key.username}}

**Rationale:** DSA is obsolete. RSA keys under 2048 bits are weak offline. Modern RSA (2048+) still uses the ssh-rsa key type name in authorized_keys — that alone is not deprecated.

```
authorized_key.key_type == "ssh-dss"
  or (
    authorized_key.key_type == "ssh-rsa"
    and authorized_key.bits != null
    and authorized_key.bits < 2048
  )
```

### RM-USER-0001

| | |
|---|---|
| **Name** | UID 0 account other than root |
| **File** | [`checks/RM-USER-0001.toml`](../checks/RM-USER-0001.toml) |
| **Type** | `user` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `account` |
| **ATT&CK** | T1136 |

**Title:** UID 0 account '{{account.username}}' other than root

**Rationale:** Additional uid-0 accounts are a common backdoor.

```
account.uid == 0
  and account.username != "root"
```

### RM-USER-0002

| | |
|---|---|
| **Name** | Passwordless account (empty shadow hash) |
| **File** | [`checks/RM-USER-0002.toml`](../checks/RM-USER-0002.toml) |
| **Type** | `user` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `shadow_entry` |
| **ATT&CK** | T1078 |

**Title:** Passwordless login enabled for account '{{shadow_entry.username}}'

**Rationale:** Empty password hashes allow login without credentials when paired with a valid shell.

```
shadow_entry.empty_password == true
```

### RM-USER-0003

| | |
|---|---|
| **Name** | Service account with interactive shell |
| **File** | [`checks/RM-USER-0003.toml`](../checks/RM-USER-0003.toml) |
| **Type** | `user` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `account` |
| **Collectors** | `persistence.accounts` |
| **ATT&CK** | T1136 |

**Title:** Service account '{{account.username}}' has login shell {{account.shell}}

**Rationale:** System/service accounts should normally use nologin/false shells. Excludes the traditional sync account (/bin/sync).

```
account.uid < 1000
  and account.uid != 0
  and account.shell != "/usr/sbin/nologin"
  and account.shell != "/sbin/nologin"
  and account.shell != "/bin/false"
  and account.shell != "/usr/bin/false"
  and account.shell != "/bin/sync"
  and account.shell != "/sbin/sync"
  and account.shell != "/usr/sbin/sync"
  and not (account.shell ends_with "/nologin")
  and not (account.shell ends_with "/false")
```

### RM-USER-0004

| | |
|---|---|
| **Name** | New account vs baseline |
| **File** | [`checks/RM-USER-0004.toml`](../checks/RM-USER-0004.toml) |
| **Type** | `user` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | trivial |
| **Match** | `account` |
| **Collectors** | `persistence.accounts` |
| **ATT&CK** | T1136 |

**Title:** New account '{{account.username}}' (uid {{account.uid}}) vs baseline

**Rationale:** Accounts absent from the signed baseline indicate drift; evaluated by the baseline diff engine and server-side enrichment.

```
false
```

### RM-USER-0005

| | |
|---|---|
| **Name** | sudoers NOPASSWD ALL |
| **File** | [`checks/RM-USER-0005.toml`](../checks/RM-USER-0005.toml) |
| **Type** | `user` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `sudo_rule` |
| **ATT&CK** | T1548.003 |

**Title:** Passwordless sudo for all commands in {{sudo_rule.path}}

**Rationale:** NOPASSWD:ALL grants passwordless full root access and is a common persistence/privesc vector.

```
sudo_rule.nopasswd == true
  and sudo_rule.all_commands == true
```

### RM-USER-0006

| | |
|---|---|
| **Name** | Unsafe sudoers directive |
| **File** | [`checks/RM-USER-0006.toml`](../checks/RM-USER-0006.toml) |
| **Type** | `user` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `sudo_rule` |
| **ATT&CK** | T1548.003 |

**Title:** Unsafe sudoers line in {{sudo_rule.path}}: {{sudo_rule.line}}

**Rationale:** !authenticate and permissive SETENV directives weaken sudo hardening.

```
sudo_rule.line contains "!authenticate"
  or sudo_rule.line contains "SETENV"
```

### RM-USER-0008

| | |
|---|---|
| **Name** | New or unknown authorized_keys entry |
| **File** | [`checks/RM-USER-0008.toml`](../checks/RM-USER-0008.toml) |
| **Type** | `user` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | low |
| **Match** | `authorized_key` |
| **Collectors** | `ssh.keys` |
| **ATT&CK** | T1098.004 |

**Title:** SSH authorized key for {{authorized_key.username}} ({{authorized_key.fingerprint}})

**Rationale:** Disabled until authorized_keys baselines exist — without a baseline this matched every key. Re-enable when drift compares against a captured baseline.

```
authorized_key.fingerprint != ""
```

### RM-USER-0009

| | |
|---|---|
| **Name** | authorized_keys forced command spawns shell |
| **File** | [`checks/RM-USER-0009.toml`](../checks/RM-USER-0009.toml) |
| **Type** | `user` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `authorized_key` |
| **ATT&CK** | T1098.004 |

**Title:** Suspicious forced command in {{authorized_key.path}} for {{authorized_key.username}}

**Rationale:** Forced commands that invoke a shell may be backdoors disguised as restricted keys.

```
authorized_key.options_joined contains "command="
  and (
    authorized_key.options_joined contains "/bin/sh"
    or authorized_key.options_joined contains "/bin/bash"
  )
```

## Directory (RM-DIR)

### RM-DIR-0001

| | |
|---|---|
| **Name** | Directory link-count mismatch (hidden subdir) |
| **File** | [`checks/RM-DIR-0001.toml`](../checks/RM-DIR-0001.toml) |
| **Type** | `directory` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `dir_anomaly` |
| **ATT&CK** | T1014 |

**Title:** Hidden directory suspected at {{dir_anomaly.path}}

**Rationale:** Parent link count exceeding listed subdirectories may indicate hidden entries.

```
dir_anomaly.anomaly == "link_count_mismatch"
```

### RM-DIR-0002

| | |
|---|---|
| **Name** | getdents byte-sum mismatch |
| **File** | [`checks/RM-DIR-0002.toml`](../checks/RM-DIR-0002.toml) |
| **Type** | `directory` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `dir_anomaly` |
| **ATT&CK** | T1014 |

**Title:** getdents hiding suspected at {{dir_anomaly.path}}

**Rationale:** Disagreement between getdents metadata and entry counts may indicate magic-prefix hiding.

```
dir_anomaly.anomaly == "getdents_mismatch"
```

### RM-DIR-0003

| | |
|---|---|
| **Name** | Dotdir stash in sensitive mountpoint |
| **File** | [`checks/RM-DIR-0003.toml`](../checks/RM-DIR-0003.toml) |
| **Type** | `directory` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `dir_anomaly` |
| **ATT&CK** | T1564.001 |

**Title:** Suspicious dot-directory at {{dir_anomaly.path}}

**Rationale:** Hidden dot-directories directly under /, /tmp, or /dev are uncommon on production servers.

```
dir_anomaly.anomaly == "dotdir_stash"
```

### RM-DIR-0005

| | |
|---|---|
| **Name** | Open file absent from directory listing |
| **File** | [`checks/RM-DIR-0005.toml`](../checks/RM-DIR-0005.toml) |
| **Type** | `directory` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | medium |
| **Match** | `dir_anomaly` |
| **Collectors** | `dir.hidden`, `process.inventory` |
| **ATT&CK** | T1014 |

**Title:** Hidden open file at {{dir_anomaly.path}}

**Rationale:** Processes referencing paths that do not appear in parent directory listings indicate hiding.

```
dir_anomaly.anomaly == "unlisted_open_file"
```

## Log (RM-LOG)

### RM-LOG-0001

| | |
|---|---|
| **Name** | wtmp/utmp wiped or out-of-order |
| **File** | [`checks/RM-LOG-0001.toml`](../checks/RM-LOG-0001.toml) |
| **Type** | `log` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `log_integrity` |
| **ATT&CK** | T1070.002 |

**Title:** Login record integrity issue: {{log_integrity.path}} ({{log_integrity.issue}})

**Rationale:** Zeroed or out-of-order utmp/wtmp records may indicate login history wiping.

```
log_integrity.issue contains "wtmp"
  or log_integrity.issue contains "utmp"
```

### RM-LOG-0002

| | |
|---|---|
| **Name** | Log file NUL holes or selective deletion |
| **File** | [`checks/RM-LOG-0002.toml`](../checks/RM-LOG-0002.toml) |
| **Type** | `log` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `log_integrity` |
| **ATT&CK** | T1070.002 |

**Title:** Log tampering on {{log_integrity.path}} ({{log_integrity.issue}})

**Rationale:** NUL holes or sparse deletion patterns in logs suggest anti-forensics.

```
log_integrity.issue == "nul_hole"
  or log_integrity.issue contains "deletion"
```

### RM-LOG-0004

| | |
|---|---|
| **Name** | Expected log file missing |
| **File** | [`checks/RM-LOG-0004.toml`](../checks/RM-LOG-0004.toml) |
| **Type** | `log` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `log_integrity` |
| **ATT&CK** | T1070.002 |

**Title:** Expected log missing: {{log_integrity.path}}

**Rationale:** Missing expected log files may indicate deliberate removal.

```
log_integrity.issue == "missing"
```

### RM-LOG-0007

| | |
|---|---|
| **Name** | HISTFILE=/dev/null on live process |
| **File** | [`checks/RM-LOG-0007.toml`](../checks/RM-LOG-0007.toml) |
| **Type** | `log` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `process` |
| **ATT&CK** | T1070.003 |

**Title:** Process '{{process.comm}}' (pid {{process.pid}}) disables shell history

**Rationale:** Disabling HISTFILE on an interactive process hinders command-line forensics.

```
process.environ_flags contains "HISTFILE=/dev/null"
  or process.environ_flags contains "HISTFILE=null"
```

## Policy (RM-POL)

### RM-POL-0001

| | |
|---|---|
| **Name** | SSH host key changed since pinning |
| **File** | [`checks/RM-POL-0001.toml`](../checks/RM-POL-0001.toml) |
| **Type** | `policy` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `ssh_host_key` |

**Title:** SSH host key changed ({{ssh_host_key.key_type}} {{ssh_host_key.fingerprint}})

**Rationale:** A changed SSH host key blocks trust in scan results and may indicate MITM or host rebuild; always critical.

```
ssh_host_key.changed == true
```

### RM-POL-0021

| | |
|---|---|
| **Name** | Degraded inspection (pure-command fallback) |
| **File** | [`checks/RM-POL-0021.toml`](../checks/RM-POL-0021.toml) |
| **Type** | `policy` |
| **Severity** | high |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `policy` |

**Title:** Host could not be inspected with full-fidelity probe: {{policy.detail}}

**Rationale:** Method D pure-command fallback cannot perform differential syscall checks; raise so operators know coverage is degraded.

```
policy.code == "RM-POL-0021"
```

### RM-POL-0032

| | |
|---|---|
| **Name** | World-writable file in PATH |
| **File** | [`checks/RM-POL-0032.toml`](../checks/RM-POL-0032.toml) |
| **Type** | `policy` |
| **Severity** | medium |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | low |
| **Match** | `file_meta` |

**Title:** World-writable binary in PATH: {{file_meta.path}}

**Rationale:** World-writable executables on PATH allow local privilege escalation; noisy on some images — disabled by default.

```
file_meta.world_writable == true
  and (
    file_meta.path.path_under("/usr/bin")
    or file_meta.path.path_under("/usr/local/bin")
    or file_meta.path.path_under("/bin")
  )
```

## Incident / correlation (RM-INC)

### RM-INC-0004

| | |
|---|---|
| **Name** | Stolen SSH key placement across hosts |
| **File** | [`checks/RM-INC-0004.toml`](../checks/RM-INC-0004.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | False |
| **Cost** | low |
| **Match** | `authorized_key` |
| **Collectors** | `ssh.keys` |
| **ATT&CK** | T1021.004, T1078 |

**Title:** SSH key reused across hosts (server bipartite graph)

**Rationale:** Expression check is disabled; rustmite_checks::correlate_ssh_key_graph emits RM-INC-0004 when a fingerprint appears on multiple hosts.

```
false
```

### RM-KERN-0001

| | |
|---|---|
| **Name** | Hidden kernel module (/sys/module vs /proc/modules) |
| **File** | [`checks/RM-KERN-0001.toml`](../checks/RM-KERN-0001.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `module` |
| **ATT&CK** | T1014 |

**Title:** Hidden or inconsistent module '{{module.name}}' (sysfs={{module.in_sysfs}} proc={{module.in_proc_modules}})

**Rationale:** Disagreement between loadable modules in /sys/module (entries with initstate) and
/proc/modules is a classic LKM rootkit hiding signal. Built-in (compiled-in) modules
appear under /sys/module without initstate and are excluded from this comparison —
they never appear in /proc/modules and are not a finding.


```
(module.in_sysfs == true and module.in_proc_modules == false)
  or (module.in_sysfs == false and module.in_proc_modules == true)
```

### RM-KERN-0002

| | |
|---|---|
| **Name** | Unsigned or out-of-tree kernel module loaded |
| **File** | [`checks/RM-KERN-0002.toml`](../checks/RM-KERN-0002.toml) |
| **Type** | `incident` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `module` |
| **ATT&CK** | T1547.006 |

**Title:** Out-of-tree/unsigned module '{{module.name}}' (taint {{module.taint_flags}})

**Rationale:** Taint flags E/O indicate proprietary or out-of-tree modules that warrant review.

```
module.taint_flags != null
  and (
    module.taint_flags contains "E"
    or module.taint_flags contains "O"
  )
```

### RM-KERN-0004

| | |
|---|---|
| **Name** | Known rootkit module name |
| **File** | [`checks/RM-KERN-0004.toml`](../checks/RM-KERN-0004.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | trivial |
| **Match** | `module` |
| **ATT&CK** | T1014 |

**Title:** Known rootkit module name '{{module.name}}'

**Rationale:** Module name matches a known rootkit or hiding kit signature.

```
module.name matches "(?i)diamorphine|reptile|kit|rootkit"
```

### RM-KERN-0006

| | |
|---|---|
| **Name** | Orphan eBPF program of hooking type |
| **File** | [`checks/RM-KERN-0006.toml`](../checks/RM-KERN-0006.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `bpf_prog` |
| **ATT&CK** | T1014 |

**Title:** Orphan eBPF program id {{bpf_prog.id}} ({{bpf_prog.prog_type}})

**Rationale:** Kernel-listed eBPF programs without an owning userspace process may hide traffic or processes.

```
bpf_prog.orphan == true
```

### RM-NET-0001

| | |
|---|---|
| **Name** | Hidden socket (sock_diag vs /proc/net mismatch) |
| **File** | [`checks/RM-NET-0001.toml`](../checks/RM-NET-0001.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `hidden_socket` |
| **ATT&CK** | T1014 |

**Title:** Hidden {{hidden_socket.protocol}} socket on port {{hidden_socket.local_port}}

**Rationale:** Socket visible via sock_diag but absent from /proc/net (or vice versa) indicates socket hiding.

```
hidden_socket.local_port >= 0
```

### RM-NET-0002

| | |
|---|---|
| **Name** | Listener with no visible owning PID |
| **File** | [`checks/RM-NET-0002.toml`](../checks/RM-NET-0002.toml) |
| **Type** | `incident` |
| **Severity** | critical |
| **Confidence** | high |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `socket` |
| **Collectors** | `decloak.socket`, `net.sockets` |
| **ATT&CK** | T1014 |

**Title:** Listener {{socket.local_ip}}:{{socket.local_port}} has no visible owner

**Rationale:** Listening sockets without a resolvable owning process (after a reliable root-level
fd walk) may indicate a hidden-process backdoor. Non-root scans cannot read other
users' /proc/*/fd tables — those leave owning_pid null without owner_unresolved and
must not alert.


```
socket.state == "LISTEN"
  and socket.owning_pid == null
  and socket.owner_unresolved == true
```

### RM-NET-0003

| | |
|---|---|
| **Name** | Unexpected listening socket |
| **File** | [`checks/RM-NET-0003.toml`](../checks/RM-NET-0003.toml) |
| **Type** | `incident` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | False |
| **Cost** | low |
| **Match** | `socket` |
| **Collectors** | `net.sockets` |
| **ATT&CK** | T1571 |

**Title:** Listening {{socket.protocol}} socket on {{socket.local_ip}}:{{socket.local_port}}

**Rationale:** Disabled until host allow-baselines exist — without a baseline this matched every listener (including sshd :22). Re-enable when RM-NET-0003 is evaluated against an allowlist / baseline drift path.

```
socket.state == "LISTEN"
  and socket.local_port > 0
```

### RM-NET-0005

| | |
|---|---|
| **Name** | Raw or packet socket owned by non-standard process |
| **File** | [`checks/RM-NET-0005.toml`](../checks/RM-NET-0005.toml) |
| **Type** | `incident` |
| **Severity** | high |
| **Confidence** | medium |
| **Enabled** | True |
| **Cost** | low |
| **Match** | `socket` |
| **ATT&CK** | T1040 |

**Title:** Sniffer-class socket ({{socket.protocol}}) uid {{socket.uid}} inode {{socket.inode}}

**Rationale:** Raw/packet sockets may indicate packet capture or L2 sniffing.

```
socket.protocol == "RAW"
  or socket.protocol == "PACKET"
```

