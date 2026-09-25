# 04 — SSH Transport and Ephemeral Probe Delivery

This is the mechanism that makes RustMite agentless. It must be robust against old SSH servers, restricted shells, `noexec` filesystems, and hostile observers, and it must clean up perfectly.

## 1. Responsibilities

`rustmite-transport` provides:
- an SSH2 client (`russh`) with a connection pool,
- host-key pinning and trust-on-first-use policy,
- the **two-stage `memfd` loader** that runs the probe from memory,
- credential resolution against the vault,
- graceful teardown and forensic-clean removal.

## 2. SSH client

### 2.1 Library

`russh` (client role) + `russh-keys`. Pure Rust, async, actively maintained. The node holds an `russh::client::Handle` per live session.

### 2.2 Auth methods (in order of preference)

1. **ed25519 / ecdsa / rsa public key** from the vault (per-host key strongly preferred; `10` §2).
2. **Certificate-based** (OpenSSH user certs) where the fleet uses an SSH CA.
3. **Keyboard-interactive / password** — supported for legacy but discouraged; password from vault, zeroized after use.
4. **Agent forwarding** — **forbidden.** Never forward an agent to an untrusted host.

### 2.3 Legacy compatibility

Old appliances speak old crypto. The client must negotiate, in a **configurable, security-ordered** list, down to what a 2012-era dropbear/openssh offers, while logging when it falls back:

- KEX: `curve25519-sha256` → `ecdh-sha2-nistp256` → `diffie-hellman-group14-sha256` → (opt-in) `group14-sha1`.
- Host key: `ssh-ed25519` → `ecdsa-*` → `rsa-sha2-512/256` → (opt-in) `ssh-rsa`.
- Cipher: `chacha20-poly1305` → `aes256-gcm` → `aes128-ctr`.

Each opt-in legacy primitive is off by default and, when enabled and used, is recorded in scan evidence (a host that only supports SHA-1 KEX is itself a posture finding, `RM-POL-0020`). Confirm `russh`'s supported algorithm set covers this list during M2; if a required legacy KEX is missing, that is a `russh` contribution, not a reason to shell out to `ssh`.

### 2.4 Host-key policy

- **Pin on first successful scan.** Store `(host_id, key_type, fingerprint)` in `host_keys`.
- On mismatch: **refuse the scan**, emit `RM-POL-0001` critical, require operator acknowledgement to re-pin. Never `StrictHostKeyChecking=no` semantics.
- Support multiple pinned keys per host (key rotation windows) with explicit expiry.

### 2.5 Connection pool

- Keyed by `host_id`. Reuse a session across sweeps within an idle TTL (default 90 s) to amortise handshake cost.
- Multiplex with SSH channels: fingerprint + probe delivery + probe exec can share one connection.
- **Optional sudo escalation.** Host label `ssh_sudo=true` runs the probe under `sudo` after
  login so collectors get root-level `/proc` (fd→socket ownership, etc.). Modes:
  - `ssh_sudo_mode=nopasswd` → `sudo -n` (NOPASSWD sudoers)
  - `ssh_sudo_mode=ssh_password` → `sudo -S` with the SSH password (default for password auth)
  - `ssh_sudo_mode=password` + `ssh_sudo_password_file` → separate sudo secret
  Skipped automatically when the SSH session is already `euid=0`.
- Health-check with a lightweight `keepalive@openssh.com` global request; drop dead sessions.
- Hard cap total sessions per node (fd exhaustion protection).

## 3. Delivery strategy selection

Given the fingerprint (`01` §4), pick a delivery method. Attempt in order; each failure is diagnostic, not fatal, until all are exhausted:

| Method | Requirement | Footprint | Preferred when |
|---|---|---|---|
| **A. memfd two-stage** | kernel ≥ 3.17, exec allowed | none on disk | default |
| **B. tmpfs ephemeral** | a writable, exec-capable dir (`/dev/shm`, `/run`, `/tmp` if not `noexec`) | file exists during scan, unlinked immediately post-exec | memfd unavailable |
| **C. SFTP + exec** | SFTP subsystem + writable exec dir | file on disk briefly | shell restricted but SFTP present |
| **D. pure-command** | only `/bin/sh` and coreutils | none | no exec dir anywhere; **degraded capability** — collectors that need the binary are `Unsupported` |

Method D is the honest fallback: it runs a curated set of read-only shell/`cat`/`readlink` equivalents *from the node* over SSH and parses them, accepting that it cannot do differential syscall checks. Mark all such results `confidence: low` and raise `RM-POL-0021` ("host could not be inspected with full-fidelity probe").

Operators can also **force** Method D per host by setting `agent_kind=agentlite` (Add host → **AgentLite**). No probe ELF is transferred; sudo (when configured) wraps the remote shell so `/etc/shadow` and other users' keys remain readable. Use this when policy forbids running any foreign binary on the endpoint. Legacy host label `scan_mode=ssh_commands` is still honoured. AgentLite also appears under Settings → Build & versions.

AgentLite inventories files via `stat`/`find` under a default set of roots (`/bin`, `/usr/bin`, `/etc`, `/tmp`, …). Operators can add more absolute files or directories with the host label `collect_paths` (comma- or newline-separated) on **Add hosts** / **Edit host**.

Fleet **Settings → Agent limits** apply to AgentLite as well as the full probe (observation/file caps, remote nice/ionice/ulimit, transfer pacing).

## 4. The two-stage memfd loader (Method A, the core trick)

Goal: get a multi-MB ELF into an anonymous memory file and `execveat` it, without ever creating a named file, using only what a stock `/bin/sh` can do.

### Stage 0 — the tiny loader

A ~10–20 KB statically-linked ELF (`rustmite-loader`) that:
1. calls `memfd_create("", MFD_CLOEXEC)` → fd,
2. reads its own stdin to EOF, writing bytes into the memfd,
3. `fexecve`/`execveat(fd, "", argv, envp, AT_EMPTY_PATH)` the memfd.

Stage 0 is small enough to deliver as a **base64/xxd-encoded heredoc** decoded by the remote shell itself:

```sh
# conceptual; node generates this, sized to the shell's line limits
exec 3< <(printf '%s' "$B64" | base64 -d)   # or a chunked here-doc if base64 absent
# fallback without process substitution:  base64 -d > "$MEMFD_HELPER"  (method B)
```

Because base64 availability is not guaranteed on ancient/embedded systems, `rustmite-transport` carries **three encoders**: `base64 -d`, `openssl base64 -d`, and a pure-shell `printf \\NNN` octal decoder (slow but universal). The node picks based on the fingerprint probe of which tools exist (`command -v base64`).

Even simpler and more robust in practice: use SSH's own binary-clean channel. Open an `exec` channel running stage 0 directly *from* the memfd on the remote — but that requires stage 0 already there. So the minimal bootstrap is:

```
node → open exec channel: `sh -c '<inline stage0 bootstrap>'`
     → bootstrap decodes stage0 (small) into /dev/shm OR into a memfd via a
       one-liner C-free technique, execs it
stage0 (running) → reads its stdin (the SSH channel) = the full probe bytes
     → memfd_create + write + execveat
stage1 probe (running, anonymous) → reads ScanRequest from the same stdin stream
```

The node therefore sends, on one channel's stdin, a framed stream:
```
[stage0 bootstrap is the command line] then stdin = [len][stage0 elf][len][probe elf][ScanRequest json]\n
```

### 4.1 Framing

Length-prefixed, little-endian `u32` frames on stdin:
```
frame 0: STAGE1_PROBE   (lz4-compressed ELF)   ← stage0 decompresses, memfd, exec
frame 1: SCAN_REQUEST   (json, uncompressed)   ← consumed by stage1
```
Stage 0 reads exactly frame 0, then `dup`s the remaining stdin so stage1 inherits the SCAN_REQUEST. Compression with `lz4_flex` (pure Rust, ADR-4) roughly halves transfer bytes.

### 4.2 Why two stages

- Stage 0 is tiny → deliverable through even a restrictive shell / small line limits.
- Stage 1 (the real probe, MBs) travels as raw bytes on an already-established stdin pipe → no shell escaping of megabytes, no disk.
- The probe binary never touches the filesystem or a named path → nothing for the host's own logging/AV/FIM to record, and nothing to clean up.

### 4.3 `noexec` and hardened kernels

- If `execveat(memfd)` returns `EACCES`/`EPERM` (some SELinux/hardened configs block `execmem`/anonymous exec), fall back to Method B/C and record the restriction as evidence (a host that blocks anonymous exec is well-hardened — good — but note it).
- `fs.suid_dumpable`, `kernel.yama.ptrace_scope`, W^X policies may affect specific collectors; probe reports these in `Hello.caps`.

## 5. `argv[0]` and process presentation

The probe will appear in the host's own `/proc` for its lifetime. Decisions:
- **Do not disguise it.** `argv[0]` = `rustmite-probe`. RustMite is a defensive tool operating with authorisation; hiding it would (a) be hypocritical given the product detects exactly that behaviour, and (b) trip other defenders' tooling. The probe is meant to be visible and short-lived.
- Its own PID is excluded from decloak self-comparison to avoid a self-referential false positive (it records its own PID at startup).

## 6. Cleanup and forensic hygiene

Post-exec, the node ensures:
- Method A: nothing to clean (anonymous). Close channels; the memfd dies with the process.
- Method B/C: the file was `unlink`ed by stage0 *immediately after* opening it for exec (classic delete-then-exec; the inode lives only as long as the running process). Node verifies via a follow-up `statx` that the path is gone. If cleanup fails (rare: crash between write and unlink), node performs an explicit removal and records `cleanup_forced=true`.
- Close all channels; do not leave `sftp` sessions dangling.
- The SSH login itself is intentionally left in the host's `auth.log`/`wtmp` — see `10` §6. RustMite does not tamper with the host's audit trail.

The node emits a `DeliveryReport` for every scan documenting: method used, encoder used, bytes transferred, cleanup status, and any fallback. This is retained as scan metadata (`07` §3.6) — an attacker forcing you into Method D repeatedly is a signal.

## 7. Streaming results back

- Probe stdout (NDJSON) flows back over the same SSH channel.
- Node wraps the read side in a **bounded, line-oriented, compression-aware** reader:
  - hard cap `max_output_bytes` (default 64 MiB) — abort the channel if exceeded, mark `Truncated`;
  - per-line cap 256 KiB;
  - the probe may `lz4` its own stdout when `plan.compress_output` is set; node inflates with a bounded decompressor (never trust the decompressed-size hint from the stream).
- Node parses each line into typed `Envelope`s with `serde_json::from_slice` (no `Value`), pushing observations into the normaliser as they arrive. Constant memory regardless of host size.

## 8. Timeouts at every layer

| Layer | Default | On expiry |
|---|---|---|
| TCP connect | 10 s | `Unreachable` |
| SSH handshake+auth | 20 s | `AuthFailed`/`Unreachable` |
| Fingerprint | 10 s | proceed with trial-arch |
| Probe delivery | 30 s | `DeliveryFailed` |
| Probe run (= `deadline_ms`) | 60 s standard / 600 s deep | abort channel, `Timeout`, keep partial obs |
| Idle stream (no bytes) | 30 s | abort, `Timeout` |

All timeouts jittered ±10% to avoid synchronised fleet-wide failures.

## 9. Test surface for the transport

- A local sshd matrix in containers: OpenSSH old/new, Dropbear, `noexec /tmp`, SFTP-only, restricted `rbash`, `ForceCommand`, no-`base64`, big-endian.
- A `russh`-based fake SSH server that returns hostile streams (giant lines, invalid UTF-8, slowloris) to test the bounded reader.
- Chaos: kill the probe mid-stream, drop TCP, change host key between scans → assert correct `ScanOutcome` and no fd/session leak.
