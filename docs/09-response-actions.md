# 09 — Incident Response Actions

Optional, explicitly-authorised containment. This is the `Respond` probe mode (`03` §8) plus the server-side authorisation and audit around it. Response is powerful and dangerous; the design is dominated by **interlocks**, not features.

## 1. Philosophy
- **Off by default, opt-in per action, per host group.** A deployment can run detection-only forever.
- **Least action.** Prefer reversible, narrow actions (kill a PID) over broad ones (disable an account).
- **Two-person + signed grant** for destructive actions.
- **A build that cannot respond must be producible** (`--no-default-features`, no `respond` feature) for customers who forbid write access. The scan-only probe has `RLIMIT_FSIZE=0` and no write code paths compiled in.

## 2. Action catalog

| Action | Reversible | Default gate | Notes |
|---|---|---|---|
| `kill_process` (SIGKILL/SIGSTOP a PID) | partial | responder + grant | verify identity (starttime) at kill time to avoid PID reuse |
| `freeze_process` (SIGSTOP for forensics) | yes | responder | preserve memory for capture before kill |
| `capture_memory` (dump `/proc/<pid>/maps`+regions) | n/a (read) | analyst | forensic acquisition; large |
| `quarantine_file` (chmod 000 + `chattr +i` + move to quarantine dir) | yes | responder + grant | never delete; move + immutabilise |
| `revoke_ssh_key` (remove a fingerprint from `authorized_keys`) | yes (backup taken) | responder + grant | for stolen-key response (`06` §19) |
| `disable_account` (lock in shadow, expire) | yes | responder + grant | backup shadow line |
| `remove_persistence` (disable a cron/systemd unit) | yes | responder + grant | move aside, don't delete |
| `unload_module` / `detach_bpf` | risky | **admin + two-person** | can crash host; often better to isolate |
| `isolate_host` (apply nftables ruleset dropping all but the node's mgmt IP) | yes | responder + grant | network containment; safest broad action |
| `collect_forensics` (bundle key artefacts) | n/a | analyst | triage package |

## 3. Authorisation flow (`ActionGrant`)

```
1. Operator (responder role) requests an action on a finding/host via API.
2. Server builds an ActionGrant:
     { action, host_id, target (pid+starttime | path+hash | key_fp | ...),
       requested_by, reason, expires_at (short), nonce, single_use=true }
3. Destructive actions require a second approver (admin/responder) → two signatures.
4. Server signs the grant (ed25519, server key). 
5. Node fetches short-TTL credentials, delivers a `Respond`-mode probe with the
   signed grant in the ScanRequest (issuer_sig REQUIRED here).
6. Probe verifies: grant signature, expiry, nonce, and that the *live target still
   matches* (pid starttime, file hash, key fingerprint). Mismatch → refuse, no action.
7. Probe performs the single action, emits a signed ActionReport, exits.
8. Server records the action + report in the append-only audit_log (10 §5).
```

Interlocks summarised:
- **Target re-verification at execution time** (starttime/hash/fingerprint) — never act on stale identity.
- **Single-use, short-TTL, nonce-bound grants** — no reusable "kill anything" capability.
- **Two-person control** for host-destabilising actions.
- **Backups before mutation** — quarantine/revoke/disable snapshot the prior state to the server first, enabling rollback.
- **Dry-run mode** — every action supports `dry_run:true`, returning what *would* happen.

## 4. `Respond` probe path
- Compiled only with `--features respond`.
- `RLIMIT_FSIZE` is *not* zero, but writes are confined to the specific action; a `FsGuard` asserts every write path is within the grant's declared target(s).
- Emits `ActionReport { action, target, before_state_hash, after_state_hash, result, ts }`, node-signed onward.

## 5. Rollback
- `POST /v1/actions/{id}/rollback` restores from the stored before-state where the action is reversible (re-enable account, restore authorized_keys line, un-quarantine, remove nftables isolation). Rollback is itself an audited, granted action.

## 6. Safety rails
- **Rate limits** on response actions per host and per operator.
- **Blast-radius guard**: an action targeting >N hosts requires admin + explicit confirmation; no "respond across the fleet" one-click.
- **Production-hours policy**: optional windows restricting destructive actions.
- **Kill-switch**: an org-level flag that disables all response, verified by the node before executing any `Respond` probe.
