# 10 — Security Model of the Platform Itself

RustMite holds SSH access to an entire fleet. It is, by construction, one of the highest-value targets in the environment. This document is a hardening spec for the platform, not an afterthought.

## 1. Threat model for RustMite
Adversary goals against RustMite: (a) steal fleet SSH credentials, (b) subvert results so a compromised host reports clean, (c) use a node as a lateral-movement pivot, (d) tamper with the audit trail, (e) trigger destructive response actions. The controls below map to each.

## 2. Credential architecture (defends a, c)
- **Per-host keys, not a master key.** Each host has its own SSH key/credential. Compromise of one credential ≠ fleet compromise. A shared key is permitted only as an explicit, flagged downgrade.
- **Restricted accounts where possible.** Support and recommend a dedicated `rustmite` account with either (i) `sudo` scoped to nothing (root not required — collectors degrade gracefully and report reduced coverage), or (ii) an `authorized_keys` `command=`/`ForceCommand` restricted to launching the probe bootstrap, or (iii) full root where the customer accepts it. Document the coverage delta per privilege level.
- **Nodes never hold the whole vault.** Encrypted credentials stay on the server. Nodes receive only the ciphertext for the current job (`ssh_*_box`), decrypt in memory, and `zeroize` after use (`08` §7). A compromised node can only reach hosts it is actively scanning during the compromise window.
- **No agent forwarding, ever** (`04` §2.2).

## 3. Credential vault (defends a) — Sandfly-style node-only decrypt
See also [Sandfly Credentials Security](https://docs.sandflysecurity.com/docs/credentials-security).

- **Public-key sealed at rest.** SSH identities and passwords are encrypted to an X25519 public key (`cred.pub`). The matching private key lives **only on scanner nodes** (`cred.priv`). The control plane never holds a decrypt key.
- **Irreversible once added.** After upload, neither the UI nor the server can read credential plaintext again. To change a secret, delete and re-upload.
- **Lease delivers ciphertext.** Nodes receive `ssh_*_box` blobs over TLS and decrypt in memory for the job only (`Zeroizing` buffers).
- **Separation of duties.** A compromised server/DB yields only ciphertext. A powered-down node holds the private key but no stored fleet secrets. Compromising both is required to steal usable SSH credentials at rest.
- Optional: external KMS for the node private key; envelope encryption remains ChaCha20-Poly1305 after X25519 ECDH.
- Rotation: rotate the fleet cred keypair and re-upload secrets; per-host credential versions tracked.

## 4. Result authenticity (defends b)
- The **authenticity boundary is the SSH channel + the node**, never the probe (ADR-6). The node knows it spoke to the pinned host key over an integrity-protected channel; it normalises and **signs** the result (`ScanMeta.node_signature`, ed25519 node key) before the server persists it.
- The server verifies the node signature and the node's mTLS identity.
- **Host-key pinning** (`04` §2.4): a changed host key blocks the scan and raises critical `RM-POL-0001`. This is the primary defence against a MITM feeding fake "clean" results.
- **Differential detection** (Prime Directive) is the defence against a *host-resident* rootkit lying to the probe: it must lie consistently across all interfaces or be caught. Findings carry `confidence` reflecting how many independent sources agreed.
- **Coverage accounting** (`05` §6): a host that suddenly can't be inspected is flagged, so "clean because blind" is visible.

## 5. Tamper-evident audit (defends d)
- `audit_log` is append-only with a **hash chain** (`hash = H(prev_hash || row)`); periodically anchor the head hash to an external store (or sign it) so silent history rewrites are detectable.
- Every credential access, scan trigger, allowlist creation, check change, baseline capture, and response action is logged with actor, target, reason, timestamp.
- Auditor role has read-only access to this log and nothing else.

## 6. Non-repudiation & transparency toward monitored hosts
- RustMite deliberately **does not** hide from the host: the SSH login is recorded in the host's own `wtmp`/`auth.log`, and the probe's PID is visible while it runs (`04` §5). This is an ethical and operational stance — a defensive scanner that behaves like a rootkit is indistinguishable from one, and undermines trust and forensics.
- Optional `issuer_sig` lets a host operator verify exactly what was requested of their machine.

## 7. Sensitive-data handling (defends across)
- **Password hashes** (`06` §20): transported node→server only over TLS, held in `Zeroizing` buffers, never written to disk in cleartext, never logged. Only the *audit result* ("weak: reason") persists. Offline cracking is elevated-role, rate-limited, audited, and returns no plaintext by default.
- **SSH private-key material** is never collected — only public keys and fingerprints.
- **Evidence redaction**: configurable redaction of secrets that appear in process environments/cmdlines (tokens, passwords) before storage/display.
- PII minimisation in recon inventory; per-tenant data isolation (RLS).

## 8. Response-action safety (defends e)
See `09` §3/§6: signed single-use grants, target re-verification, two-person control, kill-switch, blast-radius guard, rollback. A stolen operator session cannot mass-destroy without a second approver and cannot forge a grant without the server key.

## 9. Supply chain (defends the build)
- `cargo-deny` gates: licence allowlist, RUSTSEC advisory DB, ban `openssl-sys`/`native-tls`/`*-sys` in probe crates, pure-Rust enforcement (`02` §3.3).
- `cargo-vet` or `cargo-crev` review gates on new dependencies.
- Reproducible builds for the probe (pinned toolchain, `--remap-path-prefix`, sorted inputs) so the embedded probe hashes are verifiable.
- Release artefacts (probes, catalog) are ed25519-signed; nodes/servers verify before use.
- SBOM generated (`cargo-cyclonedx`) per release.

## 10. Runtime hardening of node/server
- Run as unprivileged users; systemd units with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, seccomp allow-list, `CapabilityBoundingSet=` empty.
- Node needs only outbound 22 + outbound 8443; server needs inbound 443/8443. No inbound to nodes.
- TLS 1.3 only, `rustls`, modern cipher suites; mTLS for node channel; HSTS on operator API.
- Secrets never in env/CLI of long-lived processes (would show in `/proc` — the very thing RustMite detects).

## 11. Privacy & compliance posture
- Data residency via node placement + per-tenant DB scoping.
- Configurable retention (`07` §5) and right-to-erasure tooling.
- Full audit trail supports SOC2/ISO evidence.
- The agentless model itself is a compliance advantage: no third-party code persistently resident on regulated hosts.
