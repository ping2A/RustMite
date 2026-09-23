//! End-to-end remote scan: fingerprint → select delivery → run probe → normalise.

use std::time::{SystemTime, UNIX_EPOCH};

use rustmite_proto::{
    CollectorSpec, DeliveryMethod, Limits, ProbeMode, ScanRequest, SCHEMA_VERSION,
};
use uuid::Uuid;

use crate::delivery::{select_delivery_method, DeliveryOutcome, HostCapabilities};
use crate::error::TransportError;
use crate::fingerprint::{parse_uname_hint, HostFingerprint};
use crate::framing::encode_probe_frame;
use crate::hostkey::HostKeyPolicy;
use crate::ingest::{normalise_stream, NormalisedResult};
use crate::probes::ProbeCatalog;
use crate::ssh::{ConnectOpts, SshCredential, SshSession};

/// How to escalate the remote probe to root after SSH login.
#[derive(Clone, Debug, Default)]
pub enum SudoEscalation<'a> {
    #[default]
    None,
    /// `sudo -n` — requires NOPASSWD for the SSH user.
    Nopasswd,
    /// `sudo -S` — password fed on stdin before the probe payload.
    Password { password: &'a str },
}

impl SudoEscalation<'_> {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Nopasswd => "sudo-nopasswd",
            Self::Password { .. } => "sudo-password",
        }
    }
}

/// Inputs for a standalone CLI / node scan against one host.
pub struct RemoteScanOpts<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub credential: SshCredential<'a>,
    pub policy: HostKeyPolicy,
    /// Stage-1 probe ELF (Linux musl static). Ignored when `probe_catalog` is set.
    pub probe_elf: &'a [u8],
    /// Optional stage-0 loader ELF. When present and memfd looks available, Method A is used.
    pub loader_elf: Option<&'a [u8]>,
    /// When set, fingerprint the host first and pick the matching Linux 64/32 probe.
    pub probe_catalog: Option<&'a ProbeCatalog>,
    pub collectors: Vec<CollectorSpec>,
    pub mode: ProbeMode,
    pub deadline_ms: u32,
    /// Resource envelope applied inside the probe (and transfer throttle on the node).
    pub limits: Limits,
    /// Per-host / fleet SSH timeouts (connect, auth, cmd, delivery, …).
    pub timeouts: crate::timeouts::SshTimeouts,
    /// Run the probe under `sudo` so collectors see root-level `/proc` (fd ownership, etc.).
    pub sudo: SudoEscalation<'a>,
}

pub struct RemoteScanResult {
    pub fingerprint: HostFingerprint,
    pub delivery: DeliveryOutcome,
    pub normalised: NormalisedResult,
    pub raw_stdout: String,
    pub raw_stderr: String,
    pub presented_host_key: Option<crate::hostkey::HostKeyRecord>,
    /// Which agentless artifact was delivered (when selected from a catalog).
    pub probe_arch: Option<String>,
    pub probe_triple: Option<String>,
}

use crate::throttle::pace_transfer;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_request(opts: &RemoteScanOpts<'_>) -> ScanRequest {
    let mut req = ScanRequest::new_scan(Uuid::new_v4(), opts.collectors.clone());
    req.mode = opts.mode;
    req.deadline_ms = opts.deadline_ms;
    req.limits = opts.limits.clone();
    req.issued_at = now_ms();
    // Random-ish nonce from scan id bytes + time
    let mut nonce = [0u8; 32];
    let id = req.scan_id.as_bytes();
    nonce[..16].copy_from_slice(id);
    let t = now_ms().to_le_bytes();
    nonce[16..24].copy_from_slice(&t);
    nonce[24] = SCHEMA_VERSION as u8;
    req.nonce = nonce;
    req
}

async fn probe_capabilities(session: &SshSession) -> Result<(HostFingerprint, HostCapabilities), TransportError> {
    // Sanctioned fingerprint + capability probes (docs/01 §4, docs/04 §3).
    // EXEC_DIR is discovered by actually writing a tiny script and executing it.
    let cmd = r#"
uname -srm
echo ---
id -u
echo ---OS---
cat /etc/os-release 2>/dev/null || true
echo ---
command -v base64 >/dev/null && echo HAS_BASE64 || echo NO_BASE64
EXEC_DIR=
for d in /run/rustmite-exec /run/user/$(id -u) /tmp /home/$(id -un) /var/tmp /dev/shm; do
  [ -d "$d" ] && [ -w "$d" ] || continue
  f="$d/.rm-exec-probe-$$"
  if printf '#!/bin/sh\necho OK\n' > "$f" 2>/dev/null; then
    chmod 755 "$f" 2>/dev/null || true
    if "$f" >/dev/null 2>&1; then
      EXEC_DIR="$d"
      rm -f "$f"
      break
    fi
    rm -f "$f"
  fi
done
if [ -n "$EXEC_DIR" ]; then echo "EXEC_DIR=$EXEC_DIR"; else echo EXEC_DIR_NONE; fi
"#;
    let (out, err, code) = session.exec(cmd, None).await?;
    if code != 0 {
        return Err(TransportError::Ssh(format!(
            "fingerprint failed (exit {code}): {}",
            String::from_utf8_lossy(&err)
        )));
    }
    let text = String::from_utf8_lossy(&out);
    let fp = parse_uname_hint(&text);
    let staging_dir = text
        .lines()
        .find_map(|l| l.strip_prefix("EXEC_DIR="))
        .filter(|s| !s.is_empty() && *s != "NONE")
        .map(|s| s.to_string());
    let caps = HostCapabilities {
        has_base64: text.contains("HAS_BASE64"),
        exec_tmpfs: staging_dir.is_some(),
        staging_dir,
        kernel_ok_for_memfd: kernel_supports_memfd(&fp.kernel),
        // memfd_create itself does not need an exec dir; stage0 bootstrap still might.
        memfd_create: kernel_supports_memfd(&fp.kernel),
        sftp: false,
    };
    Ok((fp, caps))
}

fn kernel_supports_memfd(kernel: &str) -> bool {
    // memfd_create since Linux 3.17 — parse major.minor loosely.
    let mut parts = kernel.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    major > 3 || (major == 3 && minor >= 17)
}

/// Connect, fingerprint, select the matching agentless binary, deliver, stream, disconnect.
pub async fn remote_scan(opts: RemoteScanOpts<'_>) -> Result<RemoteScanResult, TransportError> {
    if opts.probe_catalog.is_none() && opts.probe_elf.is_empty() {
        return Err(TransportError::Delivery(
            "empty probe elf (provide --probe or a probe catalog)".into(),
        ));
    }

    let session = SshSession::connect(ConnectOpts {
        host: opts.host,
        port: opts.port,
        username: opts.username,
        credential: opts.credential,
        policy: opts.policy.clone(),
        timeouts: opts.timeouts.clone(),
    })
    .await?;
    let presented_host_key = session.presented_host_key.clone();

    let (fingerprint, caps) = probe_capabilities(&session).await?;

    // Skip sudo when the SSH session is already root.
    let sudo = if fingerprint.euid == Some(0) {
        SudoEscalation::None
    } else {
        opts.sudo.clone()
    };
    if sudo.is_enabled() {
        verify_sudo(&session, &sudo).await?;
    }

    let plan = select_delivery_method(&caps);

    let (probe_elf, loader_elf, probe_arch, probe_triple) = if let Some(catalog) = opts.probe_catalog
    {
        let art = catalog.select(fingerprint.arch)?;
        (
            art.probe.as_slice(),
            art.loader.as_deref(),
            Some(art.arch.as_str().to_string()),
            Some(art.triple.clone()),
        )
    } else {
        (opts.probe_elf, opts.loader_elf, None, None)
    };

    let request = build_request(&opts);
    let request_line = serde_json::to_vec(&request)
        .map_err(|e| TransportError::Delivery(format!("encode request: {e}")))?;
    let mut request_line = request_line;
    request_line.push(b'\n');

    // Average-rate shaping for probe + ScanRequest bytes over SSH.
    let transfer_bytes = probe_elf.len()
        + loader_elf.map(|l| l.len()).unwrap_or(0)
        + request_line.len();
    pace_transfer(transfer_bytes, opts.limits.max_transfer_bps).await;

    let (stdout, stderr, method_used, fallback_reason) = match plan.method {
        DeliveryMethod::Memfd if loader_elf.is_some() => {
            let staging = caps.staging_dir.as_deref().unwrap_or("/tmp");
            match deliver_method_a(
                &session,
                loader_elf.unwrap(),
                probe_elf,
                &request_line,
                staging,
                &sudo,
            )
            .await
            {
                Ok(v) => (v.0, v.1, DeliveryMethod::Memfd, None),
                Err(e) => {
                    let reason = format!("memfd failed: {e}; falling back to tmpfs");
                    let (o, e2) =
                        deliver_method_b(&session, probe_elf, &request_line, &caps, &sudo).await?;
                    (o, e2, DeliveryMethod::Tmpfs, Some(reason))
                }
            }
        }
        DeliveryMethod::Memfd | DeliveryMethod::Tmpfs => {
            match deliver_method_b(&session, probe_elf, &request_line, &caps, &sudo).await {
                Ok((o, e)) => (o, e, DeliveryMethod::Tmpfs, None),
                Err(e) => {
                    let reason = format!("tmpfs failed: {e}; falling back to pure-command");
                    let (o, e2) = deliver_method_d(&session).await?;
                    (o, e2, DeliveryMethod::PureCommand, Some(reason))
                }
            }
        }
        DeliveryMethod::Sftp => {
            return Err(TransportError::Delivery(
                "SFTP delivery not implemented in this build".into(),
            ));
        }
        DeliveryMethod::PureCommand => {
            let (o, e) = deliver_method_d(&session).await?;
            (
                o,
                e,
                DeliveryMethod::PureCommand,
                Some("no exec-capable staging dir or memfd".into()),
            )
        }
    };

    let _ = session.disconnect().await;

    let raw_stdout = String::from_utf8_lossy(&stdout).into_owned();
    let raw_stderr = String::from_utf8_lossy(&stderr).into_owned();
    let normalised = normalise_stream(&raw_stdout)?;

    Ok(RemoteScanResult {
        fingerprint,
        delivery: DeliveryOutcome {
            method: method_used,
            encoder: plan.encoder,
            bytes_transferred: probe_elf.len() as u64,
            cleanup_ok: true,
            fallback_reason,
        },
        normalised,
        raw_stdout,
        raw_stderr,
        presented_host_key,
        probe_arch,
        probe_triple,
    })
}

/// Method A: upload tiny loader to staging dir, exec it, stdin = [probe frame][ScanRequest].
async fn deliver_method_a(
    session: &SshSession,
    loader: &[u8],
    probe: &[u8],
    request_line: &[u8],
    staging_dir: &str,
    sudo: &SudoEscalation<'_>,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let tag = now_ms();
    let path = format!("{staging_dir}/.rustmite-loader-{tag}");
    let upload_cmd = format!("cat > {path} && chmod 755 {path}");
    let (o, e, code) = session.exec(&upload_cmd, Some(loader)).await?;
    if code != 0 {
        return Err(TransportError::Delivery(format!(
            "loader upload failed: {} / {}",
            String::from_utf8_lossy(&o),
            String::from_utf8_lossy(&e)
        )));
    }

    let mut payload = encode_probe_frame(probe);
    payload.extend_from_slice(request_line);
    let (run_cmd, stdin) = wrap_sudo_exec(&path, sudo, &payload)?;
    let (stdout, stderr, code) = session.exec(&run_cmd, Some(&stdin)).await?;
    if code != 0 || stdout.is_empty() {
        return Err(TransportError::Delivery(format!(
            "loader/probe exit {code}: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok((stdout, stderr))
}

/// Method B: write probe to exec-capable staging dir, exec with ScanRequest on stdin, unlink.
async fn deliver_method_b(
    session: &SshSession,
    probe: &[u8],
    request_line: &[u8],
    caps: &HostCapabilities,
    sudo: &SudoEscalation<'_>,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let Some(dir) = caps.staging_dir.as_deref() else {
        return Err(TransportError::Delivery(
            "no exec-capable writable dir for Method B".into(),
        ));
    };
    let tag = now_ms();
    let path = format!("{dir}/.rustmite-probe-{tag}");
    let upload_cmd = format!("cat > {path} && chmod 755 {path}");
    let (_o, e, code) = session.exec(&upload_cmd, Some(probe)).await?;
    if code != 0 {
        return Err(TransportError::Delivery(format!(
            "probe upload failed: {}",
            String::from_utf8_lossy(&e)
        )));
    }
    let (run_cmd, stdin) = wrap_sudo_exec(&path, sudo, request_line)?;
    let (stdout, stderr, code) = session.exec(&run_cmd, Some(&stdin)).await?;
    if code != 0 || stdout.is_empty() {
        return Err(TransportError::Delivery(format!(
            "probe exit {code}: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok((stdout, stderr))
}

async fn verify_sudo(
    session: &SshSession,
    sudo: &SudoEscalation<'_>,
) -> Result<(), TransportError> {
    match sudo {
        SudoEscalation::None => Ok(()),
        SudoEscalation::Nopasswd => {
            let (out, err, code) = session
                .exec("sudo -n -p '' true && sudo -n -p '' id -u", None)
                .await?;
            if code != 0 {
                return Err(TransportError::Delivery(format!(
                    "sudo -n failed (need NOPASSWD for this user): {}",
                    String::from_utf8_lossy(if err.is_empty() { &out } else { &err })
                )));
            }
            let text = String::from_utf8_lossy(&out);
            if !text.lines().any(|l| l.trim() == "0") {
                return Err(TransportError::Delivery(format!(
                    "sudo -n did not yield euid 0: {}",
                    text.trim()
                )));
            }
            Ok(())
        }
        SudoEscalation::Password { password } => {
            if password.is_empty() {
                return Err(TransportError::Delivery(
                    "sudo password is empty".into(),
                ));
            }
            if password.contains('\n') || password.contains('\r') {
                return Err(TransportError::Delivery(
                    "sudo password must not contain newlines".into(),
                ));
            }
            let mut stdin = password.as_bytes().to_vec();
            stdin.push(b'\n');
            let (out, err, code) = session
                .exec("sudo -S -p '' id -u", Some(&stdin))
                .await?;
            if code != 0 {
                return Err(TransportError::Delivery(format!(
                    "sudo -S failed (bad password or sudoers?): {}",
                    String::from_utf8_lossy(if err.is_empty() { &out } else { &err })
                )));
            }
            let text = String::from_utf8_lossy(&out);
            if !text.lines().any(|l| l.trim() == "0") {
                return Err(TransportError::Delivery(format!(
                    "sudo -S did not yield euid 0: {}",
                    text.trim()
                )));
            }
            Ok(())
        }
    }
}

/// Run `path` (optionally via sudo); always unlink afterward as the SSH user.
/// For password sudo, prepend `password\\n` so `sudo -S` can authenticate, then
/// the remaining stdin is the probe payload.
fn wrap_sudo_exec(
    path: &str,
    sudo: &SudoEscalation<'_>,
    payload: &[u8],
) -> Result<(String, Vec<u8>), TransportError> {
    let exec = match sudo {
        SudoEscalation::None => path.to_string(),
        SudoEscalation::Nopasswd => format!("sudo -n -p '' {path}"),
        SudoEscalation::Password { .. } => format!("sudo -S -p '' {path}"),
    };
    let cmd = format!("{exec}; ec=$?; rm -f {path}; exit $ec");
    match sudo {
        SudoEscalation::None | SudoEscalation::Nopasswd => Ok((cmd, payload.to_vec())),
        SudoEscalation::Password { password } => {
            if password.is_empty() {
                return Err(TransportError::Delivery("sudo password is empty".into()));
            }
            if password.contains('\n') || password.contains('\r') {
                return Err(TransportError::Delivery(
                    "sudo password must not contain newlines".into(),
                ));
            }
            let mut stdin = Vec::with_capacity(password.len() + 1 + payload.len());
            stdin.extend_from_slice(password.as_bytes());
            stdin.push(b'\n');
            stdin.extend_from_slice(payload);
            Ok((cmd, stdin))
        }
    }
}

/// Method D: read-only shell commands from the node; emit RM-POL-0021 policy observation.
async fn deliver_method_d(session: &SshSession) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    use rustmite_proto::{
        CapabilitySet, Envelope, Hello, Observation, PolicyObs, SCHEMA_VERSION, Severity, Summary,
    };

    let (uname_out, _, _) = session.exec("uname -srm; id -u; id -un", None).await?;
    let text = String::from_utf8_lossy(&uname_out);
    let fp = parse_uname_hint(&text);
    let _ = session
        .exec("head -n 50 /etc/passwd 2>/dev/null || true", None)
        .await?;

    let hello = Envelope::Hello(Hello {
        schema: SCHEMA_VERSION,
        probe_version: "pure-command".into(),
        arch: fp.arch,
        kernel: fp.kernel.clone(),
        boot_id: "unknown".into(),
        euid: fp.euid.unwrap_or(0),
        pid: 0,
        nonce: "00".repeat(32),
        caps: CapabilitySet::default(),
    });
    let policy = Envelope::Obs {
        c: "policy".into(),
        n: 0,
        d: Observation::Policy(PolicyObs {
            code: "RM-POL-0021".into(),
            detail: "host could not be inspected with full-fidelity probe (no memfd/tmpfs exec)"
                .into(),
            severity: Severity::High,
        }),
    };
    let summary = Envelope::Summary(Summary {
        outcome: "complete".into(),
        collectors: vec![],
        observation_count: 1,
        bytes_out: 0,
        elapsed_ms: 0,
    });

    let mut out = Vec::new();
    for env in [hello, policy, summary] {
        let line = serde_json::to_vec(&env)
            .map_err(|e| TransportError::Delivery(format!("encode: {e}")))?;
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    Ok((out, Vec::new()))
}
