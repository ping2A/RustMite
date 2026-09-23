//! Lightweight host reachability probes (no full scan).

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::TransportError;
use crate::fingerprint::HostSystemInfo;
#[cfg(feature = "ssh")]
use crate::hostkey::HostKeyPolicy;
use crate::hostkey::HostKeyRecord;
use crate::timeouts::SshTimeouts;

#[cfg(feature = "ssh")]
use crate::ssh::{ConnectOpts, SshCredential, SshSession};

#[derive(Clone, Debug, Serialize)]
pub struct ConnectivityStage {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectivityReport {
    pub ok: bool,
    /// High-level status for the host record / UI.
    /// `ok` | `unreachable` | `no_sshd` | `auth_failed` | `no_credential` | `partial`
    pub auth_status: String,
    pub stages: Vec<ConnectivityStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Which auth method succeeded (`publickey` / `password`), when login was tested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
}

fn report(
    ok: bool,
    auth_status: impl Into<String>,
    stages: Vec<ConnectivityStage>,
    host_key: Option<&HostKeyRecord>,
    sys: &HostSystemInfo,
    auth_method: Option<String>,
) -> ConnectivityReport {
    ConnectivityReport {
        ok,
        auth_status: auth_status.into(),
        stages,
        host_key_type: host_key.map(|h| h.key_type.clone()),
        host_key_fingerprint: host_key.map(|h| h.fingerprint.clone()),
        uname: sys.uname.clone(),
        arch: sys.arch.clone(),
        kernel: sys.kernel.clone(),
        os: sys.os.clone(),
        os_id: sys.os_id.clone(),
        os_version: sys.os_version.clone(),
        auth_method,
    }
}

pub struct ConnectivityTestOpts<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: Option<&'a str>,
    /// Preferred when both identity and password are set.
    pub identity: Option<&'a Path>,
    /// In-memory PEM (vault-unsealed). Preferred over `identity` path when set.
    pub identity_pem: Option<&'a str>,
    pub password: Option<&'a str>,
    pub timeouts: SshTimeouts,
    /// When true and no credential is provided, still report `no_credential` after a successful TCP/SSH banner.
    pub require_auth: bool,
}

fn stage(name: &str, ok: bool, detail: impl Into<String>, started: Instant) -> ConnectivityStage {
    ConnectivityStage {
        name: name.into(),
        ok,
        detail: detail.into(),
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

/// TCP connect + read SSH identification string (RFC 4253).
pub async fn probe_tcp_ssh_banner(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<(String, u64, u64), TransportError> {
    let t0 = Instant::now();
    let addr = format!("{host}:{port}");
    let mut stream = timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| TransportError::Timeout(format!("tcp connect {addr}")))?
        .map_err(|e| TransportError::Io(e))?;
    let connect_ms = t0.elapsed().as_millis() as u64;

    let t1 = Instant::now();
    // SSH servers speak first with "SSH-2.0-...\r\n"
    let mut buf = [0u8; 256];
    let n = timeout(connect_timeout, stream.read(&mut buf))
        .await
        .map_err(|_| TransportError::Timeout("ssh banner".into()))?
        .map_err(TransportError::Io)?;
    if n == 0 {
        return Err(TransportError::Ssh("empty banner (port open but not SSH?)".into()));
    }
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if !banner.starts_with("SSH-") {
        return Err(TransportError::Ssh(format!(
            "not an SSH banner: {:?}",
            banner.chars().take(64).collect::<String>()
        )));
    }
    // Be polite: send our ID then drop (enough for a smoke test).
    let _ = timeout(
        Duration::from_secs(2),
        stream.write_all(b"SSH-2.0-RustMiteProbe_0.1\r\n"),
    )
    .await;
    let banner_ms = t1.elapsed().as_millis() as u64;
    Ok((banner, connect_ms, banner_ms))
}

fn no_cred_report(
    stages: Vec<ConnectivityStage>,
    require_auth: bool,
    detail: &str,
) -> ConnectivityReport {
    let mut stages = stages;
    stages.push(stage("ssh_auth", false, detail, Instant::now()));
    let auth_status = if require_auth {
        "no_credential"
    } else {
        "partial"
    };
    report(
        !require_auth,
        auth_status,
        stages,
        None,
        &HostSystemInfo::default(),
        None,
    )
}

#[cfg(feature = "ssh")]
const SYSTEM_PROBE_CMD: &str = r#"uname -srm 2>/dev/null || uname -a
echo ---OS---
cat /etc/os-release 2>/dev/null || true
"#;

/// Operator "Test connection" — TCP/SSH banner, optional key/password login + system probe.
pub async fn test_host_connectivity(
    opts: ConnectivityTestOpts<'_>,
) -> Result<ConnectivityReport, TransportError> {
    let mut stages = Vec::new();
    let host = opts.host.trim();
    if host.is_empty() {
        return Ok(report(
            false,
            "unreachable",
            vec![stage(
                "validate",
                false,
                "host address is required",
                Instant::now(),
            )],
            None,
            &HostSystemInfo::default(),
            None,
        ));
    }

    let t_tcp = Instant::now();
    let banner = match probe_tcp_ssh_banner(host, opts.port, opts.timeouts.connect).await {
        Ok((banner, connect_ms, banner_ms)) => {
            stages.push(ConnectivityStage {
                name: "tcp_connect".into(),
                ok: true,
                detail: format!("{host}:{} reachable", opts.port),
                duration_ms: connect_ms,
            });
            stages.push(ConnectivityStage {
                name: "ssh_banner".into(),
                ok: true,
                detail: banner.clone(),
                duration_ms: banner_ms,
            });
            banner
        }
        Err(e) => {
            let detail = e.to_string();
            let auth_status = if detail.contains("not an SSH") || detail.contains("empty banner") {
                "no_sshd"
            } else {
                "unreachable"
            };
            stages.push(stage("tcp_connect", false, detail, t_tcp));
            return Ok(report(
                false,
                auth_status,
                stages,
                None,
                &HostSystemInfo::default(),
                None,
            ));
        }
    };
    let _ = banner;

    let username = opts.username.map(str::trim).filter(|s| !s.is_empty());
    let identity_pem = opts
        .identity_pem
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let identity = opts.identity.filter(|p| p.as_os_str().len() > 0);
    let password = opts
        .password
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let has_key = identity_pem.is_some() || identity.is_some();

    match (username, has_key, password) {
        (None, _, _) => {
            return Ok(no_cred_report(
                stages,
                opts.require_auth,
                if !has_key && password.is_none() {
                    "No SSH username or credential configured — TCP/SSH reachable, but login was not tested"
                } else {
                    "SSH username missing — login not tested"
                },
            ));
        }
        (Some(_), false, None) => {
            return Ok(no_cred_report(
                stages,
                opts.require_auth,
                "SSH identity key or password required — login not tested",
            ));
        }
        (Some(user), _key_ok, pw) => {
            #[cfg(not(feature = "ssh"))]
            {
                let _ = (user, pw, identity_pem, identity);
                stages.push(stage(
                    "ssh_auth",
                    false,
                    "server built without transport ssh feature",
                    Instant::now(),
                ));
                return Ok(report(
                    false,
                    "auth_failed",
                    stages,
                    None,
                    &HostSystemInfo::default(),
                    None,
                ));
            }

            #[cfg(feature = "ssh")]
            {
                let cred = match (identity_pem, identity, pw) {
                    (Some(pem), _, _) => SshCredential::PublicKeyPem { pem },
                    (None, Some(path), _) => SshCredential::PublicKey { identity: path },
                    (None, None, Some(p)) => SshCredential::Password { password: p },
                    (None, None, None) => unreachable!(),
                };
                if let SshCredential::PublicKey { identity } = cred {
                    if !identity.is_file() {
                        stages.push(stage(
                            "ssh_auth",
                            false,
                            format!("identity file not found: {}", identity.display()),
                            Instant::now(),
                        ));
                        return Ok(report(
                            false,
                            "no_credential",
                            stages,
                            None,
                            &HostSystemInfo::default(),
                            None,
                        ));
                    }
                }

                let method = cred.method_name();
                let t_auth = Instant::now();
                let session = match SshSession::connect(ConnectOpts {
                    host,
                    port: opts.port,
                    username: user,
                    credential: cred,
                    policy: HostKeyPolicy {
                        pinned: vec![],
                        allow_tofu: true,
                    },
                    timeouts: opts.timeouts.clone(),
                })
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        let detail = e.to_string();
                        let auth_status = if matches!(e, TransportError::Auth(_))
                            || detail.contains("auth")
                            || detail.contains("publickey")
                            || detail.contains("password")
                        {
                            "auth_failed"
                        } else if matches!(e, TransportError::Timeout(_)) {
                            "unreachable"
                        } else {
                            "auth_failed"
                        };
                        stages.push(stage("ssh_auth", false, detail, t_auth));
                        return Ok(report(
                            false,
                            auth_status,
                            stages,
                            None,
                            &HostSystemInfo::default(),
                            Some(method.into()),
                        ));
                    }
                };

                let hk = session.presented_host_key.clone();
                stages.push(stage(
                    "ssh_auth",
                    true,
                    format!("authenticated as {user} via {method}"),
                    t_auth,
                ));

                let t_cmd = Instant::now();
                let sys = match session
                    .exec_timeout(SYSTEM_PROBE_CMD, None, opts.timeouts.command)
                    .await
                {
                    Ok((stdout, _, code)) if code == 0 => {
                        let raw = String::from_utf8_lossy(&stdout);
                        let info = HostSystemInfo::from_probe_output(&raw);
                        let detail = info
                            .os
                            .as_deref()
                            .or(info.uname.as_deref())
                            .unwrap_or("ok");
                        stages.push(stage("system_probe", true, detail, t_cmd));
                        info
                    }
                    Ok((_, stderr, code)) => {
                        stages.push(stage(
                            "system_probe",
                            false,
                            format!(
                                "exit {code}: {}",
                                String::from_utf8_lossy(&stderr).trim()
                            ),
                            t_cmd,
                        ));
                        HostSystemInfo::default()
                    }
                    Err(e) => {
                        stages.push(stage("system_probe", false, e.to_string(), t_cmd));
                        HostSystemInfo::default()
                    }
                };

                let _ = session.disconnect().await;

                return Ok(report(
                    true,
                    "ok",
                    stages,
                    hk.as_ref(),
                    &sys,
                    Some(method.into()),
                ));
            }
        }
    }
}

/// Convenience for unit tests / callers that only need a HostKeyRecord pin.
pub fn host_key_record(key_type: String, fingerprint: String) -> HostKeyRecord {
    HostKeyRecord {
        key_type,
        fingerprint,
    }
}
