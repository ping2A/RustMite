//! russh client session with host-key pinning and command/delivery helpers.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{
    decode_secret_key, load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
};
use russh::{client, ChannelMsg, Disconnect, Preferred};
use tokio::time::timeout;

use crate::error::TransportError;
use crate::hostkey::{HostKeyAction, HostKeyPolicy, HostKeyRecord, HostKeyReject};
use crate::timeouts::SshTimeouts;

#[derive(Clone)]
struct KeyGate {
    policy: HostKeyPolicy,
    /// Filled during handshake so callers can pin TOFU keys.
    presented: Arc<Mutex<Option<HostKeyRecord>>>,
    reject: Arc<Mutex<Option<HostKeyReject>>>,
}

struct ClientHandler {
    gate: KeyGate,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let record = HostKeyRecord {
            key_type: key.algorithm().to_string(),
            fingerprint: format!("{}", key.fingerprint(HashAlg::Sha256)),
        };
        if let Ok(mut g) = self.gate.presented.lock() {
            *g = Some(record.clone());
        }
        match self.gate.policy.check(&record) {
            Ok(HostKeyAction::Accept) | Ok(HostKeyAction::PinNew(_)) => Ok(true),
            Err(rej) => {
                if let Ok(mut g) = self.gate.reject.lock() {
                    *g = Some(rej);
                }
                Ok(false)
            }
        }
    }
}

/// How the client authenticates after the SSH handshake.
#[derive(Clone, Copy, Debug)]
pub enum SshCredential<'a> {
    /// OpenSSH / PEM private key on disk.
    PublicKey { identity: &'a Path },
    /// OpenSSH / PEM private key already in memory (vault-unsealed / lease material).
    PublicKeyPem { pem: &'a str },
    /// Username/password (keyboard/password auth).
    Password { password: &'a str },
}

impl<'a> SshCredential<'a> {
    pub fn method_name(self) -> &'static str {
        match self {
            Self::PublicKey { .. } | Self::PublicKeyPem { .. } => "publickey",
            Self::Password { .. } => "password",
        }
    }
}

/// Authenticated SSH session used for fingerprinting and probe delivery.
pub struct SshSession {
    handle: client::Handle<ClientHandler>,
    pub presented_host_key: Option<HostKeyRecord>,
    timeouts: SshTimeouts,
}

pub struct ConnectOpts<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub credential: SshCredential<'a>,
    pub policy: HostKeyPolicy,
    pub timeouts: SshTimeouts,
}

impl SshSession {
    pub async fn connect(opts: ConnectOpts<'_>) -> Result<Self, TransportError> {
        if !opts.timeouts.connect_delay.is_zero() {
            tokio::time::sleep(opts.timeouts.connect_delay).await;
        }

        let gate = KeyGate {
            policy: opts.policy,
            presented: Arc::new(Mutex::new(None)),
            reject: Arc::new(Mutex::new(None)),
        };

        let config = client::Config {
            inactivity_timeout: Some(opts.timeouts.inactivity),
            preferred: Preferred::default(),
            ..Default::default()
        };

        let addr = (opts.host, opts.port);
        let handler = ClientHandler { gate: gate.clone() };
        let connect_fut = client::connect(Arc::new(config), addr, handler);
        let mut handle = timeout(opts.timeouts.connect, connect_fut)
            .await
            .map_err(|_| TransportError::Timeout("tcp/ssh connect".into()))?
            .map_err(|e| {
                if let Ok(g) = gate.reject.lock() {
                    if let Some(HostKeyReject::Changed { expected, got }) = g.clone() {
                        return TransportError::HostKeyChanged { expected, got };
                    }
                    if let Some(HostKeyReject::NoPin) = g.clone() {
                        return TransportError::Ssh("host key not pinned (TOFU disabled)".into());
                    }
                }
                TransportError::Ssh(format!("connect: {e}"))
            })?;

        match opts.credential {
            SshCredential::PublicKey { identity } => {
                let key_pair = load_secret_key(identity, None)
                    .map_err(|e| TransportError::Auth(format!("load key: {e}")))?;
                Self::auth_publickey(&mut handle, opts.username, key_pair, opts.timeouts.auth)
                    .await?;
            }
            SshCredential::PublicKeyPem { pem } => {
                let key_pair = decode_secret_key(pem, None)
                    .map_err(|e| TransportError::Auth(format!("decode key: {e}")))?;
                Self::auth_publickey(&mut handle, opts.username, key_pair, opts.timeouts.auth)
                    .await?;
            }
            SshCredential::Password { password } => {
                if password.is_empty() {
                    return Err(TransportError::Auth("empty password".into()));
                }
                let auth_fut = handle.authenticate_password(opts.username, password);
                let auth = timeout(opts.timeouts.auth, auth_fut)
                    .await
                    .map_err(|_| TransportError::Timeout("ssh auth".into()))?
                    .map_err(|e| TransportError::Auth(e.to_string()))?;
                if !auth.success() {
                    return Err(TransportError::Auth("password rejected".into()));
                }
            }
        }

        let presented = gate.presented.lock().ok().and_then(|g| g.clone());

        Ok(Self {
            handle,
            presented_host_key: presented,
            timeouts: opts.timeouts,
        })
    }

    async fn auth_publickey(
        handle: &mut client::Handle<ClientHandler>,
        username: &str,
        key_pair: russh::keys::PrivateKey,
        auth_timeout: Duration,
    ) -> Result<(), TransportError> {
        let auth_fut = handle.authenticate_publickey(
            username,
            PrivateKeyWithHashAlg::new(
                Arc::new(key_pair),
                handle
                    .best_supported_rsa_hash()
                    .await
                    .ok()
                    .flatten()
                    .flatten(),
            ),
        );
        let auth = timeout(auth_timeout, auth_fut)
            .await
            .map_err(|_| TransportError::Timeout("ssh auth".into()))?
            .map_err(|e| TransportError::Auth(e.to_string()))?;
        if !auth.success() {
            return Err(TransportError::Auth("publickey rejected".into()));
        }
        Ok(())
    }

    /// Run a remote command; return (stdout, stderr, exit_status).
    pub async fn exec(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>, u32), TransportError> {
        self.exec_timeout(command, stdin, self.timeouts.command)
            .await
    }

    pub async fn exec_timeout(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
        cmd_timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>, u32), TransportError> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| TransportError::Ssh(format!("channel: {e}")))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| TransportError::Ssh(format!("exec: {e}")))?;

        if let Some(data) = stdin {
            channel
                .data(&data[..])
                .await
                .map_err(|e| TransportError::Ssh(format!("stdin: {e}")))?;
        }
        channel
            .eof()
            .await
            .map_err(|e| TransportError::Ssh(format!("eof: {e}")))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = 0u32;

        let collect = async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { ref data }) => stdout.extend_from_slice(data),
                    Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                        stderr.extend_from_slice(data)
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => status = exit_status,
                    Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
            Ok::<_, TransportError>((stdout, stderr, status))
        };

        timeout(cmd_timeout, collect)
            .await
            .map_err(|_| TransportError::Timeout("remote command".into()))?
    }

    pub async fn disconnect(self) -> Result<(), TransportError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| TransportError::Ssh(format!("disconnect: {e}")))
    }
}
