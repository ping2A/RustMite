//! TLS 1.3 (`rustls`) helpers for the operator and node listeners.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;

/// PEM certificate + private key paths for a TLS listener.
#[derive(Clone, Debug)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// When set, require and verify client certificates (mTLS).
    pub client_ca: Option<PathBuf>,
    /// True when the pair was auto-generated for local/dev use.
    pub auto_generated: bool,
}

impl TlsPaths {
    pub fn new(cert: PathBuf, key: PathBuf) -> Self {
        Self {
            cert,
            key,
            client_ca: None,
            auto_generated: false,
        }
    }

    pub fn with_client_ca(mut self, ca: PathBuf) -> Self {
        self.client_ca = Some(ca);
        self
    }
}

/// Default relative directory for auto-generated self-signed PEMs.
pub const DEFAULT_TLS_DIR: &str = ".dev/tls";

/// Ensure a self-signed cert/key exist under `dir` (create on first run).
///
/// Default SANs: `localhost`, `127.0.0.1`, `::1`, plus `$HOSTNAME` and `extra`.
/// Reuses existing PEMs when both files are present.
pub fn ensure_dev_certs(dir: impl AsRef<Path>) -> anyhow::Result<TlsPaths> {
    ensure_dev_certs_with_sans(dir, &[] as &[String])
}

pub fn ensure_dev_certs_with_sans(
    dir: impl AsRef<Path>,
    extra: &[String],
) -> anyhow::Result<TlsPaths> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir).with_context(|| format!("create TLS dir {}", dir.display()))?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let sans = default_dev_sans(extra);

    if cert_path.is_file() && key_path.is_file() {
        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "reusing auto-generated TLS certificates"
        );
        return Ok(TlsPaths {
            cert: cert_path,
            key: key_path,
            client_ca: None,
            auto_generated: true,
        });
    }

    tracing::info!(
        dir = %dir.display(),
        sans = ?sans,
        "generating self-signed TLS certificate"
    );
    let (cert_pem, key_pem) = generate_self_signed_pem(&sans)?;
    fs::write(&cert_path, cert_pem.as_bytes())
        .with_context(|| format!("write {}", cert_path.display()))?;
    fs::write(&key_path, key_pem.as_bytes())
        .with_context(|| format!("write {}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }

    Ok(TlsPaths {
        cert: cert_path,
        key: key_path,
        client_ca: None,
        auto_generated: true,
    })
}

fn default_dev_sans(extra: &[String]) -> Vec<String> {
    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(h) = std::env::var("HOSTNAME") {
        push_san(&mut sans, h.trim());
    }
    for s in extra {
        push_san(&mut sans, s.trim());
    }
    sans
}

fn push_san(sans: &mut Vec<String>, name: &str) {
    if name.is_empty() {
        return;
    }
    if !sans.iter().any(|s| s == name) {
        sans.push(name.to_string());
    }
}

fn generate_self_signed_pem(sans: &[String]) -> anyhow::Result<(String, String)> {
    let mut params =
        rcgen::CertificateParams::new(sans.to_vec()).context("build certificate params")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "RustMite Dev");
    let key_pair = KeyPair::generate().context("generate TLS key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign development certificate")?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Load a rustls `ServerConfig`: TLS 1.3 only, ALPN `h2` + `http/1.1`.
pub fn load_server_config(paths: &TlsPaths) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = load_certs(&paths.cert)
        .with_context(|| format!("read TLS certificate {}", paths.cert.display()))?;
    let key = load_private_key(&paths.key)
        .with_context(|| format!("read TLS private key {}", paths.key.display()))?;

    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let mut config = if let Some(ref ca_path) = paths.client_ca {
        let roots = load_root_store(ca_path)
            .with_context(|| format!("read TLS client CA {}", ca_path.display()))?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build mTLS client verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("install TLS certificate/key (mTLS)")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("install TLS certificate/key")?
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub async fn rustls_config(paths: &TlsPaths) -> anyhow::Result<RustlsConfig> {
    let cfg = load_server_config(paths)?;
    Ok(RustlsConfig::from_config(cfg))
}

/// Serve an axum `Router` over TLS on `addr`.
pub async fn serve_tls(
    addr: std::net::SocketAddr,
    app: Router,
    paths: &TlsPaths,
) -> anyhow::Result<()> {
    let config = rustls_config(paths).await?;
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .with_context(|| format!("TLS serve on {addr}"))
}

/// Serve an axum `Router` in cleartext (local/dev).
pub async fn serve_plain(addr: std::net::SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    axum::serve(listener, app)
        .await
        .with_context(|| format!("HTTP serve on {addr}"))
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open certificate PEM {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate PEM {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("parse private key PEM {}", path.display()))
}

fn load_root_store(path: &Path) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certs = load_certs(path)?;
    for cert in certs {
        roots
            .add(cert)
            .with_context(|| format!("add CA cert from {}", path.display()))?;
    }
    if roots.is_empty() {
        bail!("no CA certificates found in {}", path.display());
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cert_errors() {
        let paths = TlsPaths::new(
            PathBuf::from("/no/such/cert.pem"),
            PathBuf::from("/no/such/key.pem"),
        );
        assert!(load_server_config(&paths).is_err());
    }

    #[test]
    fn ensure_dev_certs_creates_and_reuses() {
        let dir = std::env::temp_dir().join(format!(
            "rustmite-tls-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let first = ensure_dev_certs(&dir).expect("generate");
        assert!(first.cert.is_file());
        assert!(first.key.is_file());
        assert!(first.auto_generated);
        let cert1 = fs::read(&first.cert).unwrap();
        let second = ensure_dev_certs(&dir).expect("reuse");
        assert_eq!(cert1, fs::read(&second.cert).unwrap());
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(load_server_config(&second).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
