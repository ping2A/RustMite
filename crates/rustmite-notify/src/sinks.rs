use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use rustmite_proto::Severity;
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;

use crate::AlertEvent;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("sink: {0}")]
    Other(String),
}

pub trait NotifySink: Send + Sync {
    fn notify(&self, event: &AlertEvent) -> Result<(), NotifyError>;
    fn name(&self) -> &str;
}

/// HTTP POST with `X-RustMite-Signature: sha256=<hex>` HMAC-SHA256 of the body.
pub struct WebhookSink {
    pub url: String,
    pub secret: Vec<u8>,
    pub header_name: String,
}

impl WebhookSink {
    pub fn new(url: impl Into<String>, secret: impl AsRef<[u8]>) -> Self {
        Self {
            url: url.into(),
            secret: secret.as_ref().to_vec(),
            header_name: "X-RustMite-Signature".into(),
        }
    }

    pub fn sign_body(&self, body: &[u8]) -> Result<String, NotifyError> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NotifyError::Crypto(e.to_string()))?;
        mac.update(body);
        let sig = mac.finalize().into_bytes();
        Ok(format!("sha256={}", hex::encode(sig)))
    }
}

impl NotifySink for WebhookSink {
    fn notify(&self, event: &AlertEvent) -> Result<(), NotifyError> {
        let body = serde_json::to_vec(event).map_err(|e| NotifyError::Other(e.to_string()))?;
        let sig = self.sign_body(&body)?;
        let client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| NotifyError::Http(e.to_string()))?;
        let resp = client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header(&self.header_name, sig)
            .body(body)
            .send()
            .map_err(|e| NotifyError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(NotifyError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// Formats an RFC5424-ish syslog line.
pub struct SyslogSink {
    writer: Mutex<Box<dyn Write + Send>>,
    app_name: String,
    hostname: String,
}

impl SyslogSink {
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Mutex::new(Box::new(writer)),
            app_name: "rustmite".into(),
            hostname: "localhost".into(),
        }
    }

    pub fn with_identity(mut self, hostname: impl Into<String>, app: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self.app_name = app.into();
        self
    }

    pub fn format_line(hostname: &str, app: &str, event: &AlertEvent) -> String {
        let pri = severity_pri(event.severity);
        let ts = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let msg = serde_json::to_string(event).unwrap_or_else(|_| "{}".into());
        // RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        format!("<{pri}>1 {ts} {hostname} {app} - - - {msg}")
    }
}

fn severity_pri(s: Severity) -> u8 {
    // facility local0 (16) * 8 + severity
    let sev = match s {
        Severity::Critical => 2, // critical
        Severity::High => 3,     // error
        Severity::Medium => 4,   // warning
        Severity::Low => 5,      // notice
        Severity::Info => 6,     // informational
    };
    16 * 8 + sev
}

impl NotifySink for SyslogSink {
    fn notify(&self, event: &AlertEvent) -> Result<(), NotifyError> {
        let line = Self::format_line(&self.hostname, &self.app_name, event);
        let mut w = self
            .writer
            .lock()
            .map_err(|e| NotifyError::Other(e.to_string()))?;
        writeln!(w, "{line}")?;
        Ok(())
    }

    fn name(&self) -> &str {
        "syslog"
    }
}

/// Append one JSON object per line to a file.
pub struct NdjsonFileSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl NdjsonFileSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NotifyError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl NotifySink for NdjsonFileSink {
    fn notify(&self, event: &AlertEvent) -> Result<(), NotifyError> {
        let mut f = self
            .file
            .lock()
            .map_err(|e| NotifyError::Other(e.to_string()))?;
        serde_json::to_writer(&mut *f, event).map_err(|e| NotifyError::Other(e.to_string()))?;
        f.write_all(b"\n")?;
        Ok(())
    }

    fn name(&self) -> &str {
        "ndjson_file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::Severity;

    #[test]
    fn webhook_hmac_stable() {
        let sink = WebhookSink::new("http://example.invalid/hook", b"secret");
        let sig = sink.sign_body(b"{\"a\":1}").unwrap();
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }

    #[test]
    fn syslog_line_contains_pri_and_json() {
        let event = AlertEvent {
            severity: Severity::High,
            title: "t".into(),
            body: serde_json::json!({}),
            finding: None,
        };
        let line = SyslogSink::format_line("h", "rustmite", &event);
        assert!(line.starts_with("<"));
        assert!(line.contains("rustmite"));
        assert!(line.contains("\"severity\""));
    }

    #[test]
    fn ndjson_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.ndjson");
        let sink = NdjsonFileSink::open(&path).unwrap();
        sink.notify(&AlertEvent {
            severity: Severity::Info,
            title: "hi".into(),
            body: serde_json::json!({"x": 1}),
            finding: None,
        })
        .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"hi\""));
        assert!(contents.ends_with('\n'));
    }
}
