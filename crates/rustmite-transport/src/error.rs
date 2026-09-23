use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("host key changed: expected {expected}, got {got}")]
    HostKeyChanged { expected: String, got: String },
    #[error("auth failed: {0}")]
    Auth(String),
    #[error("delivery failed: {0}")]
    Delivery(String),
    #[error("ingest: {0}")]
    Ingest(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
