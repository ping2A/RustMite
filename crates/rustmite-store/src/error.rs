use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("backend: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;
