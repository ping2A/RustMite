//! Check loading and evaluation errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("expression error in check {check_id}: {source}")]
    Expr {
        check_id: String,
        #[source]
        source: rustmite_expr::ExprError,
    },

    #[error("unknown match stream: {0}")]
    UnknownMatch(String),

    #[error("invalid manifest: {0}")]
    Invalid(String),
}
