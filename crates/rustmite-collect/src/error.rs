//! Collector errors.

use rustmite_proto::BudgetExceeded;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollectError {
    #[error("budget exceeded: {0:?}")]
    Budget(BudgetExceeded),
    #[error("sys: {0}")]
    Sys(#[from] rustmite_sys::SysError),
    #[error("errno: {0}")]
    Errno(rustmite_sys::Errno),
    #[error("{0}")]
    Message(String),
}

impl From<BudgetExceeded> for CollectError {
    fn from(e: BudgetExceeded) -> Self {
        Self::Budget(e)
    }
}

impl From<rustmite_sys::Errno> for CollectError {
    fn from(e: rustmite_sys::Errno) -> Self {
        Self::Errno(e)
    }
}

impl CollectError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}
