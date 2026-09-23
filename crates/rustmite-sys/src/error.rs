//! Error types — no panics, checked everywhere.

use alloc::string::String;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    NotFound,
    PermissionDenied,
    InvalidInput,
    NotSupported,
    WouldBlock,
    Busy,
    Io,
    Other(i32),
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::NotSupported => write!(f, "not supported"),
            Self::WouldBlock => write!(f, "would block"),
            Self::Busy => write!(f, "busy"),
            Self::Io => write!(f, "io error"),
            Self::Other(c) => write!(f, "errno {c}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SysError {
    #[error("{0}")]
    Errno(Errno),
    #[error("{0}")]
    Message(String),
}

impl From<Errno> for SysError {
    fn from(e: Errno) -> Self {
        Self::Errno(e)
    }
}

impl SysError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}
