//! Shared enums.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckType {
    Process,
    File,
    User,
    Directory,
    Log,
    Policy,
    Incident,
    Recon,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorStatus {
    Complete,
    Truncated,
    Failed,
    Unsupported,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    Scan,
    Respond,
    Selftest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorCost {
    Trivial,
    Low,
    Medium,
    High,
    Forensic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
    Armv7,
    Armv5te,
    I686,
    Mips,
    Mipsel,
    Mips64,
    Riscv64,
    Ppc64le,
    S390x,
    Unknown,
}

impl Arch {
    pub fn from_uname(m: &str) -> Self {
        match m {
            "x86_64" | "amd64" => Self::X86_64,
            "aarch64" | "arm64" => Self::Aarch64,
            "armv7l" | "armv7" => Self::Armv7,
            "armv6l" | "arm" => Self::Armv5te,
            "i686" | "i386" => Self::I686,
            "mips" => Self::Mips,
            "mipsel" => Self::Mipsel,
            "mips64" | "mips64el" => Self::Mips64,
            "riscv64" => Self::Riscv64,
            "ppc64le" => Self::Ppc64le,
            "s390x" => Self::S390x,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Armv7 => "armv7",
            Self::Armv5te => "armv5te",
            Self::I686 => "i686",
            Self::Mips => "mips",
            Self::Mipsel => "mipsel",
            Self::Mips64 => "mips64",
            Self::Riscv64 => "riscv64",
            Self::Ppc64le => "ppc64le",
            Self::S390x => "s390x",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Acknowledged,
    Suppressed,
    Resolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMethod {
    Memfd,
    Tmpfs,
    Sftp,
    PureCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanOutcome {
    Complete,
    Partial {
        failed_collectors: alloc::vec::Vec<alloc::string::String>,
    },
    Timeout {
        elapsed_ms: u64,
    },
    ProbeCrashed {
        signal: Option<i32>,
        exit: Option<i32>,
        stderr_tail: alloc::string::String,
    },
    DeliveryFailed {
        reason: alloc::string::String,
    },
    AuthFailed {
        reason: alloc::string::String,
    },
    HostKeyChanged {
        expected: alloc::string::String,
        got: alloc::string::String,
    },
    Unreachable {
        reason: alloc::string::String,
    },
}
