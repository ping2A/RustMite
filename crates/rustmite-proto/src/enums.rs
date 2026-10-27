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
    /// Confirmed real alert (keep visible; triage complete).
    TruePositive,
    /// Benign / noise — hide from the default findings view.
    FalsePositive,
    Suppressed,
    Resolved,
}

impl FindingStatus {
    /// Parse UI / API status strings (accepts aliases like `tp` / `fp`).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "new" | "open" => Some(Self::New),
            "acknowledged" | "ack" => Some(Self::Acknowledged),
            "true_positive" | "true-positive" | "tp" | "confirmed" => Some(Self::TruePositive),
            "false_positive" | "false-positive" | "fp" | "benign" => Some(Self::FalsePositive),
            "suppressed" => Some(Self::Suppressed),
            "resolved" | "closed" => Some(Self::Resolved),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Acknowledged => "acknowledged",
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::Suppressed => "suppressed",
            Self::Resolved => "resolved",
        }
    }

    /// Hidden from the default findings list unless the operator asks for them.
    pub fn is_hidden_by_default(self) -> bool {
        matches!(self, Self::FalsePositive | Self::Suppressed)
    }
}

#[cfg(test)]
mod finding_status_tests {
    use super::FindingStatus;

    #[test]
    fn parse_canonical_and_aliases() {
        assert_eq!(FindingStatus::parse("new"), Some(FindingStatus::New));
        assert_eq!(FindingStatus::parse(" OPEN "), Some(FindingStatus::New));
        assert_eq!(FindingStatus::parse("ack"), Some(FindingStatus::Acknowledged));
        assert_eq!(
            FindingStatus::parse("acknowledged"),
            Some(FindingStatus::Acknowledged)
        );
        assert_eq!(FindingStatus::parse("tp"), Some(FindingStatus::TruePositive));
        assert_eq!(
            FindingStatus::parse("true-positive"),
            Some(FindingStatus::TruePositive)
        );
        assert_eq!(
            FindingStatus::parse("confirmed"),
            Some(FindingStatus::TruePositive)
        );
        assert_eq!(FindingStatus::parse("fp"), Some(FindingStatus::FalsePositive));
        assert_eq!(
            FindingStatus::parse("false_positive"),
            Some(FindingStatus::FalsePositive)
        );
        assert_eq!(FindingStatus::parse("benign"), Some(FindingStatus::FalsePositive));
        assert_eq!(
            FindingStatus::parse("suppressed"),
            Some(FindingStatus::Suppressed)
        );
        assert_eq!(FindingStatus::parse("resolved"), Some(FindingStatus::Resolved));
        assert_eq!(FindingStatus::parse("closed"), Some(FindingStatus::Resolved));
        assert_eq!(FindingStatus::parse(""), None);
        assert_eq!(FindingStatus::parse("nope"), None);
        assert_eq!(FindingStatus::parse("true positive"), None);
    }

    #[test]
    fn as_str_roundtrips_through_parse() {
        for st in [
            FindingStatus::New,
            FindingStatus::Acknowledged,
            FindingStatus::TruePositive,
            FindingStatus::FalsePositive,
            FindingStatus::Suppressed,
            FindingStatus::Resolved,
        ] {
            assert_eq!(FindingStatus::parse(st.as_str()), Some(st));
        }
    }

    #[test]
    fn hidden_by_default_only_fp_and_suppressed() {
        assert!(!FindingStatus::New.is_hidden_by_default());
        assert!(!FindingStatus::Acknowledged.is_hidden_by_default());
        assert!(!FindingStatus::TruePositive.is_hidden_by_default());
        assert!(!FindingStatus::Resolved.is_hidden_by_default());
        assert!(FindingStatus::FalsePositive.is_hidden_by_default());
        assert!(FindingStatus::Suppressed.is_hidden_by_default());
    }

    #[test]
    fn serde_snake_case() {
        let j = serde_json::to_string(&FindingStatus::TruePositive).unwrap();
        assert_eq!(j, "\"true_positive\"");
        let back: FindingStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, FindingStatus::TruePositive);
        let fp: FindingStatus = serde_json::from_str("\"false_positive\"").unwrap();
        assert_eq!(fp, FindingStatus::FalsePositive);
    }
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
