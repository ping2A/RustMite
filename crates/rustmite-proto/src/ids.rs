//! Newtype IDs.

use alloc::string::String;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn new_v4() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

uuid_id!(HostId);
uuid_id!(NodeId);
uuid_id!(ScanId);
uuid_id!(FindingId);

/// Stable check identifier, e.g. `"RM-PROC-0001"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckId(pub String);

impl CheckId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for CheckId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Collector identifier (static on probe side).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CollectorId(pub &'static str);

impl CollectorId {
    pub const DECLOAK_PROCESS: Self = Self("decloak.process");
    pub const PROCESS_INVENTORY: Self = Self("process.inventory");
    pub const NET_SOCKETS: Self = Self("net.sockets");
    pub const DECLOAK_SOCKET: Self = Self("decloak.socket");
    pub const ENTROPY: Self = Self("entropy");
    pub const FILE_ELF: Self = Self("file.elf");
    pub const MODULES_LKM: Self = Self("modules.lkm");
    pub const MODULES_EBPF: Self = Self("modules.ebpf");
    pub const EBPF: Self = Self("ebpf");
    pub const PERSISTENCE_PRELOAD: Self = Self("persistence.preload");
    pub const PERSISTENCE_SCHEDULED: Self = Self("persistence.scheduled");
    pub const PERSISTENCE_SERVICES: Self = Self("persistence.services");
    pub const PERSISTENCE_ACCOUNTS: Self = Self("persistence.accounts");
    pub const FS_ANOMALY: Self = Self("fs.anomaly");
    pub const DIR_HIDDEN: Self = Self("dir.hidden");
    pub const FILE_INTEGRITY: Self = Self("file.integrity");
    pub const FILE_IOC: Self = Self("file.ioc");
    pub const LOG_INTEGRITY: Self = Self("log.integrity");
    pub const USER_SESSIONS: Self = Self("user.sessions");
    pub const SESSION_INVENTORY: Self = Self("session.inventory");
    pub const CONTAINER_ESCAPE: Self = Self("container.escape");
    pub const CONTAINER_INVENTORY: Self = Self("container.inventory");
    pub const MOUNT_ANOMALY: Self = Self("mount.anomaly");
    pub const MOUNTS_INVENTORY: Self = Self("mounts.inventory");
    pub const SSH_KEYS: Self = Self("ssh.keys");
    pub const CRED_AUDIT: Self = Self("cred.audit");
    pub const DRIFT_BASELINE: Self = Self("drift.baseline");
    pub const RECON_INVENTORY: Self = Self("recon.inventory");

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for CollectorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}
