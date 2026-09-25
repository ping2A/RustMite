//! Observation tagged union — one variant per detection module.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::path::{BigInt, PathBytes};
use crate::{Confidence, Severity};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Observation {
    Process(ProcessObs),
    HiddenProcess(HiddenProcessObs),
    Socket(SocketObs),
    HiddenSocket(HiddenSocketObs),
    Module(ModuleObs),
    HiddenModule(ModuleObs),
    BpfProg(BpfProgObs),
    FileMeta(FileMetaObs),
    FileEntropy(FileEntropyObs),
    ElfInfo(ElfInfoObs),
    Preload(PreloadObs),
    ScheduledTask(ScheduledTaskObs),
    Service(ServiceObs),
    Account(AccountObs),
    ShadowEntry(ShadowEntryObs),
    SudoRule(SudoRuleObs),
    AuthorizedKey(AuthorizedKeyObs),
    SshHostKey(SshHostKeyObs),
    DirAnomaly(DirAnomalyObs),
    Timestomp(TimestompObs),
    Mount(MountObs),
    LogIntegrity(LogIntegrityObs),
    UtmpSession(UtmpSessionObs),
    IntegrityMismatch(IntegrityObs),
    IocHit(IocHitObs),
    ContainerInfo(ContainerObs),
    Recon(ReconObs),
    Policy(PolicyObs),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NamespaceIds {
    pub pid: Option<BigInt>,
    pub net: Option<BigInt>,
    pub mnt: Option<BigInt>,
    pub user: Option<BigInt>,
    pub uts: Option<BigInt>,
    pub ipc: Option<BigInt>,
    pub cgroup: Option<BigInt>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessObs {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe: Option<PathBytes>,
    pub exe_deleted: bool,
    pub exe_memfd: bool,
    pub cmdline: Vec<PathBytes>,
    pub cwd: Option<PathBytes>,
    pub root: Option<PathBytes>,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    /// Resolved from `/etc/passwd` when available (real uid).
    #[serde(default)]
    pub username: Option<String>,
    pub starttime: u64,
    pub num_threads: i64,
    pub tty: i32,
    pub state: char,
    pub caps_eff: u64,
    pub ns: NamespaceIds,
    pub rwx_maps: u32,
    pub unbacked_exec: u32,
    pub listen_ports: Vec<u16>,
    pub selinux: Option<String>,
    #[serde(default)]
    pub environ_flags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HiddenProcessObs {
    pub pid: i32,
    pub sources_present: Vec<String>,
    pub sources_absent: Vec<String>,
    pub comm: Option<String>,
    pub exe: Option<PathBytes>,
    pub uid: Option<u32>,
    pub starttime: Option<u64>,
    pub cgroup: Option<String>,
    pub passes_confirmed: u8,
    pub confidence: Confidence,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SocketObs {
    pub inode: BigInt,
    pub family: String,
    pub protocol: String,
    pub state: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub uid: u32,
    pub owning_pid: Option<i32>,
    /// `comm` of `owning_pid` when resolved.
    #[serde(default)]
    pub owning_comm: Option<String>,
    /// True only when fd tables were walked with enough coverage that a missing
    /// owner is suspicious (root + most `/proc/*/fd` readable). Non-root scans
    /// leave this false so RM-NET-0002 does not flood on permission gaps.
    #[serde(default)]
    pub owner_unresolved: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HiddenSocketObs {
    pub inode: BigInt,
    pub local_port: u16,
    pub protocol: String,
    pub sources_present: Vec<String>,
    pub sources_absent: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModuleObs {
    pub name: String,
    pub size: Option<u64>,
    pub refcount: Option<i32>,
    pub used_by: Vec<String>,
    pub in_sysfs: bool,
    pub in_proc_modules: bool,
    pub taint_flags: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BpfProgObs {
    pub id: u32,
    pub prog_type: String,
    pub name: Option<String>,
    pub tag: Option<String>,
    pub orphan: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileMetaObs {
    pub path: PathBytes,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: BigInt,
    pub inode: BigInt,
    pub nlink: u32,
    pub setuid: bool,
    pub setgid: bool,
    pub immutable: bool,
    /// Resolved owner name when known (`stat %U` / passwd).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Resolved group name when known (`stat %G` / group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileEntropyObs {
    pub path: PathBytes,
    pub entropy: f64,
    pub window_max: Option<f64>,
    pub window_offset: Option<u64>,
    pub size: BigInt,
    pub is_elf: bool,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElfInfoObs {
    pub path: PathBytes,
    pub machine: String,
    pub is_static: bool,
    pub stripped: bool,
    pub interp: Option<PathBytes>,
    pub section_count: u16,
    pub has_rwx_segment: bool,
    pub packer_hints: Vec<String>,
    pub entry: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreloadObs {
    pub path: PathBytes,
    pub entries: Vec<PathBytes>,
    pub present: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScheduledTaskObs {
    pub kind: String,
    pub path: PathBytes,
    pub user: Option<String>,
    pub schedule: Option<String>,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceObs {
    pub name: String,
    pub path: PathBytes,
    pub exec_start: Option<String>,
    pub unit_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountObs {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBytes,
    pub shell: PathBytes,
    pub gecos: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShadowEntryObs {
    pub username: String,
    /// Algorithm tag only (e.g. "yescrypt", "sha512crypt") — never the raw hash on wire to storage.
    pub algorithm: String,
    pub empty_password: bool,
    pub locked: bool,
    pub hash_fingerprint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SudoRuleObs {
    pub path: PathBytes,
    pub line: String,
    pub nopasswd: bool,
    pub all_commands: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedKeyObs {
    pub path: PathBytes,
    pub username: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub options: Vec<String>,
    /// Public key size in bits when known (RSA/DSA modulus, curve size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SshHostKeyObs {
    pub path: PathBytes,
    pub key_type: String,
    pub fingerprint: String,
    #[serde(default)]
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirAnomalyObs {
    pub path: PathBytes,
    pub anomaly: String,
    pub detail: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimestompObs {
    pub path: PathBytes,
    pub btime: Option<u64>,
    pub mtime: u64,
    pub ctime: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MountObs {
    pub device: String,
    pub mountpoint: PathBytes,
    pub fstype: String,
    pub options: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogIntegrityObs {
    pub path: PathBytes,
    pub issue: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UtmpSessionObs {
    pub user: String,
    pub line: String,
    pub host: String,
    pub pid: i32,
    pub typ: u16,
    pub time: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntegrityObs {
    pub path: PathBytes,
    pub expected_hash: String,
    pub actual_hash: String,
    pub package: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IocHitObs {
    pub path: PathBytes,
    pub ioc_kind: String,
    pub ioc_value: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContainerObs {
    pub in_container: bool,
    pub runtime: Option<String>,
    pub privileged: bool,
    pub docker_sock_mounted: bool,
    pub host_pid_ns: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReconObs {
    pub category: String,
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyObs {
    pub code: String,
    pub detail: String,
    pub severity: Severity,
}
