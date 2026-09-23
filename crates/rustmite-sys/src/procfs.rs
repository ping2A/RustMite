//! ProcSource trait + Live/Fixture implementations.

use alloc::string::String;
use alloc::vec::Vec;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::dirent::DirEnt;
use crate::error::Errno;
use crate::pid_probe::PidProbeView;

/// Minimal `statx`-like metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Statx {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub ino: u64,
    pub nlink: u32,
    pub mtime_sec: u64,
    pub ctime_sec: u64,
    pub btime_sec: Option<u64>,
    pub is_dir: bool,
    pub is_reg: bool,
    pub is_lnk: bool,
}

/// Every collector reads the host through this trait.
pub trait ProcSource: Send + Sync {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno>;
    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno>;
    /// MUST use raw getdents64 on live systems — never libc readdir.
    fn list_dir_raw(&self, path: &str) -> Result<Vec<DirEnt>, Errno>;
    fn statx(&self, path: &str) -> Result<Statx, Errno>;
    fn open_exists(&self, path: &str) -> bool {
        self.statx(path).is_ok() || self.read(path).is_ok()
    }
}

/// Optional PID-liveness view for decloak differential testing.
pub trait PidProbeExt: ProcSource {
    fn pid_probe(&self) -> Option<&dyn PidProbeView> {
        None
    }
}

/// Fixture-backed `/proc` (and friends) tree for tests.
///
/// Supports dual views for decloak: listing can omit PIDs that syscall probe still sees.
#[derive(Clone, Debug)]
pub struct FixtureProc {
    root: PathBuf,
    /// Overlay file contents: path relative to `/` → bytes.
    files: BTreeMap<String, Vec<u8>>,
    /// Overlay directory listings: path → entry names.
    dirs: BTreeMap<String, Vec<Vec<u8>>>,
    /// Symlink targets.
    links: BTreeMap<String, Vec<u8>>,
    /// PIDs absent from `list_dir_raw("/proc")` but present to the syscall probe.
    hidden_pids: BTreeSet<i32>,
    /// PIDs the scheduler probe reports as alive (defaults to all listed + hidden).
    alive_pids: BTreeSet<i32>,
    /// Per-pid starttime for race control.
    starttimes: BTreeMap<i32, u64>,
}

impl FixtureProc {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
            links: BTreeMap::new(),
            hidden_pids: BTreeSet::new(),
            alive_pids: BTreeSet::new(),
            starttimes: BTreeMap::new(),
        }
    }

    pub fn from_tree(root: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let root = root.as_ref().to_path_buf();
        let mut fx = Self::new(root.clone());
        fx.load_tree(&root, "")?;
        Ok(fx)
    }

    fn load_tree(&mut self, abs: &Path, rel: &str) -> Result<(), std::io::Error> {
        if !abs.is_dir() {
            return Ok(());
        }
        let mut entries = Vec::new();
        for ent in std::fs::read_dir(abs)? {
            let ent = ent?;
            let name = ent.file_name();
            let name_bytes = name.as_os_str().as_encoded_bytes().to_vec();
            entries.push(name_bytes.clone());
            let child_rel = if rel.is_empty() {
                String::from_utf8_lossy(&name_bytes).into_owned()
            } else {
                format!("{rel}/{}", String::from_utf8_lossy(&name_bytes))
            };
            let child_abs = ent.path();
            if child_abs.is_symlink() {
                let target = std::fs::read_link(&child_abs)?;
                self.links
                    .insert(child_rel, target.as_os_str().as_encoded_bytes().to_vec());
            } else if child_abs.is_dir() {
                self.load_tree(&child_abs, &child_rel)?;
            } else if child_abs.is_file() {
                self.files.insert(child_rel, std::fs::read(&child_abs)?);
            }
        }
        let key = if rel.is_empty() {
            String::new()
        } else {
            rel.to_string()
        };
        self.dirs.insert(key, entries);
        Ok(())
    }

    pub fn with_file(mut self, path: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        let path = normalize_path(&path.into());
        self.ensure_path_parents(&path);
        self.files.insert(path, data.into());
        self
    }

    pub fn with_link(mut self, path: impl Into<String>, target: impl Into<Vec<u8>>) -> Self {
        let path = normalize_path(&path.into());
        self.ensure_path_parents(&path);
        self.links.insert(path, target.into());
        self
    }

    pub fn with_dir(mut self, path: impl Into<String>) -> Self {
        let path = normalize_path(&path.into());
        self.dirs.entry(path.clone()).or_default();
        self.ensure_path_parents(&path);
        // also register the dir itself as an entry in its parent
        if let Some((parent, name)) = path.rsplit_once('/') {
            self.ensure_dir_entry(parent, name.as_bytes());
        } else if !path.is_empty() {
            self.ensure_dir_entry("", path.as_bytes());
        }
        self
    }

    /// Model a Diamorphine-style hidden PID: absent from listing, alive to scheduler.
    pub fn with_hidden_pid(mut self, pid: i32, starttime: u64) -> Self {
        self.hidden_pids.insert(pid);
        self.alive_pids.insert(pid);
        self.starttimes.insert(pid, starttime);
        self
    }

    pub fn with_alive_pid(mut self, pid: i32) -> Self {
        self.alive_pids.insert(pid);
        self
    }

    /// Ensure every path prefix appears in its parent's directory listing.
    fn ensure_path_parents(&mut self, path: &str) {
        if path.is_empty() {
            return;
        }
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let mut acc = String::new();
        for (i, part) in parts.iter().enumerate() {
            let parent = acc.clone();
            self.ensure_dir_entry(&parent, part.as_bytes());
            if i + 1 < parts.len() {
                // intermediate component is a directory
                if acc.is_empty() {
                    acc = (*part).to_string();
                } else {
                    acc = format!("{acc}/{part}");
                }
                self.dirs.entry(acc.clone()).or_default();
            }
        }
    }

    fn ensure_dir_entry(&mut self, parent: &str, name: &[u8]) {
        let parent = normalize_path(parent);
        let entries = self.dirs.entry(parent).or_default();
        if !entries.iter().any(|e| e.as_slice() == name) {
            entries.push(name.to_vec());
        }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let p = normalize_path(path);
        if p.is_empty() {
            self.root.clone()
        } else {
            self.root.join(p)
        }
    }
}

fn normalize_path(path: &str) -> String {
    let p = path.trim_start_matches('/');
    p.trim_end_matches('/').to_string()
}

impl ProcSource for FixtureProc {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let key = normalize_path(path);
        if let Some(data) = self.files.get(&key) {
            return Ok(data.clone());
        }
        let abs = self.resolve(path);
        std::fs::read(&abs).map_err(|e| io_to_errno(e))
    }

    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let key = normalize_path(path);
        if let Some(t) = self.links.get(&key) {
            return Ok(t.clone());
        }
        let abs = self.resolve(path);
        let t = std::fs::read_link(&abs).map_err(io_to_errno)?;
        Ok(t.as_os_str().as_encoded_bytes().to_vec())
    }

    fn list_dir_raw(&self, path: &str) -> Result<Vec<DirEnt>, Errno> {
        let key = normalize_path(path);
        let mut names = if let Some(entries) = self.dirs.get(&key) {
            entries.clone()
        } else {
            let abs = self.resolve(path);
            let rd = std::fs::read_dir(&abs).map_err(io_to_errno)?;
            let mut v = Vec::new();
            for ent in rd {
                let ent = ent.map_err(io_to_errno)?;
                v.push(ent.file_name().as_os_str().as_encoded_bytes().to_vec());
            }
            v
        };

        // Hide configured PIDs from /proc listing.
        if key == "proc" || path == "/proc" || path == "proc" {
            names.retain(|n| {
                let s = String::from_utf8_lossy(n);
                if let Ok(pid) = s.parse::<i32>() {
                    !self.hidden_pids.contains(&pid)
                } else {
                    true
                }
            });
        }

        Ok(names
            .into_iter()
            .enumerate()
            .map(|(i, name)| DirEnt {
                ino: i as u64 + 1,
                name,
                file_type: DirEnt::DT_DIR,
            })
            .collect())
    }

    fn statx(&self, path: &str) -> Result<Statx, Errno> {
        let key = normalize_path(path);
        if self.files.contains_key(&key) {
            let size = self.files.get(&key).map(|d| d.len() as u64).unwrap_or(0);
            return Ok(Statx {
                mode: 0o100644,
                size,
                ino: 1,
                nlink: 1,
                is_reg: true,
                ..Statx::default()
            });
        }
        if self.dirs.contains_key(&key) || self.links.contains_key(&key) {
            return Ok(Statx {
                mode: 0o040755,
                is_dir: self.dirs.contains_key(&key),
                is_lnk: self.links.contains_key(&key),
                nlink: 2,
                ..Statx::default()
            });
        }
        let abs = self.resolve(path);
        let meta = std::fs::symlink_metadata(&abs).map_err(io_to_errno)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Statx {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.size(),
                ino: meta.ino(),
                nlink: meta.nlink() as u32,
                mtime_sec: meta.mtime() as u64,
                ctime_sec: meta.ctime() as u64,
                btime_sec: None,
                is_dir: meta.is_dir(),
                is_reg: meta.is_file(),
                is_lnk: meta.file_type().is_symlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Statx {
                size: meta.len(),
                is_dir: meta.is_dir(),
                is_reg: meta.is_file(),
                ..Statx::default()
            })
        }
    }
}

impl PidProbeView for FixtureProc {
    fn pid_exists(&self, pid: i32) -> crate::pid_probe::PidLiveness {
        if self.alive_pids.contains(&pid) || self.hidden_pids.contains(&pid) {
            return crate::pid_probe::PidLiveness::Alive;
        }
        // Also alive if present in listing under proc/<pid>
        let path = format!("proc/{pid}/stat");
        if self.files.contains_key(&path) || self.resolve(&path).exists() {
            return crate::pid_probe::PidLiveness::Alive;
        }
        // Numeric dirs under proc
        if let Ok(ents) = self.list_dir_raw("proc") {
            for e in ents {
                if String::from_utf8_lossy(&e.name) == pid.to_string() {
                    return crate::pid_probe::PidLiveness::Alive;
                }
            }
        }
        // Hidden PIDs are intentionally not in listing but still alive — already handled.
        // Check overlay for any alive set built from dirs at load time:
        let dir_path = format!("proc/{pid}");
        if self.dirs.contains_key(&dir_path) {
            return crate::pid_probe::PidLiveness::Alive;
        }
        crate::pid_probe::PidLiveness::Absent
    }

    fn hidden_from_listing(&self, pid: i32) -> bool {
        self.hidden_pids.contains(&pid)
    }

    fn starttime(&self, pid: i32) -> Option<u64> {
        if let Some(st) = self.starttimes.get(&pid) {
            return Some(*st);
        }
        let path = format!("proc/{pid}/stat");
        let data = self.read(&path).ok()?;
        crate::parse::parse_proc_stat(&data)
            .ok()
            .map(|s| s.starttime)
    }
}

impl PidProbeExt for FixtureProc {
    fn pid_probe(&self) -> Option<&dyn PidProbeView> {
        Some(self)
    }
}

fn io_to_errno(e: std::io::Error) -> Errno {
    match e.kind() {
        std::io::ErrorKind::NotFound => Errno::NotFound,
        std::io::ErrorKind::PermissionDenied => Errno::PermissionDenied,
        std::io::ErrorKind::InvalidInput => Errno::InvalidInput,
        _ => Errno::Io,
    }
}

/// Live `/proc` via std (non-probe builds / host tooling). Probe uses rustix raw on Linux.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct LiveProc;

#[cfg(feature = "std")]
impl ProcSource for LiveProc {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        std::fs::read(p).map_err(io_to_errno)
    }

    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        let t = std::fs::read_link(p).map_err(io_to_errno)?;
        Ok(t.as_os_str().as_encoded_bytes().to_vec())
    }

    fn list_dir_raw(&self, path: &str) -> Result<Vec<DirEnt>, Errno> {
        // Note: probe build must use rustix getdents64. This LiveProc is for
        // non-hostile host tooling / macOS fixture development only.
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        let rd = std::fs::read_dir(p).map_err(io_to_errno)?;
        let mut out = Vec::new();
        for (i, ent) in rd.enumerate() {
            let ent = ent.map_err(io_to_errno)?;
            let ft = ent.file_type().map_err(io_to_errno)?;
            let file_type = if ft.is_dir() {
                DirEnt::DT_DIR
            } else if ft.is_symlink() {
                DirEnt::DT_LNK
            } else if ft.is_file() {
                DirEnt::DT_REG
            } else {
                DirEnt::DT_UNKNOWN
            };
            out.push(DirEnt {
                ino: i as u64 + 1,
                name: ent.file_name().as_os_str().as_encoded_bytes().to_vec(),
                file_type,
            });
        }
        Ok(out)
    }

    fn statx(&self, path: &str) -> Result<Statx, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        let meta = std::fs::symlink_metadata(p).map_err(io_to_errno)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Statx {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.size(),
                ino: meta.ino(),
                nlink: meta.nlink() as u32,
                mtime_sec: meta.mtime() as u64,
                ctime_sec: meta.ctime() as u64,
                btime_sec: None,
                is_dir: meta.is_dir(),
                is_reg: meta.is_file(),
                is_lnk: meta.file_type().is_symlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Statx {
                size: meta.len(),
                is_dir: meta.is_dir(),
                is_reg: meta.is_file(),
                ..Statx::default()
            })
        }
    }
}
