//! Filesystem source trait (non-/proc paths).

use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::dirent::DirEnt;
use crate::error::Errno;
use crate::procfs::Statx;

pub trait FsSource: Send + Sync {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno>;
    fn list_dir(&self, path: &str) -> Result<Vec<DirEnt>, Errno>;
    fn statx(&self, path: &str) -> Result<Statx, Errno>;
    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno>;
}

/// Fixture filesystem overlay (typically same tree as FixtureProc).
#[derive(Clone, Debug, Default)]
pub struct FixtureFs {
    files: BTreeMap<String, Vec<u8>>,
    /// Optional mode overrides for in-memory files (e.g. setuid `0o104755`).
    modes: BTreeMap<String, u32>,
    /// Optional uid overrides for in-memory files.
    uids: BTreeMap<String, u32>,
    root: Option<PathBuf>,
}

impl FixtureFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_tree(root: impl AsRef<Path>) -> Self {
        Self {
            files: BTreeMap::new(),
            modes: BTreeMap::new(),
            uids: BTreeMap::new(),
            root: Some(root.as_ref().to_path_buf()),
        }
    }

    pub fn with_file(mut self, path: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        self.files
            .insert(path.into().trim_start_matches('/').to_string(), data.into());
        self
    }

    /// In-memory file with explicit mode/uid (for setuid/GTFOBins fixtures).
    pub fn with_file_meta(
        mut self,
        path: impl Into<String>,
        data: impl Into<Vec<u8>>,
        mode: u32,
        uid: u32,
    ) -> Self {
        let key = path.into().trim_start_matches('/').to_string();
        self.files.insert(key.clone(), data.into());
        self.modes.insert(key.clone(), mode);
        self.uids.insert(key, uid);
        self
    }
}

impl FsSource for FixtureFs {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let key = path.trim_start_matches('/');
        if let Some(d) = self.files.get(key) {
            return Ok(d.clone());
        }
        if let Some(root) = &self.root {
            return std::fs::read(root.join(key)).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Errno::NotFound,
                std::io::ErrorKind::PermissionDenied => Errno::PermissionDenied,
                _ => Errno::Io,
            });
        }
        Err(Errno::NotFound)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEnt>, Errno> {
        let key = path.trim_start_matches('/');
        if let Some(root) = &self.root {
            let abs = if key.is_empty() {
                root.clone()
            } else {
                root.join(key)
            };
            let rd = std::fs::read_dir(abs).map_err(|_| Errno::NotFound)?;
            let mut out = Vec::new();
            for (i, ent) in rd.enumerate() {
                let ent = ent.map_err(|_| Errno::Io)?;
                out.push(DirEnt {
                    ino: i as u64 + 1,
                    name: ent.file_name().as_os_str().as_encoded_bytes().to_vec(),
                    file_type: DirEnt::DT_UNKNOWN,
                });
            }
            return Ok(out);
        }
        // Derive directory listings from in-memory file keys.
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{key}/")
        };
        let mut names = std::collections::BTreeSet::new();
        for file_key in self.files.keys() {
            let rest = if prefix.is_empty() {
                file_key.as_str()
            } else if let Some(r) = file_key.strip_prefix(&prefix) {
                r
            } else {
                continue;
            };
            let name = rest.split('/').next().unwrap_or("");
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
        if names.is_empty() {
            return Err(Errno::NotFound);
        }
        Ok(names
            .into_iter()
            .enumerate()
            .map(|(i, name)| DirEnt {
                ino: i as u64 + 1,
                name: name.into_bytes(),
                file_type: DirEnt::DT_UNKNOWN,
            })
            .collect())
    }

    fn statx(&self, path: &str) -> Result<Statx, Errno> {
        let key = path.trim_start_matches('/');
        if let Some(data) = self.files.get(key) {
            let mode = self
                .modes
                .get(key)
                .copied()
                .unwrap_or(0o100644);
            let uid = self.uids.get(key).copied().unwrap_or(0);
            return Ok(Statx {
                mode,
                uid,
                size: data.len() as u64,
                is_reg: true,
                nlink: 1,
                ..Statx::default()
            });
        }
        if let Some(root) = &self.root {
            let meta = std::fs::symlink_metadata(root.join(key)).map_err(|_| Errno::NotFound)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                return Ok(Statx {
                    mode: meta.mode(),
                    uid: meta.uid(),
                    gid: meta.gid(),
                    size: meta.len(),
                    ino: meta.ino(),
                    nlink: meta.nlink() as u32,
                    mtime_sec: meta.mtime() as u64,
                    ctime_sec: meta.ctime() as u64,
                    is_dir: meta.is_dir(),
                    is_reg: meta.is_file(),
                    is_lnk: meta.file_type().is_symlink(),
                    ..Statx::default()
                });
            }
            #[cfg(not(unix))]
            {
                return Ok(Statx {
                    size: meta.len(),
                    is_dir: meta.is_dir(),
                    is_reg: meta.is_file(),
                    is_lnk: meta.file_type().is_symlink(),
                    ..Statx::default()
                });
            }
        }
        Err(Errno::NotFound)
    }

    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let key = path.trim_start_matches('/');
        if let Some(root) = &self.root {
            let t = std::fs::read_link(root.join(key)).map_err(|_| Errno::NotFound)?;
            return Ok(t.as_os_str().as_encoded_bytes().to_vec());
        }
        Err(Errno::NotFound)
    }
}

/// Read-only live FS for host tooling.
#[derive(Clone, Debug, Default)]
pub struct LiveFs;

impl FsSource for LiveFs {
    fn read(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        std::fs::read(p).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Errno::NotFound,
            std::io::ErrorKind::PermissionDenied => Errno::PermissionDenied,
            _ => Errno::Io,
        })
    }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEnt>, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        let rd = std::fs::read_dir(p).map_err(|_| Errno::NotFound)?;
        let mut out = Vec::new();
        for (i, ent) in rd.enumerate() {
            let ent = ent.map_err(|_| Errno::Io)?;
            out.push(DirEnt {
                ino: i as u64 + 1,
                name: ent.file_name().as_os_str().as_encoded_bytes().to_vec(),
                file_type: DirEnt::DT_UNKNOWN,
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
        let meta = std::fs::symlink_metadata(p).map_err(|_| Errno::NotFound)?;
        Ok(Statx {
            size: meta.len(),
            is_dir: meta.is_dir(),
            is_reg: meta.is_file(),
            is_lnk: meta.file_type().is_symlink(),
            ..Statx::default()
        })
    }

    fn read_link(&self, path: &str) -> Result<Vec<u8>, Errno> {
        let p = if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        };
        let t = std::fs::read_link(p).map_err(|_| Errno::NotFound)?;
        Ok(t.as_os_str().as_encoded_bytes().to_vec())
    }
}
