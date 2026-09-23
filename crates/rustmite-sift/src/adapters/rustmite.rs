//! Adapters from RustMite observations / hosts into IronSift raw log shapes.

use rustmite_proto::{Observation, PathBytes, ProcessObs};

use crate::types::{RawConnectionEntry, RawFileEntry, RawLogEntry};

fn path_lossy(p: &Option<PathBytes>) -> String {
    p.as_ref()
        .map(|b| String::from_utf8_lossy(&b.0).into_owned())
        .unwrap_or_default()
}

fn cmdline_join(parts: &[PathBytes]) -> String {
    parts
        .iter()
        .map(|p| String::from_utf8_lossy(&p.0))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Convert a RustMite process observation into an IronSift raw log row.
pub fn process_obs_to_raw(machine_id: &str, p: &ProcessObs, timestamp: Option<String>) -> RawLogEntry {
    RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: p.pid.max(0) as u32,
        ppid: p.ppid.max(0) as u32,
        name: p.comm.clone(),
        uid: p.uids[0],
        path: path_lossy(&p.exe),
        args: cmdline_join(&p.cmdline),
        timestamp,
    }
}

/// Expand a mixed observation list into process rows for fleet sift.
pub fn observations_to_process_logs(
    machine_id: &str,
    observations: &[Observation],
    timestamp: Option<String>,
) -> Vec<RawLogEntry> {
    let mut out = Vec::new();
    for o in observations {
        match o {
            Observation::Process(p) => {
                out.push(process_obs_to_raw(machine_id, p, timestamp.clone()));
            }
            Observation::HiddenProcess(h) => {
                out.push(RawLogEntry {
                    machine_id: machine_id.to_string(),
                    pid: h.pid.max(0) as u32,
                    ppid: 0,
                    name: h.comm.clone().unwrap_or_else(|| "(hidden)".into()),
                    uid: h.uid.unwrap_or(0),
                    path: path_lossy(&h.exe),
                    args: String::new(),
                    timestamp: timestamp.clone(),
                });
            }
            _ => {}
        }
    }
    out
}

/// Map socket observations into temporal connection rows.
pub fn observations_to_connections(
    machine_id: &str,
    observations: &[Observation],
    timestamp: Option<String>,
) -> Vec<RawConnectionEntry> {
    let mut out = Vec::new();
    for o in observations {
        let Observation::Socket(s) = o else {
            continue;
        };
        if s.remote_ip.is_empty() || s.remote_ip == "0.0.0.0" || s.remote_ip == "::" {
            continue;
        }
        out.push(RawConnectionEntry {
            machine_id: machine_id.to_string(),
            remote_ip: s.remote_ip.clone(),
            local_ip: Some(s.local_ip.clone()),
            remote_port: Some(s.remote_port),
            process_name: s.owning_comm.clone(),
            timestamp: timestamp.clone(),
        });
    }
    out
}

/// Best-effort file meta → IronSift file row (permissions / size when present).
pub fn observations_to_file_logs(
    machine_id: &str,
    observations: &[Observation],
    timestamp: Option<String>,
) -> Vec<RawFileEntry> {
    let mut out = Vec::new();
    for o in observations {
        let Observation::FileMeta(f) = o else {
            continue;
        };
        let path = String::from_utf8_lossy(&f.path.0).into_owned();
        if path.is_empty() {
            continue;
        }
        out.push(RawFileEntry {
            machine_id: machine_id.to_string(),
            path,
            uid: f.uid,
            timestamp: timestamp.clone(),
            mtime: None,
            permissions: Some(format!("{:o}", f.mode)),
            owner: None,
            group: None,
            size: f.size.0.parse().ok(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::NamespaceIds;

    #[test]
    fn maps_process_obs() {
        let p = ProcessObs {
            pid: 42,
            ppid: 1,
            comm: "sshd".into(),
            exe: Some(PathBytes(b"/usr/sbin/sshd".to_vec())),
            exe_deleted: false,
            exe_memfd: false,
            cmdline: vec![PathBytes(b"/usr/sbin/sshd".to_vec()), PathBytes(b"-D".to_vec())],
            cwd: None,
            root: None,
            uids: [0, 0, 0, 0],
            gids: [0, 0, 0, 0],
            username: Some("root".into()),
            starttime: 0,
            num_threads: 1,
            tty: 0,
            state: 'S',
            caps_eff: 0,
            ns: NamespaceIds::default(),
            rwx_maps: 0,
            unbacked_exec: 0,
            listen_ports: vec![],
            selinux: None,
            environ_flags: vec![],
        };
        let raw = process_obs_to_raw("host-a", &p, Some("2026-01-01T00:00:00Z".into()));
        assert_eq!(raw.machine_id, "host-a");
        assert_eq!(raw.name, "sshd");
        assert_eq!(raw.uid, 0);
        assert!(raw.args.contains("-D"));
    }
}
