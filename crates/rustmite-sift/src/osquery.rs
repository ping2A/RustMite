//! Minimal osquery 5.22.1 oriented normalization helpers for process/file events.

use serde_json::Value;

use crate::types::{RawFileEntry, RawLogEntry};

fn get_u32(v: &Value, keys: &[&str]) -> u32 {
    keys.iter()
        .find_map(|k| v.get(*k))
        .and_then(|x| {
            x.as_u64()
                .map(|n| n as u32)
                .or_else(|| x.as_str().and_then(|s| s.parse::<u32>().ok()))
        })
        .unwrap_or(0)
}

fn get_string(v: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| v.get(*k))
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Normalize an osquery process-like row into `RawLogEntry`.
pub fn normalize_osquery_process_row(v: &Value, default_machine: &str) -> RawLogEntry {
    let machine_id = {
        let m = get_string(v, &["machine_id", "hostname", "host_identifier", "host", "node"]);
        if m.is_empty() {
            default_machine.to_string()
        } else {
            m
        }
    };

    let name = {
        let n = get_string(v, &["name"]);
        if n.is_empty() {
            get_string(v, &["cmdline", "command"])
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        } else {
            n
        }
    };

    RawLogEntry {
        machine_id,
        pid: get_u32(v, &["pid"]),
        ppid: get_u32(v, &["parent", "ppid"]),
        name,
        uid: get_u32(v, &["uid", "euid"]),
        path: get_string(v, &["path", "exe"]),
        args: get_string(v, &["cmdline", "command"]),
        timestamp: {
            let ts = get_string(v, &["time", "timestamp", "calendar_time"]);
            if ts.is_empty() { None } else { Some(ts) }
        },
    }
}

/// Normalize an osquery file-like row into `RawFileEntry`.
pub fn normalize_osquery_file_row(v: &Value, default_machine: &str) -> RawFileEntry {
    let machine_id = {
        let m = get_string(v, &["machine_id", "hostname", "host_identifier", "host", "node"]);
        if m.is_empty() {
            default_machine.to_string()
        } else {
            m
        }
    };

    RawFileEntry {
        machine_id,
        path: get_string(v, &["path", "target_path", "file_path"]),
        uid: get_u32(v, &["uid", "owner_uid"]),
        timestamp: {
            let ts = get_string(v, &["time", "timestamp"]);
            if ts.is_empty() { None } else { Some(ts) }
        },
        mtime: {
            let mt = get_string(v, &["mtime", "btime", "date"]);
            if mt.is_empty() { None } else { Some(mt) }
        },
        permissions: {
            let p = get_string(v, &["mode", "permissions"]);
            if p.is_empty() { None } else { Some(p) }
        },
        owner: {
            let o = get_string(v, &["username", "owner"]);
            if o.is_empty() { None } else { Some(o) }
        },
        group: {
            let g = get_string(v, &["groupname", "group"]);
            if g.is_empty() { None } else { Some(g) }
        },
        size: v
            .get("size")
            .and_then(|x| x.as_u64())
            .or_else(|| v.get("size").and_then(|x| x.as_str()?.parse::<u64>().ok())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_process_prefers_machine_and_numeric_strings() {
        let v = json!({
            "machine_id": "host-a",
            "pid": "100",
            "parent": 1,
            "name": "nginx",
            "path": "/usr/sbin/nginx",
            "cmdline": "/usr/sbin/nginx -c /etc/nginx.conf",
            "uid": 33
        });
        let r = normalize_osquery_process_row(&v, "fallback");
        assert_eq!(r.machine_id, "host-a");
        assert_eq!(r.pid, 100);
        assert_eq!(r.ppid, 1);
        assert_eq!(r.name, "nginx");
        assert_eq!(r.path, "/usr/sbin/nginx");
        assert!(r.args.contains("nginx"));
    }

    #[test]
    fn normalize_process_uses_default_machine_when_missing() {
        let v = json!({
            "pid": 1,
            "cmdline": "/bin/bash",
        });
        let r = normalize_osquery_process_row(&v, "default-host");
        assert_eq!(r.machine_id, "default-host");
        assert_eq!(r.name, "/bin/bash"); // first whitespace-separated token from cmdline when name empty
    }

    #[test]
    fn normalize_file_row_paths_and_size() {
        let v = json!({
            "machine_id": "m",
            "path": "/etc/shadow",
            "mode": "-rw-------",
            "size": "4096",
            "mtime": "2024-01-01T00:00:00Z"
        });
        let f = normalize_osquery_file_row(&v, "x");
        assert_eq!(f.path, "/etc/shadow");
        assert_eq!(f.permissions.as_deref(), Some("-rw-------"));
        assert_eq!(f.size, Some(4096));
        assert!(f.mtime.is_some());
    }
}
