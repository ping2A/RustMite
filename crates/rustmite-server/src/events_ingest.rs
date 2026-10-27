//! Map probe observations → ClickHouse `events` rows for RPL hunting.
//! Also maps virtual-agent process/file JSONL into the same table so Hunt works.

use rustmite_proto::{Observation, PathBytes};
use rustmite_sift::{RawFileEntry, RawLogEntry};
use serde_json::Value;
use uuid::Uuid;

use crate::sys_metrics::utc_now_rfc3339;

pub struct EventContext<'a> {
    pub host_id: Uuid,
    pub host_name: &'a str,
    pub scan_id: Uuid,
    pub collector: &'a str,
    pub timestamp: &'a str,
}

/// Build JSONEachRow payloads for `rustmite.events` from typed observations.
pub fn observations_to_events(ctx: &EventContext<'_>, observations: &[Observation]) -> Vec<Value> {
    let ts = clickhouse_ts(ctx.timestamp);
    observations
        .iter()
        .map(|o| observation_to_event(ctx, &ts, o))
        .collect()
}

fn observation_to_event(ctx: &EventContext<'_>, ts: &str, o: &Observation) -> Value {
    let kind = kind_of(o);
    let mut process_name = String::new();
    let mut process_id: u32 = 0;
    let mut user = String::new();
    let mut path = String::new();
    let mut args = String::new();
    let mut cmdline = String::new();
    let mut src_ip = String::new();
    let mut dest_ip = String::new();
    let mut file_hash = String::new();
    let mut severity = "info".to_string();
    let mut exe_memfd: u8 = 0;
    let mut check_id = String::new();

    let message = match o {
        Observation::Process(p) => {
            process_name = p.comm.clone();
            process_id = p.pid.max(0) as u32;
            user = p.uids.first().copied().unwrap_or(0).to_string();
            path = path_str(p.exe.as_ref());
            let (a, c) = process_argv_strings(p.exe.as_ref(), &p.cmdline);
            args = a;
            cmdline = c;
            if cmdline.is_empty() && !path.is_empty() {
                cmdline = path.clone();
            }
            exe_memfd = u8::from(p.exe_memfd);
            severity = if p.exe_memfd || p.exe_deleted {
                "high".into()
            } else {
                "info".into()
            };
            if args.is_empty() {
                format!(
                    "process pid={} comm={} exe={}",
                    p.pid,
                    p.comm,
                    if path.is_empty() { "—" } else { &path }
                )
            } else {
                format!(
                    "process pid={} comm={} exe={} args={}",
                    p.pid,
                    p.comm,
                    if path.is_empty() { "—" } else { &path },
                    args
                )
            }
        }
        Observation::HiddenProcess(p) => {
            process_name = p.comm.clone().unwrap_or_default();
            process_id = p.pid.max(0) as u32;
            if let Some(u) = p.uid {
                user = u.to_string();
            }
            path = path_str(p.exe.as_ref());
            severity = "critical".into();
            format!(
                "hidden process pid={} sources_absent={:?}",
                p.pid, p.sources_absent
            )
        }
        Observation::Socket(s) => {
            process_id = s.owning_pid.unwrap_or(0).max(0) as u32;
            user = s.uid.to_string();
            src_ip = format!("{}:{}", s.local_ip, s.local_port);
            dest_ip = format!("{}:{}", s.remote_ip, s.remote_port);
            format!(
                "{} {} {} → {} (pid={:?})",
                s.protocol, s.state, src_ip, dest_ip, s.owning_pid
            )
        }
        Observation::HiddenSocket(s) => {
            src_ip = format!("*:{}", s.local_port);
            severity = "high".into();
            format!(
                "hidden socket {}:{} absent={:?}",
                s.protocol, s.local_port, s.sources_absent
            )
        }
        Observation::Module(m) | Observation::HiddenModule(m) => {
            process_name = m.name.clone();
            severity = if matches!(o, Observation::HiddenModule(_)) {
                "critical".into()
            } else {
                "info".into()
            };
            format!("module {} size={:?}", m.name, m.size)
        }
        Observation::BpfProg(b) => {
            process_name = b.name.clone().unwrap_or_default();
            severity = if b.orphan { "high".into() } else { "info".into() };
            format!("bpf prog id={} type={}", b.id, b.prog_type)
        }
        Observation::FileMeta(f) => {
            path = f.path.to_string_lossy();
            user = f.uid.to_string();
            format!("file_meta {}", path)
        }
        Observation::FileEntropy(f) => {
            path = f.path.to_string_lossy();
            file_hash = f.sha256.clone().unwrap_or_default();
            severity = "high".into();
            format!("entropy={:.2} {}", f.entropy, path)
        }
        Observation::ElfInfo(e) => {
            path = e.path.to_string_lossy();
            format!("elf {} static={}", path, e.is_static)
        }
        Observation::Preload(p) => {
            path = p.path.to_string_lossy();
            severity = "high".into();
            format!("preload {}", path)
        }
        Observation::ScheduledTask(t) => {
            path = t.path.to_string_lossy();
            user = t.user.clone().unwrap_or_default();
            format!("scheduled {} {}", t.kind, path)
        }
        Observation::Service(s) => {
            process_name = s.name.clone();
            path = s.path.to_string_lossy();
            format!("service {} {}", s.name, s.unit_type)
        }
        Observation::Account(a) => {
            user = a.username.clone();
            path = a.shell.to_string_lossy();
            format!("account uid={} {}", a.uid, a.username)
        }
        Observation::ShadowEntry(s) => {
            user = s.username.clone();
            severity = "medium".into();
            format!("shadow {}", s.username)
        }
        Observation::SudoRule(s) => {
            path = s.path.to_string_lossy();
            format!("sudo {}", s.line)
        }
        Observation::AuthorizedKey(k) => {
            user = k.username.clone();
            path = k.path.to_string_lossy();
            process_name = "sshd".into();
            severity = "medium".into();
            format!("authorized_key {} {}", k.username, k.fingerprint)
        }
        Observation::SshHostKey(k) => {
            path = k.path.to_string_lossy();
            format!("ssh_host_key {}", k.key_type)
        }
        Observation::DirAnomaly(d) => {
            path = d.path.to_string_lossy();
            severity = "high".into();
            format!("dir_anomaly {}: {}", d.anomaly, d.detail)
        }
        Observation::Timestomp(t) => {
            path = t.path.to_string_lossy();
            severity = "high".into();
            format!("timestomp {}", path)
        }
        Observation::Mount(m) => {
            path = m.mountpoint.to_string_lossy();
            format!("mount {} {} {}", m.device, path, m.fstype)
        }
        Observation::LogIntegrity(l) => {
            path = l.path.to_string_lossy();
            severity = "high".into();
            format!("log_integrity {}: {}", l.issue, l.detail)
        }
        Observation::UtmpSession(u) => {
            user = u.user.clone();
            process_id = u.pid.max(0) as u32;
            src_ip = u.host.clone();
            format!("session {}@{} pid={}", u.user, u.line, u.pid)
        }
        Observation::IntegrityMismatch(i) => {
            path = i.path.to_string_lossy();
            file_hash = i.actual_hash.clone();
            severity = "critical".into();
            format!("integrity mismatch {}", path)
        }
        Observation::IocHit(i) => {
            path = i.path.to_string_lossy();
            severity = format!("{:?}", i.severity).to_ascii_lowercase();
            format!("ioc {}={}", i.ioc_kind, i.ioc_value)
        }
        Observation::ContainerInfo(c) => {
            format!(
                "container in={} runtime={:?} privileged={}",
                c.in_container, c.runtime, c.privileged
            )
        }
        Observation::Recon(r) => {
            format!("recon {}", r.category)
        }
        Observation::Policy(p) => {
            check_id = p.code.clone();
            severity = format!("{:?}", p.severity).to_ascii_lowercase();
            format!("policy {}: {}", p.code, p.detail)
        }
    };

    let ext = serde_json::to_string(o).unwrap_or_else(|_| "{}".into());
    serde_json::json!({
        "timestamp": ts,
        "message": message,
        "source_type": "rustmite_probe",
        "source": "scan",
        "platform": "linux",
        "host_id": ctx.host_id.to_string(),
        "host_name": ctx.host_name,
        "scan_id": ctx.scan_id.to_string(),
        "collector": ctx.collector,
        "kind": kind,
        "check_id": check_id,
        "data_type": kind,
        "process_name": process_name,
        "process_id": process_id,
        "user": user,
        "path": path,
        "args": args,
        "cmdline": cmdline,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "file_hash": file_hash,
        "severity": severity,
        "exe_memfd": exe_memfd,
        "ext": ext,
    })
}

fn kind_of(o: &Observation) -> String {
    match o {
        Observation::Process(_) => "process",
        Observation::HiddenProcess(_) => "hidden_process",
        Observation::Socket(_) => "socket",
        Observation::HiddenSocket(_) => "hidden_socket",
        Observation::Module(_) => "module",
        Observation::HiddenModule(_) => "hidden_module",
        Observation::BpfProg(_) => "bpf_prog",
        Observation::FileMeta(_) => "file_meta",
        Observation::FileEntropy(_) => "file_entropy",
        Observation::ElfInfo(_) => "elf_info",
        Observation::Preload(_) => "preload",
        Observation::ScheduledTask(_) => "scheduled_task",
        Observation::Service(_) => "service",
        Observation::Account(_) => "account",
        Observation::ShadowEntry(_) => "shadow_entry",
        Observation::SudoRule(_) => "sudo_rule",
        Observation::AuthorizedKey(_) => "authorized_key",
        Observation::SshHostKey(_) => "ssh_host_key",
        Observation::DirAnomaly(_) => "dir_anomaly",
        Observation::Timestomp(_) => "timestomp",
        Observation::Mount(_) => "mount",
        Observation::LogIntegrity(_) => "log_integrity",
        Observation::UtmpSession(_) => "utmp_session",
        Observation::IntegrityMismatch(_) => "integrity_mismatch",
        Observation::IocHit(_) => "ioc_hit",
        Observation::ContainerInfo(_) => "container_info",
        Observation::Recon(_) => "recon",
        Observation::Policy(_) => "policy",
    }
    .into()
}

fn path_str(p: Option<&PathBytes>) -> String {
    p.map(|p| p.to_string_lossy()).unwrap_or_default()
}

fn path_bytes_join(parts: &[PathBytes]) -> String {
    parts
        .iter()
        .map(|p| p.to_string_lossy())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Full command line (argv) and arguments-only string for Hunt (`args` / `cmdline` columns).
fn process_argv_strings(exe: Option<&PathBytes>, cmdline: &[PathBytes]) -> (String, String) {
    let full = path_bytes_join(cmdline);
    if full.is_empty() {
        let exe_s = path_str(exe);
        return (String::new(), exe_s);
    }
    let exe_s = path_str(exe);
    let args = if cmdline.len() > 1 {
        path_bytes_join(&cmdline[1..])
    } else if !exe_s.is_empty() && full == exe_s {
        String::new()
    } else if !exe_s.is_empty() && full.starts_with(&exe_s) {
        full[exe_s.len()..].trim_start().to_string()
    } else {
        // cmdline[0] is often the exe; treat remainder as args when present.
        String::new()
    };
    (args, full)
}

/// Map virtual-agent process JSONL rows → ClickHouse `events` for RPL hunt.
///
/// `timestamp` is clamped to "now" when the vendor stamp is older than the events
/// table TTL (90 days) — otherwise rows are inserted then immediately dropped.
pub fn virtual_processes_to_events(
    host_id: Uuid,
    host_name: &str,
    rows: &[RawLogEntry],
) -> Vec<Value> {
    let now = utc_now_rfc3339();
    rows.iter()
        .map(|e| {
            let ts = hunt_event_ts(e.timestamp.as_deref(), &now);
            let path = e.path.clone();
            let args = e.args.trim().to_string();
            let cmdline = if args.is_empty() {
                if path.is_empty() {
                    e.name.clone()
                } else {
                    path.clone()
                }
            } else if path.is_empty() {
                format!("{} {}", e.name, args)
            } else {
                format!("{path} {args}")
            };
            let message = if args.is_empty() {
                format!("process pid={} comm={} exe={}", e.pid, e.name, path_or_dash(&path))
            } else {
                format!(
                    "process pid={} comm={} exe={} args={}",
                    e.pid,
                    e.name,
                    path_or_dash(&path),
                    args
                )
            };
            serde_json::json!({
                "timestamp": ts,
                "message": message,
                "source_type": "rustmite_virtual",
                "source": "virtual_ingest",
                "platform": "linux",
                "host_id": host_id.to_string(),
                "host_name": host_name,
                "scan_id": "",
                "collector": "virtual.process",
                "kind": "process",
                "check_id": "",
                "data_type": "process",
                "process_name": e.name,
                "process_id": e.pid,
                "user": e.uid.to_string(),
                "path": path,
                "args": args,
                "cmdline": cmdline,
                "src_ip": "",
                "dest_ip": "",
                "file_hash": "",
                "severity": "info",
                "exe_memfd": 0,
                "ext": serde_json::to_string(e).unwrap_or_else(|_| "{}".into()),
            })
        })
        .collect()
}

/// Map virtual-agent file JSONL rows → ClickHouse `events` for RPL hunt.
pub fn virtual_files_to_events(
    host_id: Uuid,
    host_name: &str,
    rows: &[RawFileEntry],
) -> Vec<Value> {
    let now = utc_now_rfc3339();
    rows.iter()
        .map(|e| {
            let ts = hunt_event_ts(
                e.timestamp
                    .as_deref()
                    .or(e.mtime.as_deref()),
                &now,
            );
            let message = format!("file_meta {}", e.path);
            serde_json::json!({
                "timestamp": ts,
                "message": message,
                "source_type": "rustmite_virtual",
                "source": "virtual_ingest",
                "platform": "linux",
                "host_id": host_id.to_string(),
                "host_name": host_name,
                "scan_id": "",
                "collector": "virtual.file",
                "kind": "file_meta",
                "check_id": "",
                "data_type": "file_meta",
                "process_name": "",
                "process_id": 0,
                "user": e.uid.to_string(),
                "path": e.path,
                "src_ip": "",
                "dest_ip": "",
                "file_hash": "",
                "severity": "info",
                "exe_memfd": 0,
                "ext": serde_json::to_string(e).unwrap_or_else(|_| "{}".into()),
            })
        })
        .collect()
}

fn path_or_dash(path: &str) -> &str {
    if path.is_empty() {
        "—"
    } else {
        path
    }
}

/// Prefer vendor time when it is within the events TTL window; otherwise use now
/// so virtual-import Hunt rows are not TTL-deleted on insert.
fn hunt_event_ts(raw: Option<&str>, now: &str) -> String {
    let fallback = clickhouse_ts(now);
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback;
    };
    let candidate = clickhouse_ts(raw);
    // Rough check: if the normalized stamp year-month looks older than ~80 days,
    // ClickHouse TTL (timestamp + 90d) would drop the row immediately.
    // Compare as strings `YYYY-MM-DD` prefix when both look like dates.
    let now_day = fallback.get(..10).unwrap_or("");
    let cand_day = candidate.get(..10).unwrap_or("");
    if cand_day.len() == 10 && now_day.len() == 10 && cand_day < now_day {
        // days between via simple ordinal approximation on YYYY-MM-DD
        if let (Ok(a), Ok(b)) = (ymd_ord(cand_day), ymd_ord(now_day)) {
            if b.saturating_sub(a) > 80 {
                return fallback;
            }
        }
    }
    candidate
}

fn ymd_ord(ymd: &str) -> Result<i64, ()> {
    let y: i64 = ymd.get(0..4).ok_or(())?.parse().map_err(|_| ())?;
    let m: i64 = ymd.get(5..7).ok_or(())?.parse().map_err(|_| ())?;
    let d: i64 = ymd.get(8..10).ok_or(())?.parse().map_err(|_| ())?;
    Ok(y * 372 + m * 31 + d)
}

/// Normalize a timestamp into a ClickHouse `DateTime64(6)`-friendly string.
/// Bad / exotic vendor stamps fall back to now so a single bad row cannot abort
/// a whole JSONEachRow insert chunk (which left virtual Hunt empty).
fn clickhouse_ts(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return format_ch_ts(&utc_now_rfc3339());
    }
    // Unix seconds / millis (common in CSV / vendor JSONL).
    if let Ok(n) = s.parse::<i64>() {
        let secs = if n > 1_000_000_000_000 {
            n / 1000
        } else {
            n
        };
        if (1_000_000_000..4_000_000_000).contains(&secs) {
            if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) {
                return format_offset_ch(dt);
            }
        }
    }
    // RFC3339 / ISO-ish with offset — avoid truncating `+00:00` into garbage.
    if let Ok(dt) = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
    {
        return format_offset_ch(dt.to_offset(time::UtcOffset::UTC));
    }
    let normalized = format_ch_ts(s);
    // Must look like `YYYY-MM-DD HH:MM:SS…` (no trailing timezone junk).
    if normalized.len() >= 19
        && normalized.as_bytes().get(4) == Some(&b'-')
        && normalized.as_bytes().get(10) == Some(&b' ')
        && !normalized.contains('+')
        && !normalized[11..].contains('-')
    {
        return normalized.chars().take(26).collect();
    }
    format_ch_ts(&utc_now_rfc3339())
}

fn format_offset_ch(dt: time::OffsetDateTime) -> String {
    // 2024-01-15 12:00:00.000000
    let (h, m, s) = dt.to_hms();
    let us = dt.microsecond();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        h,
        m,
        s,
        us
    )
}

fn format_ch_ts(raw: &str) -> String {
    // Strip a trailing numeric timezone (`+00:00` / `-05:00`) before truncating.
    let mut s = raw.replace('T', " ").replace('Z', "");
    if let Some(idx) = s.rfind(['+', '-']) {
        if idx > 10 {
            // Keep only if it looks like a timezone suffix, not a date dash.
            let tail = &s[idx..];
            if tail.len() >= 3 && tail.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit()) {
                s.truncate(idx);
            }
        }
    }
    s.chars().take(26).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::ProcessObs;

    #[test]
    fn process_event_has_comm() {
        let obs = Observation::Process(ProcessObs {
            pid: 1,
            ppid: 0,
            comm: "systemd".into(),
            exe: Some(PathBytes::from_str("/sbin/init")),
            exe_deleted: false,
            exe_memfd: false,
            cmdline: vec![
                PathBytes::from_str("/sbin/init"),
                PathBytes::from_str("auto"),
            ],
            cwd: None,
            root: None,
            uids: [0, 0, 0, 0],
            gids: [0, 0, 0, 0],
            starttime: 0,
            num_threads: 1,
            tty: 0,
            state: 'S',
            caps_eff: 0,
            ns: rustmite_proto::NamespaceIds {
                pid: None,
                net: None,
                mnt: None,
                user: None,
                uts: None,
                ipc: None,
                cgroup: None,
            },
            rwx_maps: 0,
            unbacked_exec: 0,
            listen_ports: vec![],
            selinux: None,
            environ_flags: vec![],
            username: None,
        });
        let host = Uuid::nil();
        let scan = Uuid::nil();
        let ctx = EventContext {
            host_id: host,
            host_name: "vm",
            scan_id: scan,
            collector: "process.inventory",
            timestamp: "2026-09-16T14:00:00.000Z",
        };
        let rows = observations_to_events(&ctx, &[obs]);
        assert_eq!(rows[0]["process_name"], "systemd");
        assert_eq!(rows[0]["kind"], "process");
        assert_eq!(rows[0]["process_id"], 1);
        assert_eq!(rows[0]["args"], "auto");
        assert_eq!(rows[0]["cmdline"], "/sbin/init auto");
        assert!(rows[0]["message"].as_str().unwrap().contains("args=auto"));
    }

    #[test]
    fn virtual_process_rows_are_hunt_searchable() {
        let rows = virtual_processes_to_events(
            Uuid::nil(),
            "virt-host",
            &[RawLogEntry {
                machine_id: "virt-host".into(),
                pid: 42,
                ppid: 1,
                name: "nc".into(),
                uid: 0,
                path: "/usr/bin/nc".into(),
                args: "-lvp 4444".into(),
                timestamp: Some("2026-10-08T10:00:00Z".into()),
            }],
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "virtual_ingest");
        assert_eq!(rows[0]["process_name"], "nc");
        assert_eq!(rows[0]["host_name"], "virt-host");
        assert_eq!(rows[0]["args"], "-lvp 4444");
        assert_eq!(rows[0]["cmdline"], "/usr/bin/nc -lvp 4444");
        assert!(rows[0]["message"].as_str().unwrap().contains("nc"));
    }

    #[test]
    fn clickhouse_ts_handles_offsets_and_unix() {
        let with_offset = clickhouse_ts("2024-01-15T12:00:00+00:00");
        assert!(with_offset.starts_with("2024-01-15 12:00:00"), "{with_offset}");
        assert!(!with_offset.contains('+'), "{with_offset}");

        let unix = clickhouse_ts("1705312800"); // 2024-01-15T10:00:00Z
        assert!(unix.starts_with("2024-01-15"), "{unix}");

        let garbage = clickhouse_ts("not-a-date");
        assert!(garbage.starts_with("20"), "{garbage}");
        assert_eq!(garbage.as_bytes()[10], b' ');
    }
}
