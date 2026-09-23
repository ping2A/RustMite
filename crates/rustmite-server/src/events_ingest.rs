//! Map probe observations → ClickHouse `events` rows for RPL hunting.

use rustmite_proto::{Observation, PathBytes};
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
            exe_memfd = u8::from(p.exe_memfd);
            severity = if p.exe_memfd || p.exe_deleted {
                "high".into()
            } else {
                "info".into()
            };
            format!(
                "process pid={} comm={} exe={}",
                p.pid,
                p.comm,
                if path.is_empty() { "—" } else { &path }
            )
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

fn clickhouse_ts(raw: &str) -> String {
    let s = raw.trim();
    let base = if s.is_empty() {
        utc_now_rfc3339()
    } else {
        s.to_string()
    };
    base.replace('T', " ")
        .trim_end_matches('Z')
        .replace('Z', "")
        .chars()
        .take(26)
        .collect()
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
            cmdline: vec![],
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
    }
}
