//! `process.inventory` — full process facts.

use std::collections::{HashMap, HashSet};

use rustmite_proto::{
    BigInt, CollectorCost, CollectorId, CollectorReport, NamespaceIds, Observation, PathBytes,
    ProcessObs,
};
use rustmite_sys::{parse_cmdline, parse_proc_stat, parse_status_map};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ProcessInventoryCollector;

impl Collector for ProcessInventoryCollector {
    fn id(&self) -> &'static str {
        CollectorId::PROCESS_INVENTORY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let listen_by_inode = listen_ports_by_inode(ctx);
        let passwd = load_passwd_names(ctx);
        let ents = ctx.proc.list_dir_raw("proc")?;
        let mut count = 0u32;
        for e in ents {
            if e.is_dot_or_dotdot() {
                continue;
            }
            let name = e.name_str();
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            if pid <= 0 || pid == ctx.self_pid {
                continue;
            }
            if let Some(obs) = collect_one(ctx, pid, &listen_by_inode, &passwd)? {
                emit(ctx, sink, Observation::Process(obs))?;
                count = count.saturating_add(1);
            }
        }
        Ok(CollectorReport::complete(
            CollectorId::PROCESS_INVENTORY,
            count,
            0,
        ))
    }
}

/// inode → listening local ports from `/proc/net/tcp{,6}`.
fn listen_ports_by_inode(ctx: &CollectCtx<'_>) -> HashMap<String, u16> {
    let mut map = HashMap::new();
    for path in ["proc/net/tcp", "proc/net/tcp6"] {
        let Ok(data) = ctx.proc.read(path) else {
            continue;
        };
        let Ok(s) = core::str::from_utf8(&data) else {
            continue;
        };
        for (i, line) in s.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let Some(local) = parts.get(1) else {
                continue;
            };
            let state_hex = parts.get(3).copied().unwrap_or("00");
            if u8::from_str_radix(state_hex, 16).unwrap_or(0) != 0x0A {
                continue; // LISTEN
            }
            let inode = parts.get(9).copied().unwrap_or("0");
            if inode == "0" {
                continue;
            }
            let port = local
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
                .unwrap_or(0);
            if port != 0 {
                map.insert(inode.to_string(), port);
            }
        }
    }
    map
}

fn load_passwd_names(ctx: &CollectCtx<'_>) -> HashMap<u32, String> {
    let Ok(data) = ctx.proc.read("etc/passwd") else {
        // Fall back to host path via fs when proc overlay has no etc/
        let Ok(data) = ctx.fs.read("/etc/passwd") else {
            return HashMap::new();
        };
        return parse_passwd(&data);
    };
    parse_passwd(&data)
}

fn parse_passwd(data: &[u8]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(s) = core::str::from_utf8(data) else {
        return map;
    };
    for line in s.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let Some(name) = parts.next() else {
            continue;
        };
        let _passwd = parts.next();
        let Some(uid_s) = parts.next() else {
            continue;
        };
        if let Ok(uid) = uid_s.parse::<u32>() {
            map.entry(uid).or_insert_with(|| name.to_string());
        }
    }
    map
}

fn collect_one(
    ctx: &CollectCtx<'_>,
    pid: i32,
    listen_by_inode: &HashMap<String, u16>,
    passwd: &HashMap<u32, String>,
) -> Result<Option<ProcessObs>, CollectError> {
    let stat_data = match ctx.proc.read(&format!("proc/{pid}/stat")) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let st = match parse_proc_stat(&stat_data) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let exe = ctx
        .proc
        .read_link(&format!("proc/{pid}/exe"))
        .ok()
        .map(PathBytes::new);
    let exe_deleted = exe.as_ref().map(|p| p.ends_with_deleted()).unwrap_or(false);
    let exe_memfd = exe.as_ref().map(|p| p.is_memfd()).unwrap_or(false);

    let cmdline = ctx
        .proc
        .read(&format!("proc/{pid}/cmdline"))
        .map(|b| {
            parse_cmdline(&b)
                .into_iter()
                .map(PathBytes::new)
                .collect()
        })
        .unwrap_or_default();

    let cwd = ctx
        .proc
        .read_link(&format!("proc/{pid}/cwd"))
        .ok()
        .map(PathBytes::new);
    let root = ctx
        .proc
        .read_link(&format!("proc/{pid}/root"))
        .ok()
        .map(PathBytes::new);

    let (uids, gids, caps_eff) = match ctx.proc.read(&format!("proc/{pid}/status")) {
        Ok(data) => {
            let map = parse_status_map(&data);
            let uids = parse_id_quad(map.get("Uid").map(String::as_str).unwrap_or(""));
            let gids = parse_id_quad(map.get("Gid").map(String::as_str).unwrap_or(""));
            let caps_eff = map
                .get("CapEff")
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                .unwrap_or(0);
            (uids, gids, caps_eff)
        }
        Err(_) => ([0; 4], [0; 4], 0),
    };

    let environ_flags = ctx
        .proc
        .read(&format!("proc/{pid}/environ"))
        .map(|b| detect_environ_flags(&b))
        .unwrap_or_default();

    let listen_ports = collect_listen_ports(ctx, pid, listen_by_inode);
    let ns = collect_namespaces(ctx, pid);
    let selinux = ctx
        .proc
        .read(&format!("proc/{pid}/attr/current"))
        .ok()
        .and_then(|b| {
            let s = core::str::from_utf8(&b).ok()?.trim().trim_end_matches('\0');
            if s.is_empty() || s == "kernel" {
                None
            } else {
                Some(s.to_string())
            }
        });
    let (rwx_maps, unbacked_exec) = scan_maps_flags(ctx, pid);
    let username = uids.first().and_then(|u| passwd.get(u).cloned());

    Ok(Some(ProcessObs {
        pid,
        ppid: st.ppid,
        comm: st.comm,
        exe,
        exe_deleted,
        exe_memfd,
        cmdline,
        cwd,
        root,
        uids,
        gids,
        username,
        starttime: st.starttime,
        num_threads: st.num_threads,
        tty: st.tty_nr,
        state: st.state,
        caps_eff,
        ns,
        rwx_maps,
        unbacked_exec,
        listen_ports,
        selinux,
        environ_flags,
    }))
}

fn collect_namespaces(ctx: &CollectCtx<'_>, pid: i32) -> NamespaceIds {
    NamespaceIds {
        pid: read_ns_inode(ctx, &format!("proc/{pid}/ns/pid")),
        net: read_ns_inode(ctx, &format!("proc/{pid}/ns/net")),
        mnt: read_ns_inode(ctx, &format!("proc/{pid}/ns/mnt")),
        user: read_ns_inode(ctx, &format!("proc/{pid}/ns/user")),
        uts: read_ns_inode(ctx, &format!("proc/{pid}/ns/uts")),
        ipc: read_ns_inode(ctx, &format!("proc/{pid}/ns/ipc")),
        cgroup: read_ns_inode(ctx, &format!("proc/{pid}/ns/cgroup")),
    }
}

fn read_ns_inode(ctx: &CollectCtx<'_>, path: &str) -> Option<BigInt> {
    let target = ctx.proc.read_link(path).ok()?;
    let s = core::str::from_utf8(&target).ok()?;
    // e.g. "pid:[4026531836]"
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    let id = s.get(start..end)?;
    if id.is_empty() {
        None
    } else {
        Some(BigInt(id.to_string()))
    }
}

/// Light pass over `/proc/<pid>/maps` for rwx anonymous / deleted-backed exec regions.
fn scan_maps_flags(ctx: &CollectCtx<'_>, pid: i32) -> (u32, u32) {
    let Ok(data) = ctx.proc.read(&format!("proc/{pid}/maps")) else {
        return (0, 0);
    };
    let Ok(s) = core::str::from_utf8(&data) else {
        return (0, 0);
    };
    let mut rwx = 0u32;
    let mut unbacked = 0u32;
    for (i, line) in s.lines().enumerate() {
        if i > 4000 {
            break; // bound cost
        }
        let mut parts = line.split_whitespace();
        let _range = parts.next();
        let Some(perms) = parts.next() else {
            continue;
        };
        let is_rwx = perms.len() >= 3
            && perms.as_bytes().get(0) == Some(&b'r')
            && perms.as_bytes().get(1) == Some(&b'w')
            && perms.as_bytes().get(2) == Some(&b'x');
        if is_rwx {
            rwx = rwx.saturating_add(1);
        }
        let pathname = parts.nth(3).unwrap_or("");
        let exec = perms.as_bytes().get(2) == Some(&b'x');
        if exec
            && (pathname.is_empty()
                || pathname == "[anon]"
                || pathname.starts_with("[anon:")
                || pathname.contains("(deleted)"))
        {
            unbacked = unbacked.saturating_add(1);
        }
    }
    (rwx, unbacked)
}

fn collect_listen_ports(
    ctx: &CollectCtx<'_>,
    pid: i32,
    listen_by_inode: &HashMap<String, u16>,
) -> Vec<u16> {
    if listen_by_inode.is_empty() {
        return Vec::new();
    }
    let fd_path = format!("proc/{pid}/fd");
    let Ok(fds) = ctx.proc.list_dir_raw(&fd_path) else {
        return Vec::new();
    };
    let mut ports = HashSet::new();
    for fd in fds {
        if fd.is_dot_or_dotdot() {
            continue;
        }
        let link = format!("proc/{pid}/fd/{}", fd.name_str());
        let Ok(target) = ctx.proc.read_link(&link) else {
            continue;
        };
        let Ok(s) = core::str::from_utf8(&target) else {
            continue;
        };
        let Some(rest) = s.strip_prefix("socket:[") else {
            continue;
        };
        let Some(inode) = rest.strip_suffix(']') else {
            continue;
        };
        if let Some(port) = listen_by_inode.get(inode) {
            ports.insert(*port);
        }
    }
    let mut out: Vec<u16> = ports.into_iter().collect();
    out.sort_unstable();
    out
}

fn parse_id_quad(s: &str) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (i, part) in s.split_whitespace().take(4).enumerate() {
        if let Ok(v) = part.parse::<u32>() {
            if let Some(slot) = out.get_mut(i) {
                *slot = v;
            }
        }
    }
    out
}

fn detect_environ_flags(buf: &[u8]) -> Vec<String> {
    let mut flags = Vec::new();
    for entry in buf.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let Ok(s) = core::str::from_utf8(entry) else {
            continue;
        };
        if s.starts_with("LD_PRELOAD=") {
            flags.push(String::from("LD_PRELOAD"));
        } else if s.starts_with("LD_LIBRARY_PATH=") {
            flags.push(String::from("LD_LIBRARY_PATH"));
        } else if s.starts_with("HISTFILE=/dev/null") {
            flags.push(String::from("HISTFILE_NULL"));
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};
    use crate::VecSink;

    fn make_stat(pid: i32, comm: &str, starttime: u64) -> String {
        format!(
            "{pid} ({comm}) S 0 {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {starttime} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        )
    }

    #[test]
    fn picks_up_memfd_exe() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-memfd")
            .with_dir("proc/42")
            .with_file("proc/42/stat", make_stat(42, "miner", 500))
            .with_file("proc/42/status", "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0\n")
            .with_file("proc/42/cmdline", b"miner\0".as_slice())
            .with_link("proc/42/exe", "/memfd:payload (deleted)");

        let fs = FixtureFs::new();
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        ProcessInventoryCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let p = sink.observations.iter().find_map(|o| match o {
            Observation::Process(p) => Some(p),
            _ => None,
        });
        let p = p.expect("ProcessObs");
        assert!(p.exe_memfd);
        assert!(p.exe_deleted);
        assert_eq!(p.pid, 42);
    }

    #[test]
    fn fills_listen_ports_from_fds() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-listen")
            .with_dir("proc/42")
            .with_dir("proc/42/fd")
            .with_file("proc/42/stat", make_stat(42, "sshd", 500))
            .with_file("proc/42/status", "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0\n")
            .with_file("proc/42/cmdline", b"sshd\0".as_slice())
            .with_link("proc/42/exe", "/usr/sbin/sshd")
            .with_link("proc/42/fd/3", "socket:[12345]")
            .with_file(
                "proc/net/tcp",
                b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n"
                    .as_slice(),
            );

        let fs = FixtureFs::new();
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        ProcessInventoryCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let p = sink.observations.iter().find_map(|o| match o {
            Observation::Process(p) => Some(p),
            _ => None,
        });
        let p = p.expect("ProcessObs");
        assert_eq!(p.listen_ports, vec![22]);
    }

    #[test]
    fn resolves_username_and_namespaces() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-proc-rich")
            .with_dir("proc/7")
            .with_file("proc/7/stat", make_stat(7, "nginx", 9))
            .with_file("proc/7/status", "Uid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\nCapEff:\t0\n")
            .with_file("proc/7/cmdline", b"nginx: worker\0".as_slice())
            .with_link("proc/7/exe", "/usr/sbin/nginx")
            .with_link("proc/7/ns/pid", "pid:[4026531836]")
            .with_link("proc/7/ns/net", "net:[4026531840]")
            .with_file("etc/passwd", b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
            .with_file(
                "proc/7/maps",
                b"00400000-00401000 r-xp 00000000 08:01 1 /usr/sbin/nginx\n\
                  7f000000-7f001000 rwxp 00000000 00:00 0 \n",
            );
        let fs = FixtureFs::new();
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        ProcessInventoryCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let p = sink.observations.iter().find_map(|o| match o {
            Observation::Process(p) => Some(p),
            _ => None,
        });
        let p = p.expect("ProcessObs");
        assert_eq!(p.username.as_deref(), Some("www-data"));
        assert_eq!(p.ns.pid.as_ref().map(|b| b.0.as_str()), Some("4026531836"));
        assert_eq!(p.ns.net.as_ref().map(|b| b.0.as_str()), Some("4026531840"));
        assert!(p.rwx_maps >= 1);
    }
}
