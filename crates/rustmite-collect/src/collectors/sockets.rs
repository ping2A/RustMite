//! `net.sockets` — `/proc/net/{tcp,tcp6,udp,udp6}` + inode→PID via `/proc/<pid>/fd`.
//!
//! Owning-PID resolution requires reading other processes' fd tables. That only
//! works reliably as root; non-root scans leave `owning_pid` unset for foreign
//! sockets and must **not** treat that as a hidden-listener signal.

use std::collections::HashMap;

use rustmite_proto::{BigInt, CollectorCost, CollectorId, CollectorReport, Observation, SocketObs};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct SocketsCollector;

impl Collector for SocketsCollector {
    fn id(&self) -> &'static str {
        CollectorId::NET_SOCKETS.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let (inode_owners, pid_comms, walk) = map_socket_inodes_to_pid(ctx);
        let owner_lookup_reliable = walk.is_reliable(ctx.euid);
        let mut count = 0u32;
        for (path, family, protocol) in [
            ("proc/net/tcp", "ipv4", "tcp"),
            ("proc/net/tcp6", "ipv6", "tcp"),
            ("proc/net/udp", "ipv4", "udp"),
            ("proc/net/udp6", "ipv6", "udp"),
            ("proc/net/raw", "ipv4", "RAW"),
            ("proc/net/packet", "packet", "PACKET"),
        ] {
            let Ok(data) = ctx.proc.read(path) else {
                continue;
            };
            for mut sock in parse_proc_net_inet(&data, family, protocol) {
                if sock.owning_pid.is_none() {
                    if let Some(pid) = inode_owners.get(&sock.inode.0).copied() {
                        sock.owning_pid = Some(pid);
                        sock.owning_comm = pid_comms.get(&pid).cloned();
                    }
                }
                // Only flag "no owner" when we actually had a trustworthy fd walk.
                sock.owner_unresolved = sock.owning_pid.is_none()
                    && sock.state == "LISTEN"
                    && owner_lookup_reliable;
                emit(ctx, sink, Observation::Socket(sock))?;
                count = count.saturating_add(1);
            }
        }
        Ok(CollectorReport::complete(CollectorId::NET_SOCKETS, count, 0))
    }
}

#[derive(Default)]
struct FdWalkStats {
    pids_seen: u32,
    fd_dirs_ok: u32,
}

impl FdWalkStats {
    /// Root + ≥40% of pid fd dirs readable → safe to treat missing owners as signal.
    fn is_reliable(&self, euid: u32) -> bool {
        euid == 0
            && self.pids_seen >= 8
            && self.fd_dirs_ok * 100 / self.pids_seen.max(1) >= 40
    }
}

/// Build inode → owning PID by scanning `/proc/<pid>/fd/*` for `socket:[N]` targets.
fn map_socket_inodes_to_pid(
    ctx: &CollectCtx<'_>,
) -> (HashMap<String, i32>, HashMap<i32, String>, FdWalkStats) {
    let mut map = HashMap::new();
    let mut comms = HashMap::new();
    let mut stats = FdWalkStats::default();
    let Ok(ents) = ctx.proc.list_dir_raw("proc") else {
        return (map, comms, stats);
    };
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
        stats.pids_seen = stats.pids_seen.saturating_add(1);
        let fd_path = format!("proc/{pid}/fd");
        let Ok(fds) = ctx.proc.list_dir_raw(&fd_path) else {
            continue;
        };
        stats.fd_dirs_ok = stats.fd_dirs_ok.saturating_add(1);
        let mut saw_socket = false;
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
            if let Some(inode) = parse_socket_inode(s) {
                map.entry(inode).or_insert(pid);
                saw_socket = true;
            }
        }
        if saw_socket || map.values().any(|p| *p == pid) {
            if let Some(comm) = read_comm(ctx, pid) {
                comms.insert(pid, comm);
            }
        }
    }
    // Fill comm for any owner we recorded.
    for pid in map.values().copied().collect::<Vec<_>>() {
        if let std::collections::hash_map::Entry::Vacant(e) = comms.entry(pid) {
            if let Some(comm) = read_comm(ctx, pid) {
                e.insert(comm);
            }
        }
    }
    (map, comms, stats)
}

fn read_comm(ctx: &CollectCtx<'_>, pid: i32) -> Option<String> {
    let data = ctx.proc.read(&format!("proc/{pid}/comm")).ok()?;
    let s = core::str::from_utf8(&data).ok()?;
    let trimmed = s.trim().trim_end_matches('\n');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_socket_inode(target: &str) -> Option<String> {
    let rest = target.strip_prefix("socket:[")?;
    let inode = rest.strip_suffix(']')?;
    if inode.is_empty() || inode == "0" {
        return None;
    }
    Some(inode.to_string())
}

fn parse_proc_net_inet(data: &[u8], family: &str, protocol: &str) -> Vec<SocketObs> {
    let Ok(s) = core::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in s.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... uid ... inode
        let Some(local) = parts.get(1).copied() else {
            continue;
        };
        let Some(remote) = parts.get(2).copied() else {
            continue;
        };
        let state_hex = parts.get(3).copied().unwrap_or("00");
        let uid = parts
            .get(7)
            .and_then(|u| u.parse().ok())
            .unwrap_or(0);
        let inode = parts.get(9).copied().unwrap_or("0");
        if inode == "0" {
            continue;
        }

        let (local_ip, local_port) = parse_addr(local, family);
        let (remote_ip, remote_port) = parse_addr(remote, family);

        let state = if protocol == "udp" {
            udp_state_name(state_hex).to_string()
        } else {
            tcp_state_name(state_hex).to_string()
        };

        out.push(SocketObs {
            inode: BigInt(inode.to_string()),
            family: family.to_string(),
            protocol: protocol.to_string(),
            state,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            uid,
            owning_pid: None,
            owning_comm: None,
            owner_unresolved: false,
        });
    }
    out
}

fn parse_addr(s: &str, family: &str) -> (String, u16) {
    let mut it = s.split(':');
    let ip_hex = it.next().unwrap_or("0");
    let port_hex = it.next().unwrap_or("0");
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    let ip = if family == "ipv4" {
        parse_ipv4_hex(ip_hex)
    } else {
        parse_ipv6_hex(ip_hex)
    };
    (ip, port)
}

fn parse_ipv4_hex(hex: &str) -> String {
    // Little-endian 8 hex digits.
    if hex.len() != 8 {
        return hex.to_string();
    }
    let Ok(v) = u32::from_str_radix(hex, 16) else {
        return hex.to_string();
    };
    let b = v.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn parse_ipv6_hex(hex: &str) -> String {
    // 32 hex digits, little-endian 32-bit words (same layout as /proc/net/tcp6).
    if hex.len() != 32 {
        return hex.to_string();
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let start = i * 8;
        let Ok(word) = u32::from_str_radix(&hex[start..start + 8], 16) else {
            return hex.to_string();
        };
        let wb = word.to_le_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&wb);
    }
    let mut parts = [0u16; 8];
    for i in 0..8 {
        parts[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    // Compact IPv4-mapped IPv6 (::ffff:a.b.c.d) and all-zero to friendlier forms.
    if parts[0] == 0
        && parts[1] == 0
        && parts[2] == 0
        && parts[3] == 0
        && parts[4] == 0
        && parts[5] == 0xffff
    {
        let b0 = (parts[6] >> 8) as u8;
        let b1 = (parts[6] & 0xff) as u8;
        let b2 = (parts[7] >> 8) as u8;
        let b3 = (parts[7] & 0xff) as u8;
        return format!("::ffff:{b0}.{b1}.{b2}.{b3}");
    }
    if parts.iter().all(|p| *p == 0) {
        return "::".to_string();
    }
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
    )
}

fn tcp_state_name(hex: &str) -> &'static str {
    match u8::from_str_radix(hex, 16).unwrap_or(0) {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn udp_state_name(hex: &str) -> &'static str {
    match u8::from_str_radix(hex, 16).unwrap_or(0) {
        0x01 => "ESTABLISHED", // connected UDP
        0x07 => "UNCONN",
        _ => "UDP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};
    use crate::VecSink;

    #[test]
    fn parse_listen_line() {
        let data = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n";
        let socks = parse_proc_net_inet(data, "ipv4", "tcp");
        assert_eq!(socks.len(), 1);
        let s = socks.first().expect("sock");
        assert_eq!(s.local_ip, "127.0.0.1");
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.state, "LISTEN");
        assert_eq!(s.inode.0, "12345");
        assert_eq!(s.protocol, "tcp");
    }

    #[test]
    fn parse_udp_line() {
        let data = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 99999 2 0000000000000000 0\n";
        let socks = parse_proc_net_inet(data, "ipv4", "udp");
        assert_eq!(socks.len(), 1);
        let s = socks.first().expect("sock");
        assert_eq!(s.local_ip, "0.0.0.0");
        assert_eq!(s.local_port, 53);
        assert_eq!(s.protocol, "udp");
        assert_eq!(s.state, "UNCONN");
        assert_eq!(s.inode.0, "99999");
    }

    #[test]
    fn maps_owning_pid_from_fd() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-sock")
            .with_dir("proc/42")
            .with_dir("proc/42/fd")
            .with_file("proc/42/comm", b"sshd\n")
            .with_link("proc/42/fd/3", "socket:[12345]")
            .with_file(
                "proc/net/tcp",
                b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n"
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
        SocketsCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let sock = sink.observations.iter().find_map(|o| match o {
            Observation::Socket(s) => Some(s),
            _ => None,
        });
        let sock = sock.expect("SocketObs");
        assert_eq!(sock.owning_pid, Some(42));
        assert_eq!(sock.owning_comm.as_deref(), Some("sshd"));
        // Only one pid fd dir → not enough coverage to call it unresolved.
        assert!(!sock.owner_unresolved);
    }

    #[test]
    fn non_root_does_not_mark_orphan_when_fd_unreadable() {
        // Listener present, but no readable fd dirs (simulates non-root).
        let fx = FixtureProc::new("/tmp/rustmite-fx-sock-orphan")
            .with_dir("proc/1")
            .with_dir("proc/2")
            .with_dir("proc/3")
            .with_dir("proc/4")
            .with_dir("proc/5")
            .with_dir("proc/6")
            .with_dir("proc/7")
            .with_dir("proc/8")
            .with_dir("proc/9")
            .with_file(
                "proc/net/tcp",
                b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10549 1 00000000 100 0 0 10 0\n"
                    .as_slice(),
            );
        let fs = FixtureFs::new();
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 1000, // non-root
            self_pid: 99,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        SocketsCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let sock = sink.observations.iter().find_map(|o| match o {
            Observation::Socket(s) => Some(s),
            _ => None,
        });
        let sock = sock.expect("SocketObs");
        assert_eq!(sock.local_port, 22);
        assert!(sock.owning_pid.is_none());
        assert!(!sock.owner_unresolved);
    }

    #[test]
    fn parse_socket_inode_ok() {
        assert_eq!(
            parse_socket_inode("socket:[12345]").as_deref(),
            Some("12345")
        );
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn ipv6_all_zero_is_compact() {
        assert_eq!(parse_ipv6_hex("00000000000000000000000000000000"), "::");
    }
}
