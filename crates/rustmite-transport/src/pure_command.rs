//! Method D — SSH-commands-only collection (no probe binary on the host).
//!
//! Runs a curated set of read-only shell/`cat` commands over the existing SSH
//! session (optionally via sudo), parses stdout into typed observations, and
//! always raises `RM-POL-0021` so operators know coverage is degraded vs a
//! full-fidelity probe.

use rustmite_analyze::{parse_authorized_key_line, parse_passwd, parse_shadow};
use rustmite_proto::{
    AccountObs, AuthorizedKeyObs, BigInt, CapabilitySet, CollectorId, CollectorReport, Envelope,
    FileMetaObs, Hello, Limits, ModuleObs, NamespaceIds, Observation, PathBytes, PolicyObs,
    PreloadObs, ProcessObs, SCHEMA_VERSION, Severity, ShadowEntryObs, SocketObs, SshHostKeyObs,
    Summary,
};

use crate::error::TransportError;
use crate::fingerprint::parse_uname_hint;
use crate::scan::SudoEscalation;
use crate::ssh::SshSession;
use crate::throttle::pace_transfer;

/// Default absolute roots AgentLite inventories when the host has no `collect_paths`.
pub const DEFAULT_COLLECT_PATHS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/etc",
    "/opt",
    "/root",
];

/// Max paths accepted from host config (defaults + extras).
const MAX_COLLECT_PATHS: usize = 64;
/// Soft per-scan ceiling for AgentLite file rows (still clamped by fleet `max_files_examined`).
const MAX_FILE_META_SOFT: usize = 1_500;

/// Shell prefix applying Settings → Agent limits on the remote session (best-effort).
fn script_resource_prefix(limits: &Limits) -> String {
    let mut s = String::new();
    let nice = i32::from(limits.nice).clamp(-20, 19);
    s.push_str(&format!("renice {nice} $$ >/dev/null 2>&1 || true\n"));
    if limits.io_idle {
        s.push_str("ionice -c3 -p $$ >/dev/null 2>&1 || true\n");
    }
    if limits.max_open_files > 0 {
        s.push_str(&format!(
            "ulimit -n {} 2>/dev/null || true\n",
            limits.max_open_files
        ));
    }
    if limits.max_rss_bytes > 0 {
        let kb = (limits.max_rss_bytes / 1024).max(1024);
        s.push_str(&format!("ulimit -v {kb} 2>/dev/null || true\n"));
    }
    s
}

fn file_meta_cap(limits: &Limits) -> usize {
    let from_limits = limits.max_files_examined.max(1) as usize;
    from_limits.min(MAX_FILE_META_SOFT)
}

/// Curated remote script: section-tagged dumps of common forensic sources.
const COLLECT_SCRIPT: &str = r#"
set +e
echo '===META==='
uname -srm
id -u
id -un
cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown
echo '===PASSWD==='
cat /etc/passwd 2>/dev/null || true
echo '===SHADOW==='
cat /etc/shadow 2>/dev/null || true
echo '===MODULES==='
cat /proc/modules 2>/dev/null || true
echo '===SYSMODULES==='
# Loadable LKMs only (have initstate). Built-ins live under /sys/module without it.
if [ -d /sys/module ]; then
  echo 'OK=1'
  for d in /sys/module/*; do
    [ -d "$d" ] || continue
    [ -f "$d/initstate" ] || continue
    basename "$d"
  done 2>/dev/null || true
else
  echo 'OK=0'
fi
echo '===PRELOAD==='
if [ -e /etc/ld.so.preload ]; then
  echo 'PRESENT=1'
  cat /etc/ld.so.preload 2>/dev/null || true
else
  echo 'PRESENT=0'
fi
echo '===PROCESSES==='
n=0
for d in /proc/[0-9]*; do
  [ -r "$d/stat" ] || continue
  pid=${d#/proc/}
  # shellcheck disable=SC2034
  read -r _ comm state ppid _ < "$d/stat" 2>/dev/null || continue
  comm=${comm#(}
  comm=${comm%)}
  uid=$(awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null)
  gid=$(awk '/^Gid:/{print $2; exit}' "$d/status" 2>/dev/null)
  cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
  cmd=${cmd%" "}
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$pid" "$ppid" "${uid:-0}" "${gid:-0}" "${state:--}" "$comm" "$cmd"
  n=$((n+1))
  [ "$n" -ge 1000 ] && break
done
echo '===AUTHKEYS==='
while IFS=: read -r user _ uid _ _ home _; do
  [ -n "$home" ] || continue
  f="$home/.ssh/authorized_keys"
  if [ -r "$f" ]; then
    printf '@@USER=%s@@PATH=%s@@\n' "$user" "$f"
    cat "$f" 2>/dev/null || true
  fi
done < /etc/passwd 2>/dev/null
echo '===HOSTKEYS==='
for f in /etc/ssh/ssh_host_*.pub; do
  [ -f "$f" ] || continue
  printf '@@PATH=%s@@\n' "$f"
  cat "$f" 2>/dev/null || true
done
echo '===END==='
"#;

/// Separate network dump — kept free of single-quotes so SSH `sh -c '…'` nesting stays reliable.
const NET_COLLECT_SCRIPT: &str = r#"
set +e
echo ===NET_TCP===
sed -n "1,2001p" /proc/net/tcp 2>/dev/null || true
echo ===NET_TCP6===
sed -n "1,2001p" /proc/net/tcp6 2>/dev/null || true
echo ===NET_UDP===
sed -n "1,2001p" /proc/net/udp 2>/dev/null || true
echo ===NET_UDP6===
sed -n "1,2001p" /proc/net/udp6 2>/dev/null || true
echo ===SOCKOWNERS===
on=0
for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  [ -d "$d/fd" ] || continue
  for f in "$d"/fd/*; do
    [ -L "$f" ] || continue
    t=$(readlink "$f" 2>/dev/null) || continue
    case "$t" in
      socket:*)
        inode=${t#socket:[}
        inode=${inode%]}
        if [ -n "$inode" ] && [ "$inode" != 0 ]; then
          printf "%s|%s\n" "$inode" "$pid"
        fi
        ;;
    esac
  done
  on=$((on+1))
  [ "$on" -ge 300 ] && break
done
echo ===END===
"#;

/// Parse host `collect_paths` label (comma / newline / semicolon) and merge with defaults.
pub fn resolve_collect_paths(raw: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in DEFAULT_COLLECT_PATHS {
        push_collect_path(&mut out, &mut seen, p);
    }
    if let Some(raw) = raw {
        for part in raw.split(|c| c == '\n' || c == ',' || c == ';') {
            push_collect_path(&mut out, &mut seen, part.trim());
        }
    }
    out
}

fn push_collect_path(
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
    raw: &str,
) {
    if out.len() >= MAX_COLLECT_PATHS {
        return;
    }
    let p = raw.trim();
    if p.is_empty() || !p.starts_with('/') {
        return;
    }
    if p.len() > 512 || p.contains('\0') || p.contains('\n') || p.contains('\r') {
        return;
    }
    // Reject path traversal segments while still allowing absolute targets.
    if p.split('/').any(|seg| seg == "..") {
        return;
    }
    if seen.insert(p.to_string()) {
        out.push(p.to_string());
    }
}

/// Escape a string for inclusion inside a single-quoted shell literal in a script body.
fn sh_escape_single(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Build a dedicated file-inventory script for the given absolute paths.
fn build_file_collect_script(paths: &[String], max_files: usize) -> String {
    let max_files = max_files.max(1);
    let per_path = (max_files / paths.len().max(1)).clamp(1, 150);
    let mut s = String::from(
        r#"
set +e
echo ===FILEMETA===
n=0
emit_file() {
  f=$1
  [ -n "$f" ] || return 0
  [ -f "$f" ] || return 0
  st=$(stat -c '%a|%u|%g|%s|%i|%h|%U|%G' "$f" 2>/dev/null) || return 0
  printf '%s|%s\n' "$f" "$st"
  n=$((n+1))
}
"#,
    );
    for p in paths {
        let q = sh_escape_single(p);
        s.push_str(&format!(
            r#"
p='{q}'
if [ "$n" -lt {max} ]; then
  if [ -d "$p" ]; then
    # Prefer directories (incl. symlink→dir like /bin → usr/bin) over -L file branch.
    # shellcheck disable=SC2044
    for f in $(find "$p" -xdev -maxdepth 3 \( -name .cache -o -name node_modules -o -name .git -o -name .npm \) -prune -o -type f -print 2>/dev/null | head -n {per}); do
      [ "$n" -ge {max} ] && break
      emit_file "$f"
    done
  elif [ -f "$p" ]; then
    emit_file "$p"
  fi
fi
"#,
            q = q,
            max = max_files,
            per = per_path,
        ));
    }
    s.push_str("echo ===END===\n");
    s
}

fn parse_file_meta_line(line: &str) -> Option<FileMetaObs> {
    // path|mode|uid|gid|size|inode|nlink[|owner|group]
    // path may contain '|' rarely — take fixed fields from the right.
    let mut parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 7 {
        return None;
    }
    let (owner, group) = if parts.len() >= 9 {
        let g = parts.pop()?.trim().to_string();
        let o = parts.pop()?.trim().to_string();
        let owner = if o.is_empty() || o == "?" {
            None
        } else {
            Some(o)
        };
        let group = if g.is_empty() || g == "?" {
            None
        } else {
            Some(g)
        };
        (owner, group)
    } else {
        (None, None)
    };
    let nlink = parts.pop()?.parse().ok()?;
    let inode = parts.pop()?.to_string();
    let size = parts.pop()?.to_string();
    let gid: u32 = parts.pop()?.parse().ok()?;
    let uid: u32 = parts.pop()?.parse().ok()?;
    let mode_s = parts.pop()?;
    let path = parts.join("|");
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }
    if !size.chars().all(|c| c.is_ascii_digit()) || !inode.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mode = u32::from_str_radix(mode_s.trim(), 8).ok()?;
    let setuid = mode & 0o4000 != 0;
    let setgid = mode & 0o2000 != 0;
    Some(FileMetaObs {
        path: PathBytes::from(path),
        mode,
        uid,
        gid,
        size: BigInt(size),
        inode: BigInt(inode),
        nlink,
        setuid,
        setgid,
        immutable: false,
        owner,
        group,
    })
}

/// Quote a string for `sh -c '…'` (single-quote escaping).
fn sh_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

async fn exec_script(
    session: &SshSession,
    sudo: &SudoEscalation<'_>,
    script: &str,
) -> Result<(String, String), TransportError> {
    let quoted = sh_single_quote(script);
    match sudo {
        SudoEscalation::None => {
            let cmd = format!("sh -c {quoted}");
            let (out, err, _) = session.exec(&cmd, None).await?;
            Ok((
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            ))
        }
        SudoEscalation::Nopasswd => {
            let cmd = format!("sudo -n -p '' sh -c {quoted}");
            let (out, err, _) = session.exec(&cmd, None).await?;
            Ok((
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            ))
        }
        SudoEscalation::Password { password } => {
            if password.is_empty() {
                return Err(TransportError::Delivery("sudo password is empty".into()));
            }
            if password.contains('\n') || password.contains('\r') {
                return Err(TransportError::Delivery(
                    "sudo password must not contain newlines".into(),
                ));
            }
            let cmd = format!("sudo -S -p '' sh -c {quoted}");
            let mut stdin = password.as_bytes().to_vec();
            stdin.push(b'\n');
            let (out, err, _) = session.exec(&cmd, Some(&stdin)).await?;
            Ok((
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            ))
        }
    }
}

fn section<'a>(text: &'a str, name: &str) -> &'a str {
    let start_tag = format!("==={name}===");
    let Some(rest) = text.split(&start_tag).nth(1) else {
        return "";
    };
    let rest = rest.trim_start_matches('\n');
    if let Some(end) = rest.find("\n===") {
        &rest[..end]
    } else {
        rest
    }
}

fn push_obs(out: &mut Vec<Envelope>, collector: &str, n: &mut u32, d: Observation) {
    out.push(Envelope::Obs {
        c: collector.into(),
        n: *n,
        d,
    });
    *n = n.saturating_add(1);
}

/// Push an observation if the fleet `max_observations` budget still has room.
fn push_obs_capped(
    out: &mut Vec<Envelope>,
    collector: &str,
    n: &mut u32,
    total: &mut u32,
    max_obs: u32,
    d: Observation,
) -> bool {
    if *total >= max_obs {
        return false;
    }
    push_obs(out, collector, n, d);
    *total = total.saturating_add(1);
    true
}

fn parse_process_line(line: &str) -> Option<ProcessObs> {
    let mut parts = line.splitn(7, '|');
    let pid: i32 = parts.next()?.parse().ok()?;
    let ppid: i32 = parts.next()?.parse().ok()?;
    let uid: u32 = parts.next()?.parse().ok()?;
    let gid: u32 = parts.next()?.parse().ok()?;
    let state_s = parts.next().unwrap_or("-");
    let state = state_s.chars().next().unwrap_or('?');
    let comm = parts.next().unwrap_or("").to_string();
    let cmd = parts.next().unwrap_or("").trim();
    let cmdline: Vec<PathBytes> = if cmd.is_empty() {
        Vec::new()
    } else {
        cmd.split_whitespace()
            .map(|s| PathBytes::from(s.to_string()))
            .collect()
    };
    Some(ProcessObs {
        pid,
        ppid,
        comm,
        exe: None,
        exe_deleted: false,
        exe_memfd: false,
        cmdline,
        cwd: None,
        root: None,
        uids: [uid, uid, uid, uid],
        gids: [gid, gid, gid, gid],
        username: None,
        starttime: 0,
        num_threads: 1,
        tty: 0,
        state,
        caps_eff: 0,
        ns: NamespaceIds::default(),
        rwx_maps: 0,
        unbacked_exec: 0,
        listen_ports: Vec::new(),
        selinux: None,
        environ_flags: Vec::new(),
    })
}

fn parse_modules(proc_body: &str, sys_body: &str) -> Vec<(ModuleObs, bool)> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut proc_mods: BTreeMap<String, (Option<u64>, Option<i32>, Vec<String>)> = BTreeMap::new();
    for line in proc_body.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(name) = parts.first().copied() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let size = parts.get(1).and_then(|x| x.parse().ok());
        let refcount = parts.get(2).and_then(|x| x.parse().ok());
        let used_by = parts
            .get(3)
            .map(|u| {
                u.split(',')
                    .filter(|x| !x.is_empty() && *x != "-")
                    .map(|x| x.to_string())
                    .collect()
            })
            .unwrap_or_default();
        proc_mods.insert(name.to_string(), (size, refcount, used_by));
    }

    let sysfs_ok = sys_body.lines().any(|l| l.trim() == "OK=1");
    let mut sys_mods: BTreeSet<String> = BTreeSet::new();
    if sysfs_ok {
        for line in sys_body.lines() {
            let name = line.trim();
            if name.is_empty() || name.starts_with("OK=") {
                continue;
            }
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                sys_mods.insert(name.to_string());
            }
        }
    }

    // Without a usable /sys/module inventory we cannot assert disagreement —
    // emit inventory-only rows (both sides true) so RM-KERN-0001 does not FP.
    let sysfs_usable = sysfs_ok && (!sys_mods.is_empty() || proc_mods.is_empty());
    if !sysfs_usable {
        return proc_mods
            .into_iter()
            .map(|(name, (size, refcount, used_by))| {
                (
                    ModuleObs {
                        name,
                        size,
                        refcount,
                        used_by,
                        in_sysfs: true,
                        in_proc_modules: true,
                        taint_flags: None,
                    },
                    false,
                )
            })
            .collect();
    }

    let all: BTreeSet<String> = proc_mods
        .keys()
        .chain(sys_mods.iter())
        .cloned()
        .collect();

    let mut out = Vec::with_capacity(all.len());
    for name in all {
        let in_proc = proc_mods.contains_key(&name);
        let in_sysfs = sys_mods.contains(&name);
        let (size, refcount, used_by) = proc_mods
            .get(&name)
            .cloned()
            .unwrap_or((None, None, Vec::new()));
        let hidden = in_proc != in_sysfs;
        out.push((
            ModuleObs {
                name,
                size,
                refcount,
                used_by,
                in_sysfs,
                in_proc_modules: in_proc,
                taint_flags: None,
            },
            hidden,
        ));
    }
    out
}

fn parse_sock_owners(body: &str) -> std::collections::HashMap<String, i32> {
    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        let mut parts = line.splitn(2, '|');
        let Some(inode) = parts.next() else {
            continue;
        };
        let Some(pid) = parts.next().and_then(|p| p.parse().ok()) else {
            continue;
        };
        if inode.is_empty() || inode == "0" {
            continue;
        }
        map.entry(inode.to_string()).or_insert(pid);
    }
    map
}

fn parse_proc_net(body: &str, family: &str, protocol: &str) -> Vec<SocketObs> {
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Require classic /proc/net shape: "N: HEXIP:PORT HEXIP:PORT ST … inode"
        let Some(local) = parts.get(1).copied() else {
            continue;
        };
        let Some(remote) = parts.get(2).copied() else {
            continue;
        };
        if !local.contains(':') || !remote.contains(':') {
            continue;
        }
        let local_hex = local.split(':').next().unwrap_or("");
        if local_hex.len() != 8 && local_hex.len() != 32 {
            continue;
        }
        let state_hex = parts.get(3).copied().unwrap_or("00");
        if u8::from_str_radix(state_hex, 16).is_err() {
            continue;
        }
        let uid = parts.get(7).and_then(|u| u.parse().ok()).unwrap_or(0);
        let inode = parts.get(9).copied().unwrap_or("0");
        if inode == "0" || !inode.chars().all(|c| c.is_ascii_digit()) {
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
            // AgentLite fd walk is best-effort — never treat missing owners as signal.
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
        0x01 => "ESTABLISHED",
        0x07 => "UNCONN",
        _ => "UDP",
    }
}

/// Run Method D collection and emit an NDJSON observation stream.
///
/// `collect_paths_raw` is the optional host label (`collect_paths`) listing
/// extra absolute files/dirs to inventory; defaults are always included.
///
/// `limits` is the fleet Settings → Agent limits envelope (same as the full probe).
pub async fn collect_pure_command(
    session: &SshSession,
    sudo: &SudoEscalation<'_>,
    reason: &str,
    collect_paths_raw: Option<&str>,
    limits: &Limits,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let paths = resolve_collect_paths(collect_paths_raw);
    let file_cap = file_meta_cap(limits);
    let prefix = script_resource_prefix(limits);
    let collect_script = format!("{prefix}{COLLECT_SCRIPT}");
    let net_script = format!("{prefix}{NET_COLLECT_SCRIPT}");
    let file_script = format!(
        "{prefix}{}",
        build_file_collect_script(&paths, file_cap)
    );
    let (stdout, stderr) = exec_script(session, sudo, &collect_script).await?;
    let (net_stdout, net_stderr) = exec_script(session, sudo, &net_script).await?;
    let (file_stdout, file_stderr) = exec_script(session, sudo, &file_script).await?;
    // Pace the SSH result stream like probe delivery (`max_transfer_bps`).
    let transfer_bytes = stdout.len()
        .saturating_add(net_stdout.len())
        .saturating_add(file_stdout.len());
    pace_transfer(transfer_bytes, limits.max_transfer_bps).await;
    let mut stderr = stderr;
    for extra in [net_stderr, file_stderr] {
        if extra.is_empty() {
            continue;
        }
        if stderr.is_empty() {
            stderr = extra;
        } else {
            stderr = format!("{stderr}\n{extra}");
        }
    }

    let out = assemble_pure_command_ndjson(
        &stdout,
        &net_stdout,
        &file_stdout,
        reason,
        limits,
    )?;
    Ok((out, stderr.into_bytes()))
}

/// Build AgentLite NDJSON from remote script stdout (no SSH — unit-testable).
///
/// Applies the same `Limits` envelope as the full probe: observation caps,
/// file-meta soft/hard caps, and `max_output_bytes` on the encoded stream.
pub fn assemble_pure_command_ndjson(
    stdout: &str,
    net_stdout: &str,
    file_stdout: &str,
    reason: &str,
    limits: &Limits,
) -> Result<Vec<u8>, TransportError> {
    let file_cap = file_meta_cap(limits);
    let max_obs = limits.max_observations.max(1);

    let meta = section(stdout, "META");
    let fp = parse_uname_hint(meta);
    let boot_id = meta
        .lines()
        .nth(3)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());

    let mut envelopes: Vec<Envelope> = Vec::new();
    envelopes.push(Envelope::Hello(Hello {
        schema: SCHEMA_VERSION,
        probe_version: "pure-command".into(),
        arch: fp.arch,
        kernel: fp.kernel.clone(),
        boot_id,
        euid: fp.euid.unwrap_or(0),
        pid: 0,
        nonce: "00".repeat(32),
        caps: CapabilitySet::default(),
    }));

    let mut obs_n = 0u32;
    let mut truncated = false;
    let mut reports: Vec<CollectorReport> = Vec::new();

    // Accounts
    {
        let body = section(stdout, "PASSWD");
        let mut n = 0u32;
        for e in parse_passwd(body) {
            if !push_obs_capped(
                &mut envelopes,
                CollectorId::PERSISTENCE_ACCOUNTS.as_str(),
                &mut n,
                &mut obs_n,
                max_obs,
                Observation::Account(AccountObs {
                    username: e.username,
                    uid: e.uid,
                    gid: e.gid,
                    home: PathBytes::from(e.home),
                    shell: PathBytes::from(e.shell),
                    gecos: e.gecos,
                }),
            ) {
                truncated = true;
                break;
            }
        }

        reports.push(CollectorReport::complete(
            CollectorId::PERSISTENCE_ACCOUNTS,
            n,
            0,
        ));
    }

    // Shadow (may be empty without sudo)
    {
        let body = section(stdout, "SHADOW");
        let mut n = 0u32;
        if body.trim().is_empty() {
            reports.push(CollectorReport::unsupported(
                CollectorId::CRED_AUDIT,
                "etc/shadow unreadable (need sudo or root SSH)",
            ));
        } else {
            for e in parse_shadow(body) {
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::CRED_AUDIT.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::ShadowEntry(ShadowEntryObs {
                        username: e.username,
                        algorithm: e.algorithm,
                        empty_password: e.empty,
                        locked: e.locked,
                        hash_fingerprint: e.hash_fingerprint,
                    }),
                ) {
                    truncated = true;
                    break;
                }
            }

            reports.push(CollectorReport::complete(CollectorId::CRED_AUDIT, n, 0));
        }
    }

    // Modules — compare /proc/modules vs loadable /sys/module (initstate present).
    {
        let proc_body = section(stdout, "MODULES");
        let sys_body = section(stdout, "SYSMODULES");
        let mut n = 0u32;
        for (m, hidden) in parse_modules(proc_body, sys_body) {
            let obs = if hidden {
                Observation::HiddenModule(m)
            } else {
                Observation::Module(m)
            };
            if !push_obs_capped(
                &mut envelopes,
                CollectorId::MODULES_LKM.as_str(),
                &mut n,
                &mut obs_n,
                max_obs,
                obs,
            ) {
                truncated = true;
                break;
            }
        }

        reports.push(CollectorReport::complete(CollectorId::MODULES_LKM, n, 0));
    }

    // Preload
    {
        let body = section(stdout, "PRELOAD");
        let present = body.lines().any(|l| l.trim() == "PRESENT=1");
        let entries: Vec<PathBytes> = body
            .lines()
            .filter(|l| !l.starts_with("PRESENT=") && !l.trim().is_empty())
            .flat_map(|l| l.split_whitespace())
            .map(|p| PathBytes::from(p.to_string()))
            .collect();
        let mut n = 0u32;
        if !push_obs_capped(
            &mut envelopes,
            CollectorId::PERSISTENCE_PRELOAD.as_str(),
            &mut n,
            &mut obs_n,
            max_obs,
            Observation::Preload(PreloadObs {
                path: PathBytes::from("/etc/ld.so.preload"),
                entries,
                present,
            }),
        ) {
            truncated = true;
        }

        reports.push(CollectorReport::complete(
            CollectorId::PERSISTENCE_PRELOAD,
            n,
            0,
        ));
    }

    // Processes
    {
        let body = section(stdout, "PROCESSES");
        let mut n = 0u32;
        for line in body.lines() {
            if let Some(p) = parse_process_line(line) {
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::PROCESS_INVENTORY.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::Process(p),
                ) {
                    truncated = true;
                    break;
                }
            }
        }

        reports.push(CollectorReport::complete(
            CollectorId::PROCESS_INVENTORY,
            n,
            0,
        ));
    }

    // Network sockets (/proc/net/tcp{,6} udp{,6}) — from dedicated NET_COLLECT_SCRIPT.
    {
        let owners = parse_sock_owners(section(net_stdout, "SOCKOWNERS"));
        let mut pid_comms: std::collections::HashMap<i32, String> =
            std::collections::HashMap::new();
        for env in &envelopes {
            if let Envelope::Obs {
                d: Observation::Process(p),
                ..
            } = env
            {
                pid_comms.insert(p.pid, p.comm.clone());
            }
        }
        let mut n = 0u32;
        'sockets: for (sec, family, protocol) in [
            ("NET_TCP", "ipv4", "tcp"),
            ("NET_TCP6", "ipv6", "tcp"),
            ("NET_UDP", "ipv4", "udp"),
            ("NET_UDP6", "ipv6", "udp"),
        ] {
            for mut sock in parse_proc_net(section(net_stdout, sec), family, protocol) {
                if let Some(pid) = owners.get(&sock.inode.0).copied() {
                    sock.owning_pid = Some(pid);
                    sock.owning_comm = pid_comms.get(&pid).cloned();
                }
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::NET_SOCKETS.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::Socket(sock),
                ) {
                    truncated = true;
                    break 'sockets;
                }
            }
        }

        if n == 0 && section(net_stdout, "NET_TCP").trim().is_empty() {
            reports.push(CollectorReport::unsupported(
                CollectorId::NET_SOCKETS,
                "/proc/net/tcp unreadable",
            ));
        } else {
            reports.push(CollectorReport::complete(CollectorId::NET_SOCKETS, n, 0));
        }
    }

    // File inventory (defaults + host collect_paths).
    {
        let body = section(file_stdout, "FILEMETA");
        let mut n = 0u32;
        for line in body.lines() {
            if n as usize >= file_cap {
                truncated = true;
                break;
            }
            if obs_n >= max_obs {
                truncated = true;
                break;
            }
            if let Some(f) = parse_file_meta_line(line) {
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::FILE_IOC.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::FileMeta(f),
                ) {
                    truncated = true;
                    break;
                }
            }
        }

        if n == 0 {
            reports.push(CollectorReport::unsupported(
                CollectorId::FILE_IOC,
                "no readable files under collect_paths (check permissions / paths)",
            ));
        } else {
            reports.push(CollectorReport::complete(CollectorId::FILE_IOC, n, 0));
        }
    }

    // Authorized keys + host keys
    {
        let body = section(stdout, "AUTHKEYS");
        let mut n = 0u32;
        let mut cur_user = String::new();
        let mut cur_path = String::new();
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("@@USER=") {
                if let Some((user, path_part)) = rest.split_once("@@PATH=") {
                    cur_user = user.to_string();
                    cur_path = path_part.trim_end_matches("@@").to_string();
                }
                continue;
            }
            if cur_user.is_empty() {
                continue;
            }
            if let Ok(parsed) = parse_authorized_key_line(line) {
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::SSH_KEYS.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::AuthorizedKey(AuthorizedKeyObs {
                        path: PathBytes::from(cur_path.clone()),
                        username: cur_user.clone(),
                        key_type: parsed.key_type,
                        fingerprint: parsed.fingerprint,
                        comment: parsed.comment,
                        options: parsed.options,
                        bits: parsed.bits,
                    }),
                ) {
                    truncated = true;
                    break;
                }
            }
        }

        let host_body = section(stdout, "HOSTKEYS");
        let mut cur_hk = String::new();
        for line in host_body.lines() {
            if let Some(rest) = line.strip_prefix("@@PATH=") {
                cur_hk = rest.trim_end_matches("@@").to_string();
                continue;
            }
            if cur_hk.is_empty() {
                continue;
            }
            if let Ok(parsed) = parse_authorized_key_line(line) {
                if !push_obs_capped(
                    &mut envelopes,
                    CollectorId::SSH_KEYS.as_str(),
                    &mut n,
                    &mut obs_n,
                    max_obs,
                    Observation::SshHostKey(SshHostKeyObs {
                        path: PathBytes::from(cur_hk.clone()),
                        key_type: parsed.key_type,
                        fingerprint: parsed.fingerprint,
                        changed: false,
                    }),
                ) {
                    truncated = true;
                    break;
                }
            }
        }

        reports.push(CollectorReport::complete(CollectorId::SSH_KEYS, n, 0));
    }

    // Always flag degraded fidelity (and note budget truncation when limits bite).
    {
        let mut n = 0u32;
        let detail = if truncated {
            format!(
                "{reason}; truncated by agent limits (max_observations={max_obs}, max_files_examined={file_cap})"
            )
        } else {
            reason.to_string()
        };
        // Prefer to always emit RM-POL-0021 even when the observation budget is exhausted.
        let policy_max = max_obs.saturating_add(1);
        let _ = push_obs_capped(
            &mut envelopes,
            "policy",
            &mut n,
            &mut obs_n,
            policy_max,
            Observation::Policy(PolicyObs {
                code: "RM-POL-0021".into(),
                detail,
                severity: Severity::High,
            }),
        );
    }
    reports.push(CollectorReport::complete(
        CollectorId::RECON_INVENTORY,
        0,
        0,
    ));

    let bytes_out = (stdout.len() as u64)
        .saturating_add(net_stdout.len() as u64)
        .saturating_add(file_stdout.len() as u64);
    envelopes.push(Envelope::Summary(Summary {
        outcome: if truncated {
            "partial".into()
        } else {
            "complete".into()
        },
        collectors: reports,
        observation_count: obs_n,
        bytes_out,
        elapsed_ms: 0,
    }));

    let mut out = Vec::new();
    for (i, env) in envelopes.iter().enumerate() {
        let line = serde_json::to_vec(env)
            .map_err(|e| TransportError::Delivery(format!("encode: {e}")))?;
        let would = (out.len() as u64).saturating_add(line.len() as u64 + 1);
        // Always keep Hello (index 0) so the stream remains parseable even under a
        // very tight max_output_bytes; drop later envelopes when the cap bites.
        if i > 0 && limits.max_output_bytes > 0 && would > limits.max_output_bytes {
            break;
        }
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_extracts_between_markers() {
        let text = "===META===\na\nb\n===PASSWD===\nroot:x:0:0::/root:/bin/bash\n===END===\n";
        assert_eq!(section(text, "PASSWD").trim(), "root:x:0:0::/root:/bin/bash");
        assert!(section(text, "SHADOW").is_empty());
    }

    #[test]
    fn parse_process_pipe_line() {
        let p = parse_process_line("1|0|0|0|S|systemd|/sbin/init splash").expect("parse");
        assert_eq!(p.pid, 1);
        assert_eq!(p.ppid, 0);
        assert_eq!(p.comm, "systemd");
        assert_eq!(p.state, 'S');
        assert_eq!(p.cmdline.len(), 2);
    }

    #[test]
    fn parse_tcp_listen_line() {
        let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n";
        let socks = parse_proc_net(body, "ipv4", "tcp");
        assert_eq!(socks.len(), 1);
        let s = socks.first().expect("sock");
        assert_eq!(s.local_ip, "127.0.0.1");
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.state, "LISTEN");
        assert_eq!(s.inode.0, "12345");
    }

    #[test]
    fn parse_sock_owner_map() {
        let m = parse_sock_owners("12345|42\n99|7\n");
        assert_eq!(m.get("12345"), Some(&42));
        assert_eq!(m.get("99"), Some(&7));
    }

    #[test]
    fn parse_modules_consistent_when_sysfs_matches() {
        let proc = "ac97_bus 16384 1 snd_ac97_codec Live 0x0\nfuse 163840 1 - Live 0x0\n";
        let sys = "OK=1\nac97_bus\nfuse\n";
        let rows = parse_modules(proc, sys);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|(_, hidden)| !*hidden));
        assert!(rows.iter().all(|(m, _)| m.in_sysfs && m.in_proc_modules));
    }

    #[test]
    fn parse_modules_flags_proc_only_as_hidden() {
        let proc = "evil 4096 1 - Live 0x0\n";
        let sys = "OK=1\nfuse\n";
        let rows = parse_modules(proc, sys);
        let evil = rows.iter().find(|(m, _)| m.name == "evil").expect("evil");
        assert!(evil.1);
        assert!(!evil.0.in_sysfs);
        assert!(evil.0.in_proc_modules);
    }

    #[test]
    fn parse_modules_skips_kern_fp_when_sysfs_missing() {
        let proc = "ac97_bus 16384 1 - Live 0x0\n";
        let rows = parse_modules(proc, "");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].1);
        assert!(rows[0].0.in_sysfs && rows[0].0.in_proc_modules);
    }

    #[test]
    fn resolve_collect_paths_merges_defaults_and_extras() {
        let paths = resolve_collect_paths(Some("/opt/app\n/var/www,/tmp\nbad\n../etc"));
        assert!(paths.iter().any(|p| p == "/bin"));
        assert!(paths.iter().any(|p| p == "/opt/app"));
        assert!(paths.iter().any(|p| p == "/var/www"));
        // /tmp already in defaults; still present once
        assert_eq!(paths.iter().filter(|p| p.as_str() == "/tmp").count(), 1);
        assert!(!paths.iter().any(|p| p == "bad"));
        assert!(!paths.iter().any(|p| p.contains("..")));
    }

    #[test]
    fn parse_file_meta_line_setuid() {
        let f = parse_file_meta_line("/usr/bin/passwd|4755|0|0|68248|123456|1|root|root").expect("meta");
        assert_eq!(f.uid, 0);
        assert!(f.setuid);
        assert!(!f.setgid);
        assert_eq!(f.size.0, "68248");
        assert_eq!(f.mode, 0o4755);
        assert_eq!(f.owner.as_deref(), Some("root"));
        assert_eq!(f.group.as_deref(), Some("root"));
        // Legacy lines without owner/group still parse.
        let legacy = parse_file_meta_line("/tmp/x|644|1000|1000|12|99|1").expect("legacy");
        assert_eq!(legacy.uid, 1000);
        assert!(legacy.owner.is_none());
    }

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_escape_single("a'b"), "a'\\''b");
        assert_eq!(sh_single_quote("a'b"), "'a'\\''b'");
    }

    fn sample_agentlite_stdout() -> String {
        let mut procs = String::new();
        for i in 1..=40 {
            procs.push_str(&format!("{i}|0|0|0|S|proc{i}|/bin/proc{i}\n"));
        }
        format!(
            "===META===\nLinux x86_64 6.8.0\n0\nroot\nboot-id-1\n\
===PASSWD===\nroot:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
===SHADOW===\n\
===MODULES===\nac97_bus 16384 1 - Live 0x0\nfuse 163840 1 - Live 0x0\n\
===SYSMODULES===\nOK=1\nac97_bus\nfuse\n\
===PRELOAD===\nPRESENT=0\n\
===PROCESSES===\n{procs}\
===AUTHKEYS===\n\
===HOSTKEYS===\n\
===END===\n"
        )
    }

    fn sample_file_stdout(n: usize) -> String {
        let mut files = String::from("===FILEMETA===\n");
        for i in 1..=n {
            files.push_str(&format!("/tmp/f{i}|644|0|0|10|{i}|1|root|root\n"));
        }
        files.push_str("===END===\n");
        files
    }

    fn decode_ndjson(raw: &[u8]) -> Vec<Envelope> {
        raw.split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Envelope>(l).expect("envelope json"))
            .collect()
    }

    fn obs_kinds(envs: &[Envelope]) -> Vec<&str> {
        envs.iter()
            .filter_map(|e| match e {
                Envelope::Obs { d, .. } => Some(match d {
                    Observation::Account(_) => "account",
                    Observation::Module(_) => "module",
                    Observation::HiddenModule(_) => "hidden_module",
                    Observation::Process(_) => "process",
                    Observation::FileMeta(_) => "file",
                    Observation::Policy(p) => {
                        if p.code == "RM-POL-0021" {
                            "policy_0021"
                        } else {
                            "policy"
                        }
                    }
                    Observation::Preload(_) => "preload",
                    Observation::Socket(_) => "socket",
                    _ => "other",
                }),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn script_resource_prefix_applies_agent_limits() {
        let limits = Limits {
            nice: 19,
            io_idle: true,
            max_open_files: 128,
            max_rss_bytes: 16 * 1024 * 1024,
            ..Limits::default()
        };
        let prefix = script_resource_prefix(&limits);
        assert!(prefix.contains("renice 19 $$"), "{prefix}");
        assert!(prefix.contains("ionice -c3"), "{prefix}");
        assert!(prefix.contains("ulimit -n 128"), "{prefix}");
        // 16 MiB → 16384 KiB
        assert!(prefix.contains("ulimit -v 16384"), "{prefix}");
    }

    #[test]
    fn script_resource_prefix_skips_zero_caps() {
        let limits = Limits {
            io_idle: false,
            max_open_files: 0,
            max_rss_bytes: 0,
            nice: 0,
            ..Limits::default()
        };
        let prefix = script_resource_prefix(&limits);
        assert!(prefix.contains("renice 0 $$"));
        assert!(!prefix.contains("ionice"));
        assert!(!prefix.contains("ulimit -n"));
        assert!(!prefix.contains("ulimit -v"));
    }

    #[test]
    fn file_meta_cap_respects_fleet_and_soft_ceiling() {
        assert_eq!(
            file_meta_cap(&Limits {
                max_files_examined: 100,
                ..Limits::default()
            }),
            100
        );
        assert_eq!(
            file_meta_cap(&Limits {
                max_files_examined: 50_000,
                ..Limits::default()
            }),
            MAX_FILE_META_SOFT
        );
        assert_eq!(
            file_meta_cap(&Limits {
                max_files_examined: 0,
                ..Limits::default()
            }),
            1
        );
    }

    #[test]
    fn file_collect_script_embeds_path_and_max() {
        let script = build_file_collect_script(
            &["/opt/app".into(), "/tmp".into()],
            20,
        );
        assert!(script.contains("===FILEMETA==="));
        assert!(script.contains("p='/opt/app'"));
        assert!(script.contains("p='/tmp'"));
        assert!(script.contains("head -n "));
        assert!(script.contains("[ \"$n\" -lt 20 ]") || script.contains("[ \"$n\" -ge 20 ]"));
    }

    #[test]
    fn agentlite_always_emits_policy_and_modules_without_fp() {
        let limits = Limits {
            max_observations: 500_000,
            max_output_bytes: 8 * 1024 * 1024,
            max_files_examined: 1_000,
            ..Limits::default()
        };
        let raw = assemble_pure_command_ndjson(
            &sample_agentlite_stdout(),
            "===NET_TCP===\n===END===\n",
            &sample_file_stdout(5),
            "method D",
            &limits,
        )
        .expect("assemble");
        let envs = decode_ndjson(&raw);
        let kinds = obs_kinds(&envs);
        assert!(kinds.contains(&"policy_0021"), "{kinds:?}");
        assert!(kinds.contains(&"module"), "{kinds:?}");
        assert!(!kinds.contains(&"hidden_module"), "no module FP: {kinds:?}");
        assert!(kinds.iter().filter(|k| **k == "process").count() >= 10);
        assert!(kinds.iter().filter(|k| **k == "file").count() == 5);
        let summary = envs
            .iter()
            .find_map(|e| match e {
                Envelope::Summary(s) => Some(s),
                _ => None,
            })
            .expect("summary");
        assert_eq!(summary.outcome, "complete");
    }

    #[test]
    fn agentlite_obs_budget_truncates_and_marks_partial() {
        let limits = Limits {
            max_observations: 5,
            max_output_bytes: 8 * 1024 * 1024,
            max_files_examined: 1_000,
            ..Limits::default()
        };
        let raw = assemble_pure_command_ndjson(
            &sample_agentlite_stdout(),
            "===NET_TCP===\n===END===\n",
            &sample_file_stdout(20),
            "method D",
            &limits,
        )
        .expect("assemble");
        let envs = decode_ndjson(&raw);
        let kinds = obs_kinds(&envs);
        // Budget is 5 (+1 reserved for policy) — must still raise RM-POL-0021.
        assert!(kinds.contains(&"policy_0021"), "{kinds:?}");
        let obs_count = kinds.len();
        assert!(obs_count <= 6, "obs_count={obs_count} kinds={kinds:?}");
        let summary = envs
            .iter()
            .find_map(|e| match e {
                Envelope::Summary(s) => Some(s),
                _ => None,
            })
            .expect("summary");
        assert_eq!(summary.outcome, "partial");
        let policy = envs.iter().find_map(|e| match e {
            Envelope::Obs {
                d: Observation::Policy(p),
                ..
            } => Some(p),
            _ => None,
        }).expect("policy");
        assert!(
            policy.detail.contains("truncated by agent limits"),
            "{}",
            policy.detail
        );
        assert!(policy.detail.contains("max_observations=5"));
    }

    #[test]
    fn agentlite_file_cap_truncates_file_meta_rows() {
        let limits = Limits {
            max_observations: 500_000,
            max_output_bytes: 8 * 1024 * 1024,
            max_files_examined: 3,
            ..Limits::default()
        };
        let raw = assemble_pure_command_ndjson(
            &sample_agentlite_stdout(),
            "===NET_TCP===\n===END===\n",
            &sample_file_stdout(20),
            "method D",
            &limits,
        )
        .expect("assemble");
        let envs = decode_ndjson(&raw);
        let file_n = obs_kinds(&envs).iter().filter(|k| **k == "file").count();
        assert_eq!(file_n, 3, "file_meta_cap should stop at 3");
        let summary = envs
            .iter()
            .find_map(|e| match e {
                Envelope::Summary(s) => Some(s),
                _ => None,
            })
            .expect("summary");
        assert_eq!(summary.outcome, "partial");
    }

    #[test]
    fn agentlite_output_byte_cap_keeps_hello() {
        let limits = Limits {
            max_observations: 500_000,
            // Tiny vs full stream — Hello must still be emitted.
            max_output_bytes: 200,
            max_files_examined: 1_000,
            ..Limits::default()
        };
        let raw = assemble_pure_command_ndjson(
            &sample_agentlite_stdout(),
            "===NET_TCP===\n===END===\n",
            &sample_file_stdout(5),
            "method D",
            &limits,
        )
        .expect("assemble");
        assert!(!raw.is_empty());
        let envs = decode_ndjson(&raw);
        assert!(matches!(envs.first(), Some(Envelope::Hello(_))));
        // Cap bites before full stream (complete assemble has dozens of envelopes).
        assert!(envs.len() < 15, "expected truncated NDJSON, got {} envs", envs.len());
    }
}
