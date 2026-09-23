//! `/proc/<pid>/stat` parser — last-`)` rule (docs/03 §7.4, docs/14 trap #1).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Errno;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub num_threads: i64,
    pub starttime: u64,
}

/// Parse `/proc/<pid>/stat`.
///
/// Field 2 (`comm`) is wrapped in `()` and may contain spaces, `)`, and newlines.
/// Locate the **last** `)` in the buffer; everything between the first `(` and that
/// `)` is `comm`; fields after are space-separated.
pub fn parse_proc_stat(buf: &[u8]) -> Result<ProcStat, Errno> {
    let s = core::str::from_utf8(buf).map_err(|_| Errno::InvalidInput)?;
    let s = s.trim_end_matches('\n');

    let open = s.find('(').ok_or(Errno::InvalidInput)?;
    let close = s.rfind(')').ok_or(Errno::InvalidInput)?;
    if close <= open {
        return Err(Errno::InvalidInput);
    }

    let pid_str = s.get(..open).ok_or(Errno::InvalidInput)?.trim();
    let pid: i32 = pid_str.parse().map_err(|_| Errno::InvalidInput)?;
    let comm = s
        .get(open + 1..close)
        .ok_or(Errno::InvalidInput)?
        .to_string();

    let rest = s.get(close + 1..).ok_or(Errno::InvalidInput)?.trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // After comm: state(0), ppid(1), pgrp(2), session(3), tty_nr(4), tpgid(5),
    // flags(6), minflt(7), cminflt(8), majflt(9), cmajflt(10), utime(11), stime(12),
    // cutime(13), cstime(14), priority(15), nice(16), num_threads(17), itrealvalue(18),
    // starttime(19), ...
    let state = fields
        .first()
        .and_then(|f| f.chars().next())
        .ok_or(Errno::InvalidInput)?;
    let ppid = get_i32(&fields, 1)?;
    let pgrp = get_i32(&fields, 2)?;
    let session = get_i32(&fields, 3)?;
    let tty_nr = get_i32(&fields, 4)?;
    let num_threads = get_i64(&fields, 17)?;
    let starttime = get_u64(&fields, 19)?;

    Ok(ProcStat {
        pid,
        comm,
        state,
        ppid,
        pgrp,
        session,
        tty_nr,
        num_threads,
        starttime,
    })
}

fn get_i32(fields: &[&str], idx: usize) -> Result<i32, Errno> {
    fields
        .get(idx)
        .ok_or(Errno::InvalidInput)?
        .parse()
        .map_err(|_| Errno::InvalidInput)
}

fn get_i64(fields: &[&str], idx: usize) -> Result<i64, Errno> {
    fields
        .get(idx)
        .ok_or(Errno::InvalidInput)?
        .parse()
        .map_err(|_| Errno::InvalidInput)
}

fn get_u64(fields: &[&str], idx: usize) -> Result<u64, Errno> {
    fields
        .get(idx)
        .ok_or(Errno::InvalidInput)?
        .parse()
        .map_err(|_| Errno::InvalidInput)
}

/// Parse NUL-separated cmdline.
pub fn parse_cmdline(buf: &[u8]) -> Vec<Vec<u8>> {
    buf.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_vec())
        .collect()
}

/// Parse a simple `Key:\tvalue` status file line map.
pub fn parse_status_map(buf: &[u8]) -> alloc::collections::BTreeMap<String, String> {
    let mut map = alloc::collections::BTreeMap::new();
    if let Ok(s) = core::str::from_utf8(buf) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once(':') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_stat() {
        let line = b"1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        let st = parse_proc_stat(line).unwrap();
        assert_eq!(st.pid, 1);
        assert_eq!(st.comm, "systemd");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 0);
        assert_eq!(st.num_threads, 1);
        assert_eq!(st.starttime, 100);
    }

    #[test]
    fn comm_with_spaces_and_parens() {
        // comm = "1 (R 0"  — classic evasion against naive split_whitespace
        let line = b"42 (1 (R 0) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        let st = parse_proc_stat(line).unwrap();
        assert_eq!(st.pid, 42);
        assert_eq!(st.comm, "1 (R 0");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 1);
        assert_eq!(st.starttime, 999);
    }

    #[test]
    fn empty_rejects() {
        assert!(parse_proc_stat(b"").is_err());
        assert!(parse_proc_stat(b"no parens here").is_err());
    }
}
