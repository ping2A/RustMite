//! Best-effort traditional `utmp` record parsing (384-byte records).

use thiserror::Error;

/// Classic Linux `utmp` record size on most glibc builds.
pub const UTMP_RECORD_SIZE: usize = 384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtmpRecord {
    pub ut_type: u16,
    pub pid: i32,
    pub line: String,
    pub user: String,
    pub host: String,
    pub time: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UtmpError {
    #[error("buffer shorter than one record")]
    TooShort,
}

/// Parse a buffer of concatenated 384-byte utmp records (best-effort field layout).
pub fn parse_utmp(data: &[u8]) -> Result<Vec<UtmpRecord>, UtmpError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() < UTMP_RECORD_SIZE {
        return Err(UtmpError::TooShort);
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while off.saturating_add(UTMP_RECORD_SIZE) <= data.len() {
        let end = off.saturating_add(UTMP_RECORD_SIZE);
        if let Some(rec) = data.get(off..end) {
            if let Some(parsed) = parse_one(rec) {
                out.push(parsed);
            }
        }
        off = end;
    }
    Ok(out)
}

fn parse_one(rec: &[u8]) -> Option<UtmpRecord> {
    if rec.len() < UTMP_RECORD_SIZE {
        return None;
    }
    // Layout (best-effort, traditional 384-byte):
    // 0:  ut_type (i16)
    // 4:  ut_pid (i32)
    // 8:  ut_line[32]
    // 40: ut_id[4]
    // 44: ut_user[32]
    // 76: ut_host[256]
    // 340: ut_tv.tv_sec (i32) on older; try both 340 and 348
    let ut_type = read_i16(rec, 0)? as u16;
    let pid = read_i32(rec, 4)?;
    let line = cstr_field(rec.get(8..40)?);
    let user = cstr_field(rec.get(44..76)?);
    let host = cstr_field(rec.get(76..332)?);
    let time = read_i32(rec, 340)
        .map(|t| t as u64)
        .or_else(|| read_i64(rec, 340).map(|t| t as u64))
        .unwrap_or(0);

    // Skip empty/zeroed records.
    if ut_type == 0 && pid == 0 && user.is_empty() && line.is_empty() {
        return None;
    }

    Some(UtmpRecord {
        ut_type,
        pid,
        line,
        user,
        host,
        time,
    })
}

fn read_i16(buf: &[u8], off: usize) -> Option<i16> {
    let b = buf.get(off..off.saturating_add(2))?;
    Some(i16::from_ne_bytes([*b.first()?, *b.get(1)?]))
}

fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    let b = buf.get(off..off.saturating_add(4))?;
    Some(i32::from_ne_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

fn read_i64(buf: &[u8], off: usize) -> Option<i64> {
    let b = buf.get(off..off.saturating_add(8))?;
    Some(i64::from_ne_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
        *b.get(4)?,
        *b.get(5)?,
        *b.get(6)?,
        *b.get(7)?,
    ]))
}

fn cstr_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(&[])).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_synthetic_record() {
        let mut rec = vec![0u8; UTMP_RECORD_SIZE];
        // type = 7 (USER_PROCESS)
        if let Some(b) = rec.get_mut(0..2) {
            b.copy_from_slice(&7i16.to_ne_bytes());
        }
        if let Some(b) = rec.get_mut(4..8) {
            b.copy_from_slice(&1234i32.to_ne_bytes());
        }
        if let Some(b) = rec.get_mut(8..12) {
            b[..3].copy_from_slice(b"pts");
        }
        if let Some(b) = rec.get_mut(44..48) {
            b.copy_from_slice(b"root");
        }
        if let Some(b) = rec.get_mut(76..80) {
            b.copy_from_slice(b"host");
        }
        if let Some(b) = rec.get_mut(340..344) {
            b.copy_from_slice(&1_700_000_000i32.to_ne_bytes());
        }
        let v = parse_utmp(&rec).expect("parse");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pid, 1234);
        assert_eq!(v[0].user, "root");
        assert_eq!(v[0].ut_type, 7);
    }

    #[test]
    fn empty_ok() {
        assert!(parse_utmp(&[]).unwrap().is_empty());
    }
}
