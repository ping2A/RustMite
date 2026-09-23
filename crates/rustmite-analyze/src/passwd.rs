//! `/etc/passwd` line parsing.

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdEntry {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswdParseError {
    #[error("empty line")]
    Empty,
    #[error("missing fields")]
    MissingFields,
    #[error("invalid uid/gid")]
    InvalidId,
}

/// Parse a single `/etc/passwd` line.
pub fn parse_passwd_line(line: &str) -> Result<PasswdEntry, PasswdParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(PasswdParseError::Empty);
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return Err(PasswdParseError::MissingFields);
    }
    let username = parts.first().copied().unwrap_or("").to_string();
    if username.is_empty() {
        return Err(PasswdParseError::MissingFields);
    }
    let uid: u32 = parts
        .get(2)
        .ok_or(PasswdParseError::MissingFields)?
        .parse()
        .map_err(|_| PasswdParseError::InvalidId)?;
    let gid: u32 = parts
        .get(3)
        .ok_or(PasswdParseError::MissingFields)?
        .parse()
        .map_err(|_| PasswdParseError::InvalidId)?;
    let gecos = parts.get(4).copied().unwrap_or("").to_string();
    let home = parts.get(5).copied().unwrap_or("").to_string();
    let shell = parts.get(6).copied().unwrap_or("").to_string();

    Ok(PasswdEntry {
        username,
        uid,
        gid,
        gecos,
        home,
        shell,
    })
}

/// Parse all entries from a passwd file body.
pub fn parse_passwd(data: &str) -> Vec<PasswdEntry> {
    data.lines()
        .filter_map(|l| parse_passwd_line(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_root() {
        let e = parse_passwd_line("root:x:0:0:root:/root:/bin/bash").expect("parse");
        assert_eq!(e.username, "root");
        assert_eq!(e.uid, 0);
        assert_eq!(e.home, "/root");
        assert_eq!(e.shell, "/bin/bash");
    }

    #[test]
    fn parse_many() {
        let data = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        let v = parse_passwd(data);
        assert_eq!(v.len(), 2);
    }
}
