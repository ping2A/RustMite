//! Stage-0 loader: read length-prefixed LZ4 frame from stdin → memfd → exec.
//!
//! Critical: stdin must be read **unbuffered**. Rust's global `Stdin` uses an
//! internal BufReader that can pull the trailing ScanRequest JSON into
//! user-space buffers; those bytes are lost on `exec`, so the probe sees EOF
//! and emits zero observations.
//!
//! On non-Linux hosts this binary is a stub (dev/test only).

use std::io;

fn read_exact_unbuffered(buf: &mut [u8]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsFd, BorrowedFd};
        // SAFETY: stdin is fd 0 for the lifetime of this process.
        let fd = unsafe { BorrowedFd::borrow_raw(0) };
        let mut got = 0usize;
        while got < buf.len() {
            match rustix::io::read(fd.as_fd(), &mut buf[got..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stdin eof before frame complete",
                    ));
                }
                Ok(n) => got += n,
                Err(e) if e == rustix::io::Errno::INTR => continue,
                Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::io::Read;
        // Dev stub only — buffered loss does not matter for non-Linux.
        io::stdin().read_exact(buf)
    }
}

fn read_frame() -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_unbuffered(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    read_exact_unbuffered(&mut buf)?;
    Ok(buf)
}

fn main() {
    let compressed = match read_frame() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("rustmite-loader: read frame: {e}");
            std::process::exit(1);
        }
    };
    let probe = match lz4_flex::decompress_size_prepended(&compressed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("rustmite-loader: decompress: {e}");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = linux_memfd_exec(&probe) {
            eprintln!("rustmite-loader: memfd exec failed ({e})");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let path = std::env::temp_dir().join(format!("rustmite-probe-dev-{}", std::process::id()));
        if let Err(e) = std::fs::write(&path, &probe) {
            eprintln!("rustmite-loader: write: {e}");
            std::process::exit(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        }
        let err = std::process::Command::new(&path)
            .arg0("rustmite-probe")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .exec_replace();
        eprintln!("rustmite-loader: exec: {err}");
        let _ = std::fs::remove_file(&path);
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
trait ExecReplace {
    fn exec_replace(&mut self) -> std::io::Error;
    fn arg0(&mut self, _name: &str) -> &mut Self;
}

#[cfg(not(target_os = "linux"))]
impl ExecReplace for std::process::Command {
    fn exec_replace(&mut self) -> std::io::Error {
        match self.status() {
            Ok(st) => std::process::exit(st.code().unwrap_or(1)),
            Err(e) => e,
        }
    }
    fn arg0(&mut self, _name: &str) -> &mut Self {
        self
    }
}

#[cfg(target_os = "linux")]
fn linux_memfd_exec(probe: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    // No CLOEXEC: we exec via /proc/self/fd/N and the fd must remain open
    // until the new image is mapped.
    let fd = rustix::fs::memfd_create("rustmite-probe", rustix::fs::MemfdFlags::empty())
        .map_err(rix_err)?;

    let mut written = 0usize;
    while written < probe.len() {
        match rustix::io::write(&fd, &probe[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "memfd write returned 0",
                ));
            }
            Ok(n) => written += n,
            Err(e) if e == rustix::io::Errno::INTR => continue,
            Err(e) => return Err(rix_err(e)),
        }
    }

    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let mut cmd = std::process::Command::new(&path);
    cmd.arg0("rustmite-probe");
    let err = cmd.exec();
    let _keep = fd;
    Err(err)
}

#[cfg(target_os = "linux")]
fn rix_err(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}
