//! RustMite probe — stdin ScanRequest, stdout NDJSON envelopes.
//! Diagnostics go to stderr only (never println! — corrupts the stream).

#![forbid(unsafe_code)]

// M8: scan-only builds must not compile respond paths.
#[cfg(all(feature = "respond", not(feature = "respond")))]
compile_error!("unreachable");

#[cfg(not(feature = "respond"))]
const _: () = {
    // Documented: default probe is scan-only (no destructive ActionGrant execution).
};

use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use rustmite_collect::{run_plan, CollectCtx, NdjsonSink};
use rustmite_probe::{protect, sanitize_limits, summary_outcome};
use rustmite_proto::{
    Arch, Budget, CapabilitySet, CollectorStatus, Envelope, Hello, ProbeMode, ScanRequest,
    SCHEMA_VERSION, Summary, CollectorReport,
};
use rustmite_sys::{LiveFs, LiveProc, ProcSource};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_request() -> Result<ScanRequest, String> {
    let mut buf = Vec::new();
    io::stdin()
        .take(1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    let line = buf
        .split(|&b| b == b'\n')
        .next()
        .ok_or_else(|| "empty stdin".to_string())?;
    serde_json::from_slice(line).map_err(|e| e.to_string())
}

fn emit(env: &Envelope) {
    let mut out = io::stdout().lock();
    if let Ok(line) = serde_json::to_vec(env) {
        let _ = out.write_all(&line);
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

fn detect_caps() -> CapabilitySet {
    let mut caps = CapabilitySet {
        proc_exe_readable: true,
        ..CapabilitySet::default()
    };
    let proc = LiveProc;
    caps.proc_sched_debug = proc.read("proc/sched_debug").is_ok()
        || proc.read("/proc/sched_debug").is_ok();
    caps.cgroup_v2 = proc
        .read("sys/fs/cgroup/cgroup.controllers")
        .is_ok()
        || std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    caps.map_files = true;
    caps.statx = true;
    #[cfg(target_os = "linux")]
    {
        caps.memfd_create = true;
        caps.sock_diag = true;
    }
    caps
}

fn detect_arch() -> Arch {
    Arch::from_uname(std::env::consts::ARCH)
}

fn detect_kernel() -> String {
    let proc = LiveProc;
    if let Ok(b) = proc.read("proc/sys/kernel/osrelease") {
        return String::from_utf8_lossy(&b).trim().to_string();
    }
    if let Ok(b) = proc.read("/proc/sys/kernel/osrelease") {
        return String::from_utf8_lossy(&b).trim().to_string();
    }
    "unknown".into()
}

fn detect_boot_id() -> String {
    let proc = LiveProc;
    for p in ["proc/sys/kernel/random/boot_id", "/proc/sys/kernel/random/boot_id"] {
        if let Ok(b) = proc.read(p) {
            return String::from_utf8_lossy(&b).trim().to_string();
        }
    }
    "unknown".into()
}

fn detect_euid() -> u32 {
    #[cfg(unix)]
    {
        // Avoid libc: parse /proc/self/status when present (Linux); else 0 on macOS.
        if let Ok(b) = std::fs::read("/proc/self/status") {
            if let Ok(s) = std::str::from_utf8(&b) {
                for line in s.lines() {
                    if let Some(rest) = line.strip_prefix("Uid:") {
                        let mut parts = rest.split_whitespace();
                        // real effective saved fs
                        if let Some(eff) = parts.nth(1) {
                            if let Ok(v) = eff.parse() {
                                return v;
                            }
                        }
                    }
                }
            }
        }
    }
    0
}

fn main() {
    let req = match read_request() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rustmite-probe: bad request: {e}");
            std::process::exit(2);
        }
    };
    if req.schema != SCHEMA_VERSION {
        eprintln!(
            "rustmite-probe: unsupported schema {} (want {})",
            req.schema, SCHEMA_VERSION
        );
        std::process::exit(2);
    }

    protect::self_protect(&sanitize_limits(req.limits.clone()), req.mode);

    let start = now_ms();
    let nonce = encode_hex(&req.nonce);
    let euid = detect_euid();
    let hello = Hello {
        schema: SCHEMA_VERSION,
        probe_version: env!("CARGO_PKG_VERSION").into(),
        arch: detect_arch(),
        kernel: detect_kernel(),
        boot_id: detect_boot_id(),
        euid,
        pid: std::process::id() as i32,
        nonce: nonce.clone(),
        caps: detect_caps(),
    };
    emit(&Envelope::Hello(hello));

    if matches!(req.mode, ProbeMode::Selftest) {
        emit(&Envelope::Summary(Summary {
            outcome: "complete".into(),
            collectors: vec![],
            observation_count: 0,
            bytes_out: 0,
            elapsed_ms: now_ms().saturating_sub(start),
        }));
        std::process::exit(0);
    }

    let limits = sanitize_limits(req.limits.clone());
    let budget = Budget::new(&limits, req.deadline_ms, start);
    let proc = LiveProc;
    let fs = LiveFs;
    let mut sink = NdjsonSink::new();
    let ctx = CollectCtx {
        proc: &proc,
        fs: &fs,
        pid_probe: None,
        budget: &budget,
        euid,
        self_pid: std::process::id() as i32,
        now_ms: start,
    };

    let mut plan_failed = false;
    let reports = match run_plan(&req.plan, &ctx, &mut sink) {
        Ok(r) => r,
        Err(e) => {
            plan_failed = true;
            emit(&Envelope::Error {
                c: None,
                code: "collect".into(),
                msg: e.to_string(),
            });
            vec![CollectorReport {
                id: "plan".into(),
                status: CollectorStatus::Failed,
                reason: Some(e.to_string()),
                observations: 0,
                elapsed_ms: 0,
            }]
        }
    };

    let outcome = summary_outcome(&reports, plan_failed);
    emit(&Envelope::Summary(Summary {
        outcome: outcome.into(),
        collectors: reports,
        observation_count: budget.observation_count(),
        bytes_out: sink.bytes_out(),
        elapsed_ms: now_ms().saturating_sub(start),
    }));
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
