//! Apply ScanRequest resource limits on the target host (docs/03 §2.1).
//! Best-effort; never panics. Linux-only rlimits via rustix.

use rustmite_proto::{Limits, ProbeMode};

/// Harden the probe process before collectors run.
pub fn self_protect(limits: &Limits, mode: ProbeMode) {
    #[cfg(target_os = "linux")]
    {
        linux_protect(limits, mode);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (limits, mode);
    }
}

#[cfg(target_os = "linux")]
fn linux_protect(limits: &Limits, mode: ProbeMode) {
    use rustix::process::{setpriority_process, setrlimit, Resource, Rlimit};

    // Absolute nice (docs/03 default 19).
    let nice_val = i32::from(limits.nice).clamp(-20, 19);
    let _ = setpriority_process(None, nice_val);

    if limits.max_rss_bytes > 0 {
        let lim = Rlimit {
            current: Some(limits.max_rss_bytes),
            maximum: Some(limits.max_rss_bytes),
        };
        let _ = setrlimit(Resource::As, lim);
        let _ = setrlimit(Resource::Data, lim);
        let _ = setrlimit(Resource::Rss, lim);
    }

    if limits.max_open_files > 0 {
        let n = u64::from(limits.max_open_files);
        let lim = Rlimit {
            current: Some(n),
            maximum: Some(n),
        };
        let _ = setrlimit(Resource::Nofile, lim);
    }

    // Scan mode: refuse any file write (RLIMIT_FSIZE=0).
    if matches!(mode, ProbeMode::Scan | ProbeMode::Selftest) {
        let lim = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        let _ = setrlimit(Resource::Fsize, lim);
    }

    // Prefer OOM killer take us first if the host is under memory pressure.
    let _ = std::fs::write("/proc/self/oom_score_adj", "500");

    let _ = limits.io_idle;
    let _ = limits.max_cpu_pct;
    let _ = limits.max_transfer_bps;
}
