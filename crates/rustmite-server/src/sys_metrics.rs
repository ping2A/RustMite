//! Control-plane **process** resource metrics (this rustmite-server instance).

use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Clone, Debug, Serialize)]
pub struct DiskMetric {
    pub mount: String,
    pub name: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_pct: f32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemMetrics {
    pub ts: String,
    pub hostname: String,
    /// Always `process` — gauges reflect this control-plane binary, not the host.
    pub scope: &'static str,
    pub pid: u32,
    pub process_name: String,
    pub cpu_pct: f32,
    pub cpu_cores: usize,
    pub load_avg_1: f64,
    /// Host total RAM (denominator for process RSS %).
    pub mem_total_bytes: u64,
    /// This process RSS.
    pub mem_used_bytes: u64,
    pub mem_pct: f32,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_pct: f32,
    pub disk_read_bytes: u64,
    pub disk_written_bytes: u64,
    pub disk_io_bps: u64,
    /// UI bar: process disk IO intensity (0–100, ~10 MiB/s = 100).
    pub disk_pct: f32,
    pub disk_total_bytes: u64,
    pub disk_available_bytes: u64,
    pub disks: Vec<DiskMetric>,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub uptime_secs: u64,
    pub process_uptime_secs: u64,
}

struct IoSample {
    at: Instant,
    read: u64,
    written: u64,
}

pub struct MetricsHub {
    sys: Mutex<System>,
    pid: Pid,
    last_io: Mutex<Option<IoSample>>,
}

impl MetricsHub {
    pub fn new() -> Self {
        let mut sys = System::new();
        let pid = sysinfo::get_current_pid().unwrap_or(Pid::from_u32(0));
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        Self {
            sys: Mutex::new(sys),
            pid,
            last_io: Mutex::new(None),
        }
    }

    pub fn snapshot(&self) -> SystemMetrics {
        let mut sys = self.sys.lock().expect("metrics sys lock");
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );

        let cpu_cores = sys.cpus().len().max(1);
        let mem_total = sys.total_memory();
        let load = System::load_average();

        let (cpu_pct, mem_used, name, disk_read, disk_written, start_secs) =
            if let Some(proc_) = sys.process(self.pid) {
                let du = proc_.disk_usage();
                (
                    proc_.cpu_usage(),
                    proc_.memory(),
                    proc_.name().to_string_lossy().into_owned(),
                    du.total_read_bytes,
                    du.total_written_bytes,
                    proc_.run_time(),
                )
            } else {
                (0.0, 0, "rustmite-server".into(), 0, 0, 0)
            };

        let mem_pct = pct(mem_used, mem_total);
        let swap_total = sys.total_swap();
        let swap_used = sys.used_swap();
        drop(sys);

        let disk_io_bps = {
            let mut last = self.last_io.lock().expect("io sample lock");
            let now = Instant::now();
            let bps = if let Some(prev) = last.as_ref() {
                let dt = now.duration_since(prev.at).as_secs_f64().max(0.001);
                let delta = (disk_read.saturating_sub(prev.read)
                    + disk_written.saturating_sub(prev.written)) as f64;
                (delta / dt) as u64
            } else {
                0
            };
            *last = Some(IoSample {
                at: now,
                read: disk_read,
                written: disk_written,
            });
            bps
        };

        let disk_pct = ((disk_io_bps as f64 / (10.0 * 1024.0 * 1024.0)) * 100.0)
            .clamp(0.0, 100.0) as f32;
        let io_total = disk_read.saturating_add(disk_written);

        SystemMetrics {
            ts: utc_now_rfc3339(),
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            scope: "process",
            pid: self.pid.as_u32(),
            process_name: name,
            cpu_pct,
            cpu_cores,
            load_avg_1: load.one,
            mem_total_bytes: mem_total,
            mem_used_bytes: mem_used,
            mem_pct,
            swap_total_bytes: swap_total,
            swap_used_bytes: swap_used,
            swap_pct: pct(swap_used, swap_total),
            disk_read_bytes: disk_read,
            disk_written_bytes: disk_written,
            disk_io_bps,
            disk_pct,
            disk_total_bytes: io_total.max(1),
            disk_available_bytes: 0,
            disks: vec![DiskMetric {
                mount: format!("pid:{}", self.pid.as_u32()),
                name: "process-io".into(),
                total_bytes: io_total,
                available_bytes: 0,
                used_pct: disk_pct,
            }],
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            uptime_secs: System::uptime(),
            process_uptime_secs: start_secs,
        }
    }
}

impl Default for MetricsHub {
    fn default() -> Self {
        Self::new()
    }
}

fn pct(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        ((used as f64 / total as f64) * 100.0) as f32
    }
}

/// Shared UTC timestamp helper (no chrono dependency).
pub fn utc_now_rfc3339() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86400;
    let tod = secs % 86400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Days since Unix epoch → (year, month, day). Public for mtime formatting.
pub fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}
