//! PID liveness probe abstraction (scheduler vs listing).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidLiveness {
    Alive,
    AliveNotOurs, // EPERM
    Absent,       // ESRCH
    Unknown,
}

/// Dual-view PID existence for decloak differentials.
pub trait PidProbeView: Send + Sync {
    fn pid_exists(&self, pid: i32) -> PidLiveness;
    fn hidden_from_listing(&self, pid: i32) -> bool {
        let _ = pid;
        false
    }
    fn starttime(&self, pid: i32) -> Option<u64> {
        let _ = pid;
        None
    }
    fn pid_max(&self) -> i32 {
        32768
    }
}
