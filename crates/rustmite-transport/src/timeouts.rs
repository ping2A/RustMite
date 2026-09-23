//! Fleet / per-host SSH and scan deadlines (docs/04 §8).

use std::time::Duration;

/// Per-connection SSH / command deadlines.
#[derive(Clone, Debug)]
pub struct SshTimeouts {
    pub connect_delay: Duration,
    pub connect: Duration,
    pub auth: Duration,
    pub command: Duration,
    pub inactivity: Duration,
    pub delivery: Duration,
    pub fingerprint: Duration,
}

impl Default for SshTimeouts {
    fn default() -> Self {
        Self {
            connect_delay: Duration::ZERO,
            connect: Duration::from_secs(10),
            auth: Duration::from_secs(20),
            command: Duration::from_secs(60),
            inactivity: Duration::from_secs(90),
            delivery: Duration::from_secs(30),
            fingerprint: Duration::from_secs(10),
        }
    }
}

impl SshTimeouts {
    pub fn with_jitter(self, pct: u8) -> Self {
        if pct == 0 {
            return self;
        }
        let j = |d: Duration| -> Duration {
            let ms = d.as_millis() as i64;
            if ms <= 0 {
                return d;
            }
            let span = (ms * pct as i64) / 100;
            let delta = (ms.wrapping_mul(2654435761) % (2 * span + 1)) - span;
            Duration::from_millis((ms + delta).max(1) as u64)
        };
        Self {
            connect_delay: self.connect_delay,
            connect: j(self.connect),
            auth: j(self.auth),
            command: j(self.command),
            inactivity: j(self.inactivity),
            delivery: j(self.delivery),
            fingerprint: j(self.fingerprint),
        }
    }

    /// Merge optional per-host overrides onto fleet defaults.
    pub fn overlay(
        mut self,
        connect_delay_ms: Option<u64>,
        connect_timeout_secs: Option<u64>,
        auth_timeout_secs: Option<u64>,
        cmd_timeout_secs: Option<u64>,
        inactivity_timeout_secs: Option<u64>,
        delivery_timeout_secs: Option<u64>,
    ) -> Self {
        if let Some(ms) = connect_delay_ms {
            self.connect_delay = Duration::from_millis(ms);
        }
        if let Some(s) = connect_timeout_secs {
            self.connect = Duration::from_secs(s.max(1));
        }
        if let Some(s) = auth_timeout_secs {
            self.auth = Duration::from_secs(s.max(1));
        }
        if let Some(s) = cmd_timeout_secs {
            self.command = Duration::from_secs(s.max(1));
        }
        if let Some(s) = inactivity_timeout_secs {
            self.inactivity = Duration::from_secs(s.max(1));
        }
        if let Some(s) = delivery_timeout_secs {
            self.delivery = Duration::from_secs(s.max(1));
        }
        self
    }
}
