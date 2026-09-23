//! Generator for JSONL process-event logs (timestamp, event_type, user, command, pid, ppid).
//! Used for testing and regression checks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// One process event as emitted in JSONL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: String,
    pub event_type: String,
    pub user: String,
    pub command: String,
    pub pid: u32,
    pub ppid: u32,
}

impl ProcessEvent {
    pub fn new(command: impl Into<String>, pid: u32, ppid: u32) -> Self {
        Self {
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
            event_type: "process".to_string(),
            user: "0".to_string(),
            command: command.into(),
            pid,
            ppid,
        }
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts.format("%Y-%m-%dT%H:%M:%S").to_string();
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }
}

/// Generates JSONL process logs for training and testing.
pub struct LogGenerator {
    /// Commands to emit repeatedly (normal baseline).
    normal_commands: Vec<String>,
    /// Optional extra anomalous commands to append (for regression tests).
    anomalous_commands: Vec<String>,
    /// Base PID counter.
    next_pid: u32,
}

impl LogGenerator {
    pub fn new() -> Self {
        Self {
            normal_commands: Vec::new(),
            anomalous_commands: Vec::new(),
            next_pid: 1,
        }
    }

    /// Add a normal (baseline) command. Can be added multiple times to increase frequency.
    pub fn add_normal(mut self, command: impl Into<String>) -> Self {
        self.normal_commands.push(command.into());
        self
    }

    /// Add an anomalous command (for testing detection).
    pub fn add_anomalous(mut self, command: impl Into<String>) -> Self {
        self.anomalous_commands.push(command.into());
        self
    }

    /// Set seed PID (default 1).
    pub fn with_start_pid(mut self, pid: u32) -> Self {
        self.next_pid = pid;
        self
    }

    /// Generate a default set of normal kernel-like process commands (good for regression).
    pub fn with_default_normal(self) -> Self {
        self.add_normal("/sbin/init auto A /dev/sda")
            .add_normal("[kthreadd]")
            .add_normal("[rcu_gp]")
            .add_normal("[kworker/0:0H]")
            .add_normal("[mm_percpu_wq]")
            .add_normal("[ksoftirqd/0]")
            .add_normal("[rcu_sched]")
            .add_normal("[rcu_bh]")
            .add_normal("[migration/0]")
            .add_normal("[watchdog/0]")
            .add_normal("[cpuhp/0]")
            .add_normal("[cpuhp/1]")
            .add_normal("systemd")
            .add_normal("sshd")
            .add_normal("bash")
            .add_normal("nginx")
            .add_normal("cron")
    }

    /// Emit `n_normal` lines of normal commands (cycled), then `anomalous_commands` once each.
    pub fn emit(&mut self, mut w: impl Write, n_normal: usize) -> io::Result<()> {
        let mut pid = self.next_pid;
        let normal = &self.normal_commands;
        if normal.is_empty() {
            return Ok(());
        }
        for i in 0..n_normal {
            let cmd = &normal[i % normal.len()];
            let ppid = if pid == 1 { 0 } else { pid.saturating_sub(1) };
            let evt = ProcessEvent::new(cmd, pid, ppid);
            writeln!(w, "{}", serde_json::to_string(&evt).unwrap())?;
            pid += 1;
        }
        for cmd in &self.anomalous_commands {
            let ppid = if pid == 1 { 0 } else { pid.saturating_sub(1) };
            let evt = ProcessEvent::new(cmd, pid, ppid);
            writeln!(w, "{}", serde_json::to_string(&evt).unwrap())?;
            pid += 1;
        }
        self.next_pid = pid;
        Ok(())
    }

    /// Build events in memory (for tests).
    pub fn events(&mut self, n_normal: usize) -> Vec<ProcessEvent> {
        let mut buf = Vec::new();
        self.emit(&mut buf, n_normal).unwrap();
        let mut out = Vec::new();
        for line in std::str::from_utf8(&buf).unwrap().lines() {
            if line.is_empty() {
                continue;
            }
            let evt: ProcessEvent = serde_json::from_str(line).unwrap();
            out.push(evt);
        }
        out
    }
}

impl Default for LogGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_event_serializes_to_jsonl() {
        let evt = ProcessEvent::new("/sbin/init", 1, 0);
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"command\":\"/sbin/init\""));
        assert!(json.contains("\"pid\":1"));
        assert!(json.contains("\"ppid\":0"));
        assert!(json.contains("\"event_type\":\"process\""));
    }

    #[test]
    fn test_log_generator_emit() {
        let mut gen = LogGenerator::new()
            .add_normal("cmd_a")
            .add_normal("cmd_b")
            .add_anomalous("weird_cmd");
        let mut buf = Vec::new();
        gen.emit(&mut buf, 4).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 5); // 4 normal + 1 anomalous
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        }
    }

    #[test]
    fn test_log_generator_default_normal() {
        let mut gen = LogGenerator::new().with_default_normal();
        let events = gen.events(20);
        assert_eq!(events.len(), 20);
        assert!(events[0].command.starts_with("/sbin/init") || events[0].command.starts_with('['));
    }
}
