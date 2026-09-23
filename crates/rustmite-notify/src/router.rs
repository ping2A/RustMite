use std::sync::Arc;

use rustmite_proto::Severity;

use crate::sinks::{NotifyError, NotifySink};
use crate::AlertEvent;

/// Routes alerts to sinks by minimum severity threshold.
pub struct SeverityRouter {
    routes: Vec<(Severity, Arc<dyn NotifySink>)>,
}

impl SeverityRouter {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn route(mut self, min_severity: Severity, sink: Arc<dyn NotifySink>) -> Self {
        self.routes.push((min_severity, sink));
        self
    }

    pub fn add(&mut self, min_severity: Severity, sink: Arc<dyn NotifySink>) {
        self.routes.push((min_severity, sink));
    }

    pub fn dispatch(&self, event: &AlertEvent) -> Result<usize, NotifyError> {
        let mut n = 0;
        for (min, sink) in &self.routes {
            if severity_rank(event.severity) >= severity_rank(*min) {
                sink.notify(event)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

impl Default for SeverityRouter {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sinks::SyslogSink;
    use std::sync::{Arc, Mutex};

    struct CountingSink {
        hits: Arc<Mutex<usize>>,
    }

    impl NotifySink for CountingSink {
        fn notify(&self, _event: &AlertEvent) -> Result<(), NotifyError> {
            *self.hits.lock().unwrap() += 1;
            Ok(())
        }
        fn name(&self) -> &str {
            "count"
        }
    }

    #[test]
    fn routes_by_severity() {
        let hits = Arc::new(Mutex::new(0usize));
        let router = SeverityRouter::new().route(
            Severity::High,
            Arc::new(CountingSink {
                hits: hits.clone(),
            }),
        );
        let _ = SyslogSink::new(Vec::new());
        router
            .dispatch(&AlertEvent {
                severity: Severity::Low,
                title: "l".into(),
                body: serde_json::json!({}),
                finding: None,
            })
            .unwrap();
        assert_eq!(*hits.lock().unwrap(), 0);
        router
            .dispatch(&AlertEvent {
                severity: Severity::Critical,
                title: "c".into(),
                body: serde_json::json!({}),
                finding: None,
            })
            .unwrap();
        assert_eq!(*hits.lock().unwrap(), 1);
    }
}
