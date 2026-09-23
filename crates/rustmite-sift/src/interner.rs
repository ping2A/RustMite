//! Thread-safe string interning for hot log fields (`Arc<str>` dedupes heap storage across rows).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::types::RawLogEntry;

/// Global-ish intern table behind a mutex; cheap to [`Clone`] (shares the map).
#[derive(Clone, Default)]
pub struct SharedInterner {
    inner: Arc<Mutex<HashMap<String, Arc<str>>>>,
}

impl SharedInterner {
    /// Returns a shared `Arc<str>` for `s`. One heap copy per distinct string; further rows reuse it.
    pub fn intern(&self, s: &str) -> Arc<str> {
        let mut g = self.inner.lock();
        if let Some(arc) = g.get(s) {
            return arc.clone();
        }
        let a = Arc::<str>::from(s);
        g.insert(s.to_string(), a.clone());
        a
    }
}

/// Insert/update PID → name for one raw row (uses interned keys and value).
pub fn merge_pid_map_entry(
    interner: &SharedInterner,
    pid_to_name: &mut HashMap<(Arc<str>, u32), Arc<str>>,
    entry: &RawLogEntry,
) {
    pid_to_name.insert(
        (interner.intern(&entry.machine_id), entry.pid),
        interner.intern(&entry.name),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RawLogEntry;
    use std::collections::HashMap;

    #[test]
    fn intern_deduplicates_same_string() {
        let i = SharedInterner::default();
        let a = i.intern("nginx");
        let b = i.intern("nginx");
        assert!(std::sync::Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn merge_pid_map_entry_updates_entry() {
        let interner = SharedInterner::default();
        let mut map: HashMap<(std::sync::Arc<str>, u32), std::sync::Arc<str>> = HashMap::new();
        let row = RawLogEntry {
            machine_id: "m1".into(),
            pid: 42,
            ppid: 1,
            name: "bash".into(),
            uid: 0,
            path: "/bin/bash".into(),
            args: "-c ls".into(),
            timestamp: None,
        };
        merge_pid_map_entry(&interner, &mut map, &row);
        let key = (interner.intern("m1"), 42u32);
        assert_eq!(map.get(&key).map(|s| s.as_ref()), Some("bash"));
    }
}
