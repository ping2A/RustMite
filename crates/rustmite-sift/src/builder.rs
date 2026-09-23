//! ProcessBuilder and process profile building from raw logs.

use std::collections::HashMap;
use std::sync::Arc;
use log;
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use regex::Regex;

use crate::config::DetectionConfig;
use crate::interner::{merge_pid_map_entry, SharedInterner};
use crate::json_parse::{parse_json_log, parse_json_logs};
use crate::types::{MachineProfile, ProcessEntry, ProcessSignature, RawLogEntry};
use crate::utils::{
    calculate_shannon_entropy, compile_regex_list, compile_wildcard_list,
    is_path_suspicious_compiled, is_path_whitelisted_compiled, looks_like_kernel_thread_name,
    parse_command_line,
};

/// Builder for collecting processes without PIDs, then auto-resolving relationships
pub struct ProcessBuilder {
    entries: Vec<ProcessEntry>,
}

impl ProcessBuilder {
    pub fn new() -> Self {
        log::debug!("Initializing ProcessBuilder");
        Self {
            entries: Vec::new(),
        }
    }
    
    /// Add a process entry without needing PIDs
    pub fn add(&mut self, entry: ProcessEntry) -> &mut Self {
        log::debug!("Adding ProcessEntry: machine={}, name={}, ppid={:?}", entry.machine_id, entry.name, entry.ppid);
        self.entries.push(entry);
        self
    }
    
    /// Add a simple process with just name and parent
    pub fn add_process(&mut self, machine_id: &str, name: &str, parent: &str) -> &mut Self {
        log::debug!("Adding simple process: machine={}, name={}, parent={}", machine_id, name, parent);
        self.entries.push(ProcessEntry {
            machine_id: machine_id.to_string(),
            name: name.to_string(),
            parent_name: Some(parent.to_string()),
            ppid: None,  // ⭐ Initialize ppid as None
            uid: 1000,
            path: format!("/usr/bin/{}", name),
            args: String::new(),
            timestamp: None,
        });
        self
    }
    
    /// Add a process from a full command line string
    /// 
    /// Automatically extracts name, path, and args from the command.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // Parse full command lines
    /// builder.add_command("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"));
    /// builder.add_command("server1", "/tmp/suspicious --obfuscated XkzL1", Some("bash"));
    /// 
    /// // Works with just executable name
    /// builder.add_command("server2", "postgres", Some("systemd"));
    /// ```
    pub fn add_command(&mut self, machine_id: &str, command: &str, parent: Option<&str>) -> &mut Self {
        let entry = ProcessEntry::from_command_line(machine_id.to_string(), command, parent);
        self.entries.push(entry);
        self
    }
    
    /// Add a process with UID from command line
    pub fn add_command_with_uid(&mut self, machine_id: &str, command: &str, parent: Option<&str>, uid: u32) -> &mut Self {
        let mut entry = ProcessEntry::from_command_line(machine_id.to_string(), command, parent);
        entry.uid = uid;
        self.entries.push(entry);
        self
    }
    
    /// Add a process from a JSON string
    /// 
    /// Automatically extracts all available fields from JSON.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // Docker-style JSON
    /// builder.add_json(r#"{"host": "server1", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33}"#);
    /// 
    /// // Kubernetes-style JSON  
    /// builder.add_json(r#"{"node": "worker-1", "cmd": "python3 app.py", "userid": 1000}"#);
    /// ```
    pub fn add_json(&mut self, json: &str) -> &mut Self {
        match parse_json_log(json) {
            Ok(raw_entry) => {
                log::debug!("Processing JSON entry for machine: {}", raw_entry.machine_id);
                if raw_entry.ppid > 0 {
                    log::debug!("  PPID found in JSON: {}", raw_entry.ppid);
                }
                
                let (name, path, args) = if raw_entry.name.is_empty() {
                    // Parse from command if name is empty
                    let cmd = format!("{} {}", raw_entry.path, raw_entry.args).trim().to_string();
                    parse_command_line(&cmd)
                } else {
                    (raw_entry.name, raw_entry.path, raw_entry.args)
                };
                
                let entry = ProcessEntry {
                    machine_id: raw_entry.machine_id,
                    name,
                    parent_name: None, // Will be resolved from PPID later
                    ppid: if raw_entry.ppid > 0 { Some(raw_entry.ppid) } else { None },  // ⭐ PRESERVE PPID!
                    uid: raw_entry.uid,
                    path,
                    args,
                    timestamp: raw_entry.timestamp,
                };
                
                log::debug!("Created ProcessEntry: name={}, ppid={:?}", entry.name, entry.ppid);
                
                self.entries.push(entry);
            }
            Err(e) => {
                log::warn!("Failed to parse JSON: {}", e);
            }
        }
        self
    }
    
    /// Add multiple processes from a JSON string (array or newline-delimited)
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // JSON array
    /// builder.add_json_batch(r#"[
    ///     {"host": "server1", "command": "/usr/bin/nginx"},
    ///     {"host": "server2", "command": "python3 app.py"}
    /// ]"#);
    /// 
    /// // Newline-delimited JSON
    /// builder.add_json_batch(r#"
    /// {"host": "server1", "command": "/usr/bin/nginx"}
    /// {"host": "server2", "command": "python3 app.py"}
    /// "#);
    /// ```
    pub fn add_json_batch(&mut self, json: &str) -> &mut Self {
        match parse_json_logs(json) {
            Ok(entries) => {
                for raw_entry in entries {
                    let (name, path, args) = if raw_entry.name.is_empty() {
                        let cmd = format!("{} {}", raw_entry.path, raw_entry.args).trim().to_string();
                        parse_command_line(&cmd)
                    } else {
                        (raw_entry.name, raw_entry.path, raw_entry.args)
                    };
                    
                    let entry = ProcessEntry {
                        machine_id: raw_entry.machine_id,
                        name,
                        parent_name: None,
                        ppid: if raw_entry.ppid > 0 { Some(raw_entry.ppid) } else { None },  // ⭐ PRESERVE PPID!
                        uid: raw_entry.uid,
                        path,
                        args,
                        timestamp: raw_entry.timestamp,
                    };
                    
                    self.entries.push(entry);
                }
            }
            Err(e) => {
                log::warn!("Failed to parse JSON batch: {}", e);
            }
        }
        self
    }
    
    /// Get the number of collected process entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    
    /// Convert collected entries into RawLogEntry with auto-generated PIDs
    pub fn build(self) -> Vec<RawLogEntry> {
        let mut raw_entries = Vec::new();
        
        // Group by machine to assign PIDs per machine
        let mut machine_groups: HashMap<String, Vec<ProcessEntry>> = HashMap::new();
        for entry in self.entries {
            machine_groups.entry(entry.machine_id.clone())
                .or_insert_with(Vec::new)
                .push(entry);
        }
        
        for (machine_id, entries) in machine_groups {
            // Build name -> PID mapping for this machine
            let mut name_to_pid: HashMap<String, u32> = HashMap::new();
            let mut next_pid = 1u32;
            
            // First pass: assign PIDs to all unique process names
            for entry in &entries {
                if !name_to_pid.contains_key(&entry.name) {
                    name_to_pid.insert(entry.name.clone(), next_pid);
                    next_pid += 1;
                }
            }
            
            // Second pass: create RawLogEntry with resolved PIDs and PPIDs
            for entry in entries {
                let pid = *name_to_pid.get(&entry.name).unwrap();
                
                // ⭐ Use PPID from ProcessEntry if provided, otherwise resolve from parent name
                let ppid = if let Some(provided_ppid) = entry.ppid {
                    // PPID was explicitly provided - preserve it!
                    provided_ppid
                } else if let Some(parent_name) = &entry.parent_name {
                    // Resolve PPID from parent name
                    *name_to_pid.get(parent_name).unwrap_or(&0)
                } else {
                    // If no parent specified, assume systemd (PID 1) or init
                    if entry.name == "systemd" || entry.name == "init" {
                        0
                    } else {
                        1 // Default to systemd as parent
                    }
                };
                
                raw_entries.push(RawLogEntry {
                    machine_id: machine_id.clone(),
                    pid,
                    ppid,
                    name: entry.name,
                    uid: entry.uid,
                    path: entry.path,
                    args: entry.args,
                    timestamp: entry.timestamp,
                });
            }
        }
        
        log::debug!("ProcessBuilder built: {} total entries", raw_entries.len());
        
        raw_entries
    }
}

impl Default for ProcessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a row should be counted toward profiles given kernel / init / path whitelist settings.
pub(crate) fn process_entry_passes_filters(
    entry: &RawLogEntry,
    config: &DetectionConfig,
    whitelist_res: &[Regex],
) -> bool {
    if config.exclude_kernel_threads && looks_like_kernel_thread_name(&entry.name) {
        return false;
    }
    if config.exclude_init_children && entry.ppid == 1 {
        return false;
    }
    if !whitelist_res.is_empty() && is_path_whitelisted_compiled(&entry.path, whitelist_res) {
        return false;
    }
    true
}

/// Append one filtered process log to a machine profile (shared by batch and streaming builders).
pub(crate) fn merge_log_into_profile(
    profile: &mut MachineProfile,
    entry: &RawLogEntry,
    pid_to_name: &HashMap<(Arc<str>, u32), Arc<str>>,
    config: &DetectionConfig,
    interner: &SharedInterner,
    process_counts: Option<&mut HashMap<String, u32>>,
    suspicious_path_res: &[Regex],
) {
    let mid = interner.intern(&entry.machine_id);
    let parent_name = pid_to_name
        .get(&(mid.clone(), entry.ppid))
        .cloned()
        .unwrap_or_else(|| {
            if config.debug_display && entry.ppid != 0 {
                log::warn!(
                    "Unresolved PPID for {}:{} (PPID: {})",
                    entry.machine_id,
                    entry.name,
                    entry.ppid
                );
            }
            interner.intern(&format!("[unknown:{}]", entry.ppid))
        });

    let entropy = calculate_shannon_entropy(&entry.args);
    let is_high_entropy = entropy > config.entropy_threshold;
    let is_suspicious_path = is_path_suspicious_compiled(&entry.path, suspicious_path_res);

    let timestamp = entry
        .timestamp
        .as_ref()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let sig = ProcessSignature {
        name: interner.intern(&entry.name),
        parent_name,
        uid: entry.uid,
        path: interner.intern(&entry.path),
        is_high_entropy,
        is_suspicious_path,
    };

    if let Some(pc) = process_counts {
        let process_key = format!(
            "{}:{}:{}:{}",
            sig.name, sig.path, sig.parent_name, sig.uid
        );
        let is_new_process = !pc.contains_key(&process_key);
        pc.entry(process_key).and_modify(|c| *c += 1).or_insert(1);

        if config.debug_display && is_new_process {
            let risk_flags: Vec<&str> = [
                if is_high_entropy {
                    Some("HIGH_ENTROPY")
                } else {
                    None
                },
                if is_suspicious_path {
                    Some("SUSPICIOUS_PATH")
                } else {
                    None
                },
                if entry.uid == 0
                    && !config
                        .common_root_processes
                        .iter()
                        .any(|p| entry.name.contains(p))
                {
                    Some("UNEXPECTED_ROOT")
                } else {
                    None
                },
            ]
            .into_iter()
            .flatten()
            .collect();
            let risk_str = if risk_flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", risk_flags.join(", "))
            };
            log::debug!(
                "New process in {}: {} (path: {}, parent: {}, uid: {}){}",
                profile.id,
                entry.name,
                entry.path,
                sig.parent_name.as_ref(),
                entry.uid,
                risk_str
            );
        }
    }

    profile.add_process(sig, timestamp);
}

/// Resolve parent process names from PIDs (interned `Arc<str>` keys and values).
pub fn resolve_parent_names(entries: &[RawLogEntry]) -> HashMap<(Arc<str>, u32), Arc<str>> {
    let interner = SharedInterner::default();
    let mut pid_to_name = HashMap::new();
    for entry in entries {
        merge_pid_map_entry(&interner, &mut pid_to_name, entry);
    }
    pid_to_name
}

/// Build machine profiles from raw log entries with automatic parent resolution
pub fn build_profiles(entries: Vec<RawLogEntry>, config: &DetectionConfig) -> Vec<MachineProfile> {
    log::info!("Building profiles from {} raw entries", entries.len());
    if config.debug_display {
        log::debug!("PPID resolution: {} entries, sample PPIDs: {:?}", entries.len(),
            entries.iter().take(5).map(|e| (e.machine_id.as_str(), e.name.as_str(), e.ppid)).collect::<Vec<_>>());
    }
    
    let interner = SharedInterner::default();
    let mut pid_to_name: HashMap<(Arc<str>, u32), Arc<str>> = HashMap::new();
    for e in &entries {
        merge_pid_map_entry(&interner, &mut pid_to_name, e);
    }

    if config.debug_display {
        log::debug!("Resolved {} PID-to-name mappings", pid_to_name.len());
    }
    
    // Filter out kernel threads if configured
    let entries: Vec<RawLogEntry> = if config.exclude_kernel_threads {
        let before_count = entries.len();
        let filtered: Vec<_> = entries.into_iter()
            .filter(|e| !looks_like_kernel_thread_name(&e.name))
            .collect();
        let after_count = filtered.len();
        
        if config.debug_display {
            log::debug!("Kernel thread filtering: before={}, after={}, filtered={}", before_count, after_count, before_count - after_count);
        }
        
        filtered
    } else {
        entries
    };
    
    // Filter out init children if configured
    let entries: Vec<RawLogEntry> = if config.exclude_init_children {
        let before_count = entries.len();
        let filtered: Vec<_> = entries.into_iter()
            .filter(|e| e.ppid != 1)
            .collect();
        let after_count = filtered.len();
        
        if config.debug_display {
            log::debug!("Init children filtering: before={}, after={}, filtered={}", before_count, after_count, before_count - after_count);
        }
        
        filtered
    } else {
        entries
    };
    
    // Filter out whitelisted paths if configured
    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let entries: Vec<RawLogEntry> = if !whitelist_res.is_empty() {
        let before_count = entries.len();
        let filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| !is_path_whitelisted_compiled(&e.path, &whitelist_res))
            .collect();
        let after_count = filtered.len();

        if config.debug_display {
            log::debug!(
                "Whitelisted path filtering: before={}, after={}, filtered={}",
                before_count,
                after_count,
                before_count - after_count
            );
        }

        filtered
    } else {
        entries
    };
    
    // Group by machine
    let mut machine_entries: HashMap<String, Vec<RawLogEntry>> = HashMap::new();
    for entry in entries {
        machine_entries.entry(entry.machine_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
    
    if config.debug_display {
        log::debug!("Grouped into {} machines", machine_entries.len());
    }

    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);

    let profiles: Vec<MachineProfile> = machine_entries
        .par_iter()
        .map(|(machine_id, logs)| {
            let mut profile = MachineProfile::new(machine_id);
            let mut process_counts: HashMap<String, u32> = HashMap::new();
            // Per-machine interner avoids a global mutex on every field while still matching
            // `pid_to_name` lookups (Arc<str> equality/hash use string content, not pointer).
            let interner_par = SharedInterner::default();
            for entry in logs {
                let pc = if config.debug_display {
                    Some(&mut process_counts)
                } else {
                    None
                };
                merge_log_into_profile(
                    &mut profile,
                    entry,
                    &pid_to_name,
                    config,
                    &interner_par,
                    pc,
                    &suspicious_path_res,
                );
            }
            profile
        })
        .collect();
    
    log::info!("Built {} machine profiles", profiles.len());
    profiles
}

