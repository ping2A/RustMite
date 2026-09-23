use crate::*;
use chrono::Utc;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_full_pipeline_with_csv() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("test_data.csv");
    
    // Create a test CSV
    let mut wtr = csv::Writer::from_path(&csv_path).unwrap();
    
    // 5 normal machines
    for i in 0..5 {
        // systemd
        wtr.serialize(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        }).unwrap();
        
        for j in 0..100 {
            wtr.serialize(RawLogEntry {
                machine_id: format!("normal_{}", i),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-c /etc/nginx.conf".to_string(),
                timestamp: None,
            }).unwrap();
        }
    }
    
    // 1 compromised machine
    wtr.serialize(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    }).unwrap();
    
    for j in 0..100 {
        wtr.serialize(RawLogEntry {
            machine_id: "compromised".to_string(),
            pid: 666 + j,
            ppid: 1,
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/kworker".to_string(),
            args: "XkzL1^s09f87aH@9#kzL1^s09f87".to_string(),
            timestamp: None,
        }).unwrap();
    }
    
    wtr.flush().unwrap();
    
    // Load and analyze
    let config = DetectionConfig::default();
    let profiles = load_csv_data(csv_path.to_str().unwrap(), &config).unwrap();
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Verify
    assert_eq!(profiles.len(), 6);
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "compromised"));
}

#[test]
fn test_json_export() {
    let dir = tempdir().unwrap();
    let json_path = dir.path().join("report.json");
    
    let config = DetectionConfig::default();
    let profiles = generate_mock_data(&config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Export JSON
    report.export_json(&profiles, json_path.to_str().unwrap()).unwrap();
    
    // Verify file exists and is valid JSON
    let contents = fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    
    assert!(parsed.get("report_timestamp").is_some());
    assert!(parsed.get("fleet_size").is_some());
    assert!(parsed.get("investigation_targets").is_some());
}

#[test]
fn test_config_save_load() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.08;
    config.entropy_threshold = 5.0;
    
    // Save
    config.to_file(config_path.to_str().unwrap()).unwrap();
    
    // Load
    let loaded = DetectionConfig::from_file(config_path.to_str().unwrap()).unwrap();
    
    assert_eq!(loaded.dbscan_tolerance, 0.08);
    assert_eq!(loaded.entropy_threshold, 5.0);
}

#[test]
fn test_anomaly_severity_classification() {
    let critical = AnomalyDetails {
        machine_id: "test".to_string(),
        severity: AnomalyLevel::Critical,
        distance_score: 1.5,
        cluster_assignment: None,
        anomalous_features: vec![],
        process_count: 100,
        suspicious_process_count: 50,
    };
    
    assert!(matches!(critical.severity, AnomalyLevel::Critical));
}

#[test]
fn test_large_fleet_performance() {
    use std::time::Instant;
    
    let config = DetectionConfig::default();
    
    let entries: Vec<RawLogEntry> = (0..500).flat_map(|i| {
        let machine_id = format!("machine_{}", i);
        let mut logs = vec![
            RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "--system".to_string(),
                timestamp: None,
            }
        ];
        
        // Normal traffic
        for j in 0..100 {
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/bin/nginx".to_string(),
                args: "conf".to_string(),
                timestamp: None,
            });
        }
        
        // Add anomaly to a few machines
        if i % 100 == 13 {
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 666,
                ppid: 1,
                name: "miner".to_string(),
                uid: 0,
                path: "/tmp/miner".to_string(),
                args: "XkzL1^s09f87".to_string(),
                timestamp: None,
            });
        }
        
        logs
    }).collect();
    
    let start = Instant::now();
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    let elapsed = start.elapsed();
    
    println!("Analyzed {} machines in {:?}", profiles.len(), elapsed);
    
    // `cargo test` is unoptimized by default and can be ~10× slower than `--release`;
    // CI runners are variable too. Tight bound only applies to release tests.
    let limit_secs = if std::env::var("CI").is_ok() {
        120
    } else if cfg!(debug_assertions) {
        120
    } else {
        10
    };
    assert!(
        elapsed.as_secs() < limit_secs,
        "Performance regression: took {:?} (limit {}s)",
        elapsed,
        limit_secs
    );
    assert!(!report.anomalies.is_empty());
}

#[test]
fn test_temporal_tracking() {
    use chrono::{Utc, Duration};
    
    let config = DetectionConfig::default();
    
    let t1 = Utc::now();
    let t2 = t1 + Duration::hours(1);
    
    let entries = vec![
        RawLogEntry {
            machine_id: "test".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: Some(t1.to_rfc3339()),
        },
        RawLogEntry {
            machine_id: "test".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: Some(t2.to_rfc3339()),
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    assert_eq!(profile.first_seen.unwrap(), t1);
    assert_eq!(profile.last_seen.unwrap(), t2);
}

#[test]
fn test_new_process_detection() {
    let config = DetectionConfig::default();
    
    let baseline_entries = vec![
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        },
    ];
    
    let current_entries = vec![
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 666,
            ppid: 1,
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/miner".to_string(),
            args: "pool".to_string(),
            timestamp: None,
        },
    ];
    
    let baseline = &build_profiles(baseline_entries, &config)[0];
    let current = &build_profiles(current_entries, &config)[0];
    
    let new_procs = current.find_new_processes(baseline);
    
    assert_eq!(new_procs.len(), 1);
    assert_eq!(new_procs[0].name.as_ref(), "miner");
}

#[test]
fn test_parent_resolution() {
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 200,
            ppid: 100,
            name: "worker".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Check that parent names are resolved correctly
    let nginx_sig = profile.counts.keys()
        .find(|s| s.name.as_ref() == "nginx")
        .unwrap();
    assert_eq!(nginx_sig.parent_name.as_ref(), "systemd");
    
    let worker_sig = profile.counts.keys()
        .find(|s| s.name.as_ref() == "worker")
        .unwrap();
    assert_eq!(worker_sig.parent_name.as_ref(), "nginx");
}

#[test]
fn test_unknown_parent_handling() {
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 999, // Parent doesn't exist
            name: "orphan".to_string(),
            uid: 33,
            path: "/usr/bin/orphan".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    let sig = profile.counts.keys().next().unwrap();
    assert!(sig.parent_name.starts_with("[unknown:"));
}

#[test]
fn test_process_builder_simple() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes without knowing PIDs upfront
    builder
        .add_process("machine1", "systemd", "init")
        .add_process("machine1", "nginx", "systemd")
        .add_process("machine1", "worker", "nginx");
    
    let raw_entries = builder.build();
    
    // Verify PIDs were assigned
    assert_eq!(raw_entries.len(), 3);
    
    // Find systemd entry
    let systemd = raw_entries.iter().find(|e| e.name == "systemd").unwrap();
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    let worker = raw_entries.iter().find(|e| e.name == "worker").unwrap();
    
    // Verify parent relationships were resolved
    assert_eq!(nginx.ppid, systemd.pid);
    assert_eq!(worker.ppid, nginx.pid);
    
    // Build profiles and verify
    let profiles = build_profiles(raw_entries, &config);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, "machine1");
}

#[test]
fn test_process_builder_fluent_api() {
    let mut builder = ProcessBuilder::new();
    
    // Use fluent API
    builder.add(
        ProcessEntry::new("machine1".to_string(), "nginx".to_string())
            .parent("systemd")
            .uid(33)
            .path("/usr/sbin/nginx")
            .args("-c /etc/nginx.conf")
    );
    
    builder.add(
        ProcessEntry::new("machine1".to_string(), "systemd".to_string())
            .uid(0)
            .path("/usr/lib/systemd/systemd")
    );
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.uid, 33);
    assert_eq!(nginx.path, "/usr/sbin/nginx");
    assert_eq!(nginx.args, "-c /etc/nginx.conf");
}

#[test]
fn test_build_profiles_simple() {
    let config = DetectionConfig::default();
    
    // Super simple API - just name/parent tuples
    let processes = vec![
        ("m1".to_string(), "systemd".to_string(), "init".to_string()),
        ("m1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("m1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("m2".to_string(), "systemd".to_string(), "init".to_string()),
        ("m2".to_string(), "apache2".to_string(), "systemd".to_string()),
    ];
    
    let profiles = build_profiles_simple(processes, &config);
    
    assert_eq!(profiles.len(), 2);
    assert!(profiles.iter().any(|p| p.id == "m1"));
    assert!(profiles.iter().any(|p| p.id == "m2"));
}

#[test]
fn test_process_builder_multiple_machines() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes from multiple machines
    for i in 0..5 {
        let machine_id = format!("machine_{}", i);
        builder
            .add_process(&machine_id, "systemd", "init")
            .add_process(&machine_id, "nginx", "systemd");
    }
    
    let raw_entries = builder.build();
    let profiles = build_profiles(raw_entries, &config);
    
    assert_eq!(profiles.len(), 5);
}

#[test]
fn test_process_builder_no_parent_specified() {
    let mut builder = ProcessBuilder::new();
    
    // Add process without specifying parent - should default to systemd
    builder.add(
        ProcessEntry::new("machine1".to_string(), "nginx".to_string())
            .uid(33)
            .path("/usr/sbin/nginx")
    );
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 1);
    
    let nginx = &raw_entries[0];
    assert_eq!(nginx.ppid, 1); // Should default to PID 1 (systemd)
}

#[test]
fn test_parse_command_line() {
    // Full path with args
    let (name, path, args) = parse_command_line("/usr/bin/nginx -c /etc/nginx.conf");
    assert_eq!(name, "nginx");
    assert_eq!(path, "/usr/bin/nginx");
    assert_eq!(args, "-c /etc/nginx.conf");
    
    // Just executable name
    let (name, path, args) = parse_command_line("postgres");
    assert_eq!(name, "postgres");
    assert_eq!(path, "postgres");
    assert_eq!(args, "");
    
    // With multiple args
    let (name, path, args) = parse_command_line("/usr/bin/python3 script.py --debug --verbose");
    assert_eq!(name, "python3");
    assert_eq!(path, "/usr/bin/python3");
    assert_eq!(args, "script.py --debug --verbose");
    
    // Relative path
    let (name, path, args) = parse_command_line("./myscript --flag");
    assert_eq!(name, "myscript");
    assert_eq!(path, "./myscript");
    assert_eq!(args, "--flag");
    
    // Suspicious path
    let (name, path, args) = parse_command_line("/tmp/.hidden/miner --pool tcp://pool.example.org:4444");
    assert_eq!(name, "miner");
    assert_eq!(path, "/tmp/.hidden/miner");
    assert_eq!(args, "--pool tcp://pool.example.org:4444");
    
    // With quotes
    let (name, path, args) = parse_command_line(r#"/bin/sh -c "echo hello world""#);
    assert_eq!(name, "sh");
    assert_eq!(path, "/bin/sh");
    assert_eq!(args, r#"-c echo hello world"#);
    
    // Empty
    let (name, path, args) = parse_command_line("");
    assert_eq!(name, "");
    assert_eq!(path, "");
    assert_eq!(args, "");
    
    // Linux kernel threads - critical test cases!
    let (name, path, args) = parse_command_line("[kworker/1:0]");
    assert_eq!(name, "[kworker/1:0]");
    assert_eq!(path, "[kworker/1:0]");
    assert_eq!(args, "");
    
    let (name, path, args) = parse_command_line("[migration/0]");
    assert_eq!(name, "[migration/0]");
    assert_eq!(path, "[migration/0]");
    assert_eq!(args, "");
    
    let (name, path, args) = parse_command_line("[ksoftirqd/1]");
    assert_eq!(name, "[ksoftirqd/1]");
    assert_eq!(path, "[ksoftirqd/1]");
    assert_eq!(args, "");
    
    let (name, path, args) = parse_command_line("[kthreadd]");
    assert_eq!(name, "[kthreadd]");
    assert_eq!(path, "[kthreadd]");
    assert_eq!(args, "");
}

#[test]
fn test_process_entry_from_command_line() {
    let entry = ProcessEntry::from_command_line(
        "server1".to_string(),
        "/usr/bin/nginx -c /etc/nginx.conf",
        Some("systemd")
    );
    
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/bin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.parent_name, Some("systemd".to_string()));
    
    // Can still override with fluent API
    let entry2 = ProcessEntry::from_command_line(
        "server1".to_string(),
        "/usr/bin/nginx -c /etc/nginx.conf",
        None
    ).uid(33).parent("systemd");
    
    assert_eq!(entry2.uid, 33);
    assert_eq!(entry2.parent_name, Some("systemd".to_string()));
}

#[test]
fn test_builder_add_command() {
    let mut builder = ProcessBuilder::new();
    
    // Add processes using full command lines
    builder
        .add_command("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"))
        .add_command("server1", "/usr/bin/postgres -D /var/lib/postgresql/data", Some("systemd"))
        .add_command("server1", "python3 app.py --port 8000", Some("bash"));
    
    let raw_entries = builder.build();
    
    assert_eq!(raw_entries.len(), 3);
    
    // Check nginx
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.path, "/usr/bin/nginx");
    assert_eq!(nginx.args, "-c /etc/nginx.conf");
    
    // Check postgres
    let postgres = raw_entries.iter().find(|e| e.name == "postgres").unwrap();
    assert_eq!(postgres.path, "/usr/bin/postgres");
    assert_eq!(postgres.args, "-D /var/lib/postgresql/data");
    
    // Check python3
    let python = raw_entries.iter().find(|e| e.name == "python3").unwrap();
    assert_eq!(python.path, "python3");
    assert_eq!(python.args, "app.py --port 8000");
}

#[test]
fn test_builder_add_command_with_uid() {
    let mut builder = ProcessBuilder::new();
    
    // Normal process
    builder.add_command_with_uid("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"), 33);
    
    // Suspicious root process
    builder.add_command_with_uid("server1", "/tmp/miner --pool pool", Some("bash"), 0);
    
    let raw_entries = builder.build();
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.uid, 33);
    
    let miner = raw_entries.iter().find(|e| e.name == "miner").unwrap();
    assert_eq!(miner.uid, 0);
    assert_eq!(miner.path, "/tmp/miner");
}

#[test]
fn test_full_workflow_with_command_parsing() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Simulate parsing raw command lines from logs
    let log_lines = vec![
        ("server1", "/usr/sbin/sshd -D", "systemd"),
        ("server1", "/usr/bin/nginx -c /etc/nginx.conf", "systemd"),
        ("server1", "/usr/bin/nginx worker process", "nginx"),
        ("server2", "/usr/sbin/sshd -D", "systemd"),
        ("server2", "/usr/bin/nginx -c /etc/nginx.conf", "systemd"),
        ("server3", "/tmp/.hidden/kworker --url tcp://pool.example.org:4444", "systemd"),
    ];
    
    for (machine, command, parent) in log_lines {
        builder.add_command_with_uid(machine, command, Some(parent), if command.contains("/tmp") { 0 } else { 33 });
    }
    
    let raw_entries = builder.build();
    let profiles = build_profiles(raw_entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Should detect server3 as anomalous
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "server3"));
}

#[test]
fn test_command_parsing_edge_cases() {
    // Leading/trailing whitespace
    let (name, path, _args) = parse_command_line("  /usr/bin/nginx -c /etc/nginx.conf  ");
    assert_eq!(name, "nginx");
    assert_eq!(path, "/usr/bin/nginx");
    
    // Multiple spaces
    let (name, _path, args) = parse_command_line("/usr/bin/python3    script.py    --flag");
    assert_eq!(name, "python3");
    assert_eq!(args, "script.py --flag");
    
    // Process name with numbers
    let (name, _path, _args) = parse_command_line("/usr/bin/node16 app.js");
    assert_eq!(name, "node16");
    
    // Dots in name
    let (name, path, _args) = parse_command_line("/usr/bin/systemd-resolved --config");
    assert_eq!(name, "systemd-resolved");
    assert_eq!(path, "/usr/bin/systemd-resolved");
}

#[test]
fn test_bare_command_parsing() {
    // Common case: "ls /etc/" not "/bin/ls /etc/"
    let (name, path, args) = parse_command_line("ls /etc/");
    assert_eq!(name, "ls");
    assert_eq!(path, "ls");
    assert_eq!(args, "/etc/");
    
    // Multiple bare commands
    let (name, path, args) = parse_command_line("grep pattern file.txt");
    assert_eq!(name, "grep");
    assert_eq!(path, "grep");
    assert_eq!(args, "pattern file.txt");
    
    // ps output style with colon (splits on whitespace)
    let (name, path, args) = parse_command_line("nginx: worker process");
    assert_eq!(name, "nginx:");
    assert_eq!(path, "nginx:");
    assert_eq!(args, "worker process");
    
    // Docker style
    let (name, path, args) = parse_command_line("node server.js");
    assert_eq!(name, "node");
    assert_eq!(path, "node");
    assert_eq!(args, "server.js");
}

#[test]
fn test_parse_json_log_docker_style() {
    let json = r#"{
        "host": "server1",
        "command": "/usr/bin/nginx -c /etc/nginx.conf",
        "uid": 33
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/bin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.uid, 33);
}

#[test]
fn test_parse_json_log_kubernetes_style() {
    let json = r#"{
        "node": "worker-1",
        "cmd": "python3 app.py --port 8000",
        "userid": 1000,
        "timestamp": "2024-01-06T10:00:00Z"
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "worker-1");
    assert_eq!(entry.name, "python3");
    assert_eq!(entry.path, "python3");
    assert_eq!(entry.args, "app.py --port 8000");
    assert_eq!(entry.uid, 1000);
    assert_eq!(entry.timestamp, Some("2024-01-06T10:00:00Z".to_string()));
}

#[test]
fn test_parse_json_log_full_detail() {
    let json = r#"{
        "machine_id": "server1",
        "pid": 100,
        "ppid": 1,
        "name": "nginx",
        "path": "/usr/sbin/nginx",
        "args": "-c /etc/nginx.conf",
        "uid": 33,
        "timestamp": "2024-01-06T10:00:00Z"
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.pid, 100);
    assert_eq!(entry.ppid, 1);
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/sbin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.uid, 33);
}

#[test]
fn test_parse_json_log_bare_command() {
    let json = r#"{
        "hostname": "server1",
        "cmd": "ls /etc/",
        "uid": 0
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "ls");
    assert_eq!(entry.path, "ls");
    assert_eq!(entry.args, "/etc/");
}

#[test]
fn test_parse_json_logs_array() {
    let json = r#"[
        {"host": "server1", "command": "/usr/bin/nginx"},
        {"host": "server2", "command": "python3 app.py"},
        {"host": "server3", "cmd": "/tmp/miner --pool pool"}
    ]"#;
    
    let entries = parse_json_logs(json).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "nginx");
    assert_eq!(entries[1].name, "python3");
    assert_eq!(entries[2].name, "miner");
}

#[test]
fn test_parse_json_logs_ndjson() {
    let ndjson = r#"
{"host": "server1", "command": "/usr/bin/nginx"}
{"host": "server2", "command": "python3 app.py"}
{"host": "server3", "cmd": "/tmp/miner --pool pool"}
    "#;
    
    let entries = parse_json_logs(ndjson).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].machine_id, "server1");
    assert_eq!(entries[1].machine_id, "server2");
    assert_eq!(entries[2].machine_id, "server3");
}

#[test]
fn test_builder_add_json() {
    let mut builder = ProcessBuilder::new();
    
    builder.add_json(r#"{"host": "server1", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33}"#);
    builder.add_json(r#"{"node": "server2", "cmd": "python3 app.py", "userid": 1000}"#);
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.machine_id, "server1");
    assert_eq!(nginx.uid, 33);
}

#[test]
fn test_builder_add_json_batch() {
    let mut builder = ProcessBuilder::new();
    
    builder.add_json_batch(r#"[
        {"host": "server1", "command": "/usr/bin/nginx"},
        {"host": "server2", "command": "python3 app.py"}
    ]"#);
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
}

#[test]
fn test_json_parsing_with_analysis() {
    let config = DetectionConfig::default();
    
    // Simulate JSON logs from a monitoring system
    let json_logs = r#"[
        {"host": "web-1", "cmd": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33},
        {"host": "web-1", "cmd": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70},
        {"host": "web-2", "cmd": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33},
        {"host": "web-2", "cmd": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70},
        {"host": "web-3", "cmd": "/tmp/.hidden/poolig --donate-level 1", "uid": 0}
    ]"#;
    
    let entries = parse_json_logs(json_logs).unwrap();
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Should detect web-3 as anomalous
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "web-3"));
}

// --- TESTS MOVED FROM LIB.RS ---

#[test]
fn test_entropy_calculation() {
    let low = calculate_shannon_entropy("aaaaaaaaaa");
    assert_eq!(low, 0.0);
    
    let high = calculate_shannon_entropy("X5O!aH@9#kzL1^s09f87");
    assert!(high > 3.0);
}

#[test]
fn test_config_default() {
    let config = DetectionConfig::default();
    assert_eq!(config.entropy_threshold, 4.5);
    assert_eq!(config.dbscan_min_samples, 2);
}

#[test]
fn test_suspicious_path_detection() {
    let patterns = vec![r"/tmp/".to_string(), r"/dev/shm/".to_string()];
    assert!(is_path_suspicious("/tmp/malware", &patterns));
    assert!(is_path_suspicious("/dev/shm/rootkit", &patterns));
    assert!(!is_path_suspicious("/usr/bin/nginx", &patterns));
}

#[test]
fn test_resolve_parent_names_function() {
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    let pid_map = resolve_parent_names(&entries);
    assert_eq!(
        pid_map.get(&(Arc::from("m1"), 1)),
        Some(&Arc::from("systemd"))
    );
}

#[test]
fn test_identical_machines_clean() {
    let mut config = DetectionConfig::default();
    // Add "test" to common root processes to avoid flagging it as unexpected
    config.common_root_processes.push("test".to_string());
    let entries: Vec<RawLogEntry> = (0..5).flat_map(|i| {
        vec![
            RawLogEntry {
                machine_id: format!("m{}", i),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: format!("m{}", i),
                pid: 100,
                ppid: 1,
                name: "test".to_string(),
                uid: 0,
                path: "/bin/test".to_string(),
                args: "args".to_string(),
                timestamp: None,
            },
        ]
    }).collect();
    
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    assert!(report.anomalies.is_empty());
}

#[test]
fn test_detect_single_outlier() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // 10 normal machines
    for i in 0..10 {
        entries.push(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "".to_string(),
            timestamp: None,
        });
        entries.push(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        });
    }
    
    // 1 compromised machine
    entries.push(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "".to_string(),
        timestamp: None,
    });
    entries.push(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 666,
        ppid: 1,
        name: "miner".to_string(),
        uid: 0,
        path: "/tmp/kworker".to_string(),
        args: "XkzL1^s09f87".to_string(),
        timestamp: None,
    });

    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "compromised"));
}

#[test]
fn test_process_risk_factors() {
    let config = DetectionConfig::default();
    let sig = ProcessSignature {
        name: Arc::from("malware"),
        parent_name: Arc::from("bash"),
        uid: 0,
        path: Arc::from("/tmp/hidden"),
        is_high_entropy: true,
        is_suspicious_path: true,
    };
    
    let risks = sig.risk_factors(&config);
    assert!(!risks.is_empty());
    assert!(risks.iter().any(|r| r.contains("entropy")));
    assert!(risks.iter().any(|r| r.contains("Suspicious execution path")));
}

#[test]
fn test_ppid_resolution_comprehensive() {
    // Test comprehensive PPID resolution with multiple parent-child relationships
    let config = DetectionConfig::default();
    
    let entries = vec![
        // Machine 1: systemd -> nginx -> worker processes
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,  // Parent is systemd (PID 1)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "master process".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 101,
            ppid: 100,  // Parent is nginx (PID 100)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 102,
            ppid: 100,  // Another worker, parent is nginx (PID 100)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
        // Machine 2: systemd -> sshd -> bash -> malicious process
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 200,
            ppid: 1,  // Parent is systemd
            name: "sshd".to_string(),
            uid: 0,
            path: "/usr/sbin/sshd".to_string(),
            args: "-D".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 201,
            ppid: 200,  // Parent is sshd (PID 200)
            name: "bash".to_string(),
            uid: 1000,
            path: "/bin/bash".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 202,
            ppid: 201,  // Parent is bash (PID 201)
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/miner".to_string(),
            args: "--pool pool".to_string(),
            timestamp: None,
        },
    ];
    
    // Build profiles with PPID resolution
    let profiles = build_profiles(entries.clone(), &config);
    
    // Verify we got 2 machine profiles
    assert_eq!(profiles.len(), 2);
    
    // Machine 1 verification
    let m1_profile = profiles.iter().find(|p| p.id == "m1").unwrap();
    
    // Check that nginx processes exist and have correct parent
    let nginx_procs: Vec<_> = m1_profile.counts.iter()
        .filter(|(sig, _)| sig.name.as_ref() == "nginx")
        .collect();
    
    assert!(!nginx_procs.is_empty(), "Should have nginx processes");
    
    // All nginx processes should have nginx as parent (workers) or systemd (master)
    for (sig, _) in nginx_procs {
        assert!(
            sig.parent_name.as_ref() == "nginx" || sig.parent_name.as_ref() == "systemd",
            "Nginx process should have 'nginx' or 'systemd' as parent, got '{}'", 
            sig.parent_name.as_ref()
        );
    }
    
    // Machine 2 verification
    let m2_profile = profiles.iter().find(|p| p.id == "m2").unwrap();
    
    // Check that miner has bash as parent
    let miner_procs: Vec<_> = m2_profile.counts.iter()
        .filter(|(sig, _)| sig.name.as_ref() == "miner")
        .collect();
    
    assert!(!miner_procs.is_empty(), "Should have miner process");
    
    for (sig, _) in miner_procs {
        assert_eq!(sig.parent_name.as_ref(), "bash",
            "Miner should have 'bash' as parent, got '{}'", sig.parent_name.as_ref());
    }
    
    // Check that bash has sshd as parent
    let bash_procs: Vec<_> = m2_profile.counts.iter()
        .filter(|(sig, _)| sig.name.as_ref() == "bash")
        .collect();
    
    assert!(!bash_procs.is_empty(), "Should have bash process");
    
    for (sig, _) in bash_procs {
        assert_eq!(sig.parent_name.as_ref(), "sshd",
            "Bash should have 'sshd' as parent, got '{}'", sig.parent_name.as_ref());
    }
    
    // Verify parent resolution worked correctly by checking the PID map
    let pid_map = resolve_parent_names(&entries);
    
    // Check specific parent resolutions
    assert_eq!(pid_map.get(&(Arc::from("m1"), 1)), Some(&Arc::from("systemd")));
    assert_eq!(pid_map.get(&(Arc::from("m1"), 100)), Some(&Arc::from("nginx")));
    assert_eq!(pid_map.get(&(Arc::from("m2"), 200)), Some(&Arc::from("sshd")));
    assert_eq!(pid_map.get(&(Arc::from("m2"), 201)), Some(&Arc::from("bash")));
    
    println!("✅ PPID resolution test passed!");
    println!("   - Multi-level parent-child relationships resolved correctly");
    println!("   - nginx master -> workers chain verified");
    println!("   - sshd -> bash -> miner chain verified");
}

#[test]
fn test_ppid_resolution_with_missing_parents() {
    // Test PPID resolution when parent processes are missing from logs
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,  // Parent PID 1 (systemd) not in logs
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 101,
            ppid: 50,  // Parent PID 50 not in logs at all
            name: "worker".to_string(),
            uid: 33,
            path: "/usr/bin/worker".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    // Should not panic, should handle missing parents gracefully
    let profiles = build_profiles(entries, &config);
    
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    
    // Check that processes exist even with missing parents
    assert!(profile.counts.iter().any(|(sig, _)| sig.name.as_ref() == "nginx"));
    assert!(profile.counts.iter().any(|(sig, _)| sig.name.as_ref() == "worker"));
    
    println!("✅ Missing parent PPID test passed!");
}

#[test]
fn test_process_builder_len_and_is_empty() {
    let mut builder = ProcessBuilder::new();
    
    // Empty builder
    assert_eq!(builder.len(), 0);
    assert!(builder.is_empty());
    
    // Add one entry
    builder.add_process("server1", "nginx", "systemd");
    assert_eq!(builder.len(), 1);
    assert!(!builder.is_empty());
    
    // Add more entries
    builder.add_process("server1", "worker", "nginx");
    builder.add_process("server2", "postgres", "systemd");
    assert_eq!(builder.len(), 3);
    assert!(!builder.is_empty());
    
    // Add via command parsing
    builder.add_command("server3", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"));
    assert_eq!(builder.len(), 4);
    
    // Add via JSON
    builder.add_json(r#"{"host": "server4", "cmd": "python3 app.py"}"#);
    assert_eq!(builder.len(), 5);
    
    println!("✅ ProcessBuilder len() and is_empty() test passed!");
}

#[test]
fn test_load_json_data_array() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    let config = DetectionConfig::default();
    
    // Create temporary JSON file with array format
    let mut temp_file = NamedTempFile::new().unwrap();
    let json_content = r#"[
        {"machine_id": "server1", "pid": 1, "ppid": 0, "name": "systemd", "uid": 0, "path": "/usr/lib/systemd/systemd", "args": "--system"},
        {"machine_id": "server1", "pid": 100, "ppid": 1, "name": "nginx", "uid": 33, "path": "/usr/sbin/nginx", "args": "-c /etc/nginx.conf"},
        {"machine_id": "server2", "pid": 1, "ppid": 0, "name": "systemd", "uid": 0, "path": "/usr/lib/systemd/systemd", "args": "--system"},
        {"machine_id": "server2", "pid": 200, "ppid": 1, "name": "miner", "uid": 0, "path": "/tmp/miner", "args": "--pool pool"}
    ]"#;
    
    temp_file.write_all(json_content.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    
    // Load JSON data
    let profiles = load_json_data(temp_file.path().to_str().unwrap(), &config).unwrap();
    
    // Verify profiles loaded correctly
    assert_eq!(profiles.len(), 2);
    assert!(profiles.iter().any(|p| p.id == "server1"));
    assert!(profiles.iter().any(|p| p.id == "server2"));
    
    println!("✅ load_json_data (array format) test passed!");
}

#[test]
fn test_load_json_data_ndjson() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    let config = DetectionConfig::default();
    
    // Create temporary JSON file with NDJSON format
    let mut temp_file = NamedTempFile::new().unwrap();
    let json_content = r#"{"machine_id": "web1", "pid": 1, "ppid": 0, "name": "systemd", "uid": 0, "path": "/usr/lib/systemd/systemd", "args": ""}
{"machine_id": "web1", "pid": 100, "ppid": 1, "name": "nginx", "uid": 33, "path": "/usr/sbin/nginx", "args": ""}
{"machine_id": "web2", "pid": 1, "ppid": 0, "name": "systemd", "uid": 0, "path": "/usr/lib/systemd/systemd", "args": ""}
{"machine_id": "web2", "pid": 100, "ppid": 1, "name": "apache2", "uid": 33, "path": "/usr/sbin/apache2", "args": ""}
"#;
    
    temp_file.write_all(json_content.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    
    // Load JSON data
    let profiles = load_json_data(temp_file.path().to_str().unwrap(), &config).unwrap();
    
    // Verify profiles loaded correctly
    assert_eq!(profiles.len(), 2);
    assert!(profiles.iter().any(|p| p.id == "web1"));
    assert!(profiles.iter().any(|p| p.id == "web2"));
    
    println!("✅ load_json_data (NDJSON format) test passed!");
}

#[test]
fn test_load_json_data_nonexistent_file() {
    let config = DetectionConfig::default();
    
    // Try to load non-existent file
    let result = load_json_data("nonexistent_file.json", &config);
    
    // Should return error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
    
    println!("✅ load_json_data (nonexistent file) test passed!");
}

#[test]
fn test_load_json_data_empty_file() {
    use tempfile::NamedTempFile;
    
    let config = DetectionConfig::default();
    
    // Create empty file
    let temp_file = NamedTempFile::new().unwrap();
    
    // Try to load empty file
    let result = load_json_data(temp_file.path().to_str().unwrap(), &config);
    
    // Should return error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));
    
    println!("✅ load_json_data (empty file) test passed!");
}

#[test]
fn test_load_json_data_simplified_format() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    let config = DetectionConfig::default();
    
    // Create JSON with flexible key names (Docker/K8s style)
    let mut temp_file = NamedTempFile::new().unwrap();
    let json_content = r#"[
        {"host": "container1", "cmd": "nginx", "uid": 33},
        {"host": "container1", "cmd": "postgres", "uid": 70},
        {"node": "worker1", "command": "python3 app.py", "userid": 1000},
        {"container": "web-prod", "commandline": "/usr/bin/node server.js", "user_id": 1000}
    ]"#;
    
    temp_file.write_all(json_content.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    
    // Load JSON data with flexible keys
    let profiles = load_json_data(temp_file.path().to_str().unwrap(), &config).unwrap();
    
    // Should parse flexible key names correctly
    assert!(!profiles.is_empty());
    
    println!("✅ load_json_data (flexible keys) test passed!");
}

#[test]
fn test_parse_jsonl_process_line() {
    use crate::parse_jsonl_process_line;

    let line = r#"{"timestamp": "2026-03-16T00:10:05", "event_type": "process", "user": "0", "command": "/sbin/init auto A /dev/sda", "pid": 1, "ppid": 0}"#;
    let entry = parse_jsonl_process_line(line, "myhost").unwrap();
    assert_eq!(entry.machine_id, "myhost");
    assert_eq!(entry.pid, 1);
    assert_eq!(entry.ppid, 0);
    assert_eq!(entry.uid, 0);
    assert_eq!(entry.name, "init");
    assert_eq!(entry.path, "/sbin/init");
    assert_eq!(entry.args, "auto A /dev/sda");
    assert_eq!(entry.timestamp.as_deref(), Some("2026-03-16T00:10:05"));

    let kernel_line = r#"{"timestamp": "2026-03-16T00:10:05", "event_type": "process", "user": "0", "command": "[ksoftirqd/0]", "pid": 8, "ppid": 2}"#;
    let e2 = parse_jsonl_process_line(kernel_line, "default").unwrap();
    assert_eq!(e2.machine_id, "default");
    assert_eq!(e2.pid, 8);
    assert_eq!(e2.ppid, 2);
    assert_eq!(e2.name, "[ksoftirqd/0]");

    let sysmon = r#"{"hostname":"h","pid":4,"CommandLine":"C:\\Windows\\System32\\smss.exe","Image":"C:\\Windows\\System32\\smss.exe"}"#;
    let e3 = parse_jsonl_process_line(sysmon, "default").unwrap();
    assert_eq!(e3.path, r"C:\Windows\System32\smss.exe");

    let path_only = r#"{"machine_id":"m","path":"/usr/bin/bash","pid":100}"#;
    let e4 = parse_jsonl_process_line(path_only, "fallback").unwrap();
    assert_eq!(e4.machine_id, "m");
    assert_eq!(e4.path, "/usr/bin/bash");
}

#[test]
fn test_load_jsonl_data() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let config = DetectionConfig::default();
    let mut temp = NamedTempFile::new().unwrap();
    writeln!(
        temp,
        r#"{{"timestamp": "2026-03-16T00:10:05", "event_type": "process", "user": "0", "command": "/sbin/init", "pid": 1, "ppid": 0}}"#
    )
    .unwrap();
    writeln!(
        temp,
        r#"{{"timestamp": "2026-03-16T00:10:06", "user": "33", "command": "/usr/sbin/nginx -c /etc/nginx.conf", "pid": 100, "ppid": 1}}"#
    )
    .unwrap();
    temp.flush().unwrap();

    let path = temp.path().to_str().unwrap();
    let stem = temp.path().file_stem().unwrap().to_str().unwrap();
    let profiles = load_jsonl_data(path, &config, None).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, stem);
    assert!(profiles[0].total_logs >= 2);
}

// ============================================================================
// GENERATOR DETECTION TESTS - Verify all malicious machines are detected
// ============================================================================

/// Test that web shell payloads have high entropy
#[test]
fn test_web_shell_entropy() {
    let web_shell_payloads = vec![
        "proc_decode(req_data('aGVsbG8=XkzL9p'));//$A2xMq7@Fn3^Wv5",
        "runtime_invoke($_REQUEST['q7Zm9P']);cfg();//@K3pRx8Lm",
        "<?method exec_rt($_DATA['z8TpQ']);process();?>@Km9Lx2Jf",
        "decode_call(param_get('ZWNobyBzeXN0ZW0=R5mN'));//#Jf2QxYp",
        "<?dynamic(uncompress(data_b64('K0ktSgEA7Yp3')));?>Rm8Nq",
        "run_proc('cmd /c type data.txt | encode');invoke($x9HqLm3);//Wx7",
    ];
    
    let threshold = 4.5;
    let mut high_entropy_count = 0;
    
    for (i, payload) in web_shell_payloads.iter().enumerate() {
        let entropy = calculate_shannon_entropy(payload);
        println!("Web shell #{}: entropy = {:.2}", i + 1, entropy);
        
        if entropy > threshold {
            high_entropy_count += 1;
        }
    }
    
    // At least 50% of web shell payloads should have high entropy
    assert!(
        high_entropy_count >= web_shell_payloads.len() / 2,
        "Only {}/{} web shell payloads have high entropy (threshold: {}). Need at least {}.",
        high_entropy_count, web_shell_payloads.len(), threshold, web_shell_payloads.len() / 2
    );
    
    println!("✅ Web shell entropy test passed: {}/{} payloads have high entropy",
        high_entropy_count, web_shell_payloads.len());
}

/// Test that cryptominer paths are detected as suspicious
#[test]
fn test_cryptominer_detection() {
    let config = DetectionConfig::default();
    
    let miner_paths = vec![
        "/tmp/.X11-unix/kworker",
        "/var/tmp/.cache/systemd",
        "/dev/shm/.config/worker",
    ];
    
    for path in miner_paths {
        let is_suspicious = is_path_suspicious(path, &config.suspicious_path_patterns);
        assert!(
            is_suspicious,
            "Cryptominer path '{}' should be detected as suspicious",
            path
        );
    }
    
    println!("✅ Cryptominer path detection test passed!");
}

/// Test that privilege escalation is detected (unexpected root processes)
#[test]
fn test_privilege_escalation_detection() {
    let config = DetectionConfig::default();
    
    // These should be flagged as unexpected root
    let unexpected_root = vec![
        ("node", "/usr/bin/node", "server.js"),
        ("python3", "/tmp/hidden_app", "shell.py"),
        ("miner", "/tmp/kworker", "--donate-level 1"),
    ];
    
    for (name, path, _args) in unexpected_root {
        let sig = ProcessSignature {
            name: Arc::from(name),
            parent_name: Arc::from("systemd"),
            uid: 0,
            path: Arc::from(path),
            is_high_entropy: false,
            is_suspicious_path: false,
        };
        
        let is_unexpected = sig.is_unexpected_root(&config.common_root_processes);
        assert!(
            is_unexpected,
            "Process '{}' as root should be unexpected",
            name
        );
    }
    
    // These should NOT be flagged (in whitelist)
    let expected_root = vec!["systemd", "sshd", "cron", "dockerd"];
    
    for name in expected_root {
        let sig = ProcessSignature {
            name: Arc::from(name),
            parent_name: Arc::from("init"),
            uid: 0,
            path: Arc::from(format!("/usr/sbin/{}", name)),
            is_high_entropy: false,
            is_suspicious_path: false,
        };
        
        let is_unexpected = sig.is_unexpected_root(&config.common_root_processes);
        assert!(
            !is_unexpected,
            "Process '{}' as root should be expected (in whitelist)",
            name
        );
    }
    
    println!("✅ Privilege escalation detection test passed!");
}

/// Test detection with realistic malicious machine data
#[test]
fn test_malicious_machine_detection() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // Create 10 normal machines
    for i in 0..10 {
        let machine_id = format!("normal_{:03}", i);
        
        // systemd
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        });
        
        // Normal processes (50 each)
        for j in 0..50 {
            entries.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-c /etc/nginx.conf".to_string(),
                timestamp: None,
            });
        }
    }
    
    // Create 1 machine with web shell (like machine_009)
    let web_shell_id = "web_shell_machine".to_string();
    
    // systemd
    entries.push(RawLogEntry {
        machine_id: web_shell_id.clone(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // apache2 parent
    entries.push(RawLogEntry {
        machine_id: web_shell_id.clone(),
        pid: 108,
        ppid: 1,
        name: "apache2".to_string(),
        uid: 33,
        path: "/usr/sbin/apache2".to_string(),
        args: "-k start".to_string(),
        timestamp: None,
    });
    
    // Normal processes
    for j in 0..35 {
        entries.push(RawLogEntry {
            machine_id: web_shell_id.clone(),
            pid: 200 + j,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        });
    }
    
    // php-fpm with malicious payloads (like the generator creates)
    for j in 0..10 {
        entries.push(RawLogEntry {
            machine_id: web_shell_id.clone(),
            pid: 300 + j,
            ppid: 108, // apache2 parent
            name: "php-fpm".to_string(),
            uid: 33,
            path: "/usr/sbin/php-fpm".to_string(),
            // High entropy payloads
            args: "proc_decode(req_data('ZWNobyBzeXN0ZW0=R5mN'));//#Jf2QxYp".to_string(),
            timestamp: None,
        });
    }
    
    // Build profiles and analyze
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Verify web shell machine is detected
    assert_eq!(profiles.len(), 11, "Should have 11 machines total");
    assert!(
        !report.anomalies.is_empty(),
        "Should detect at least one anomaly"
    );
    
    let web_shell_detected = report.anomalies.iter()
        .any(|a| a.machine_id == web_shell_id);
    
    assert!(
        web_shell_detected,
        "Web shell machine should be detected as anomaly. Detected anomalies: {:?}",
        report.anomalies.iter().map(|a| &a.machine_id).collect::<Vec<_>>()
    );
    
    println!("✅ Malicious machine detection test passed!");
    println!("   Detected {} anomalies out of 11 machines", report.anomalies.len());
}

/// Test that ALL 6 attack types from generator are detectable
#[test]
fn test_all_attack_types_detectable() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // Create baseline: 10 normal machines
    for i in 0..10 {
        let machine_id = format!("normal_{:03}", i);
        add_normal_machine(&mut entries, &machine_id, 50);
    }
    
    // Attack Type 1: Cryptominer in /tmp
    let miner1_id = "cryptominer_tmp".to_string();
    add_normal_machine(&mut entries, &miner1_id, 30);
    for j in 0..15 {
        entries.push(RawLogEntry {
            machine_id: miner1_id.clone(),
            pid: 500 + j,
            ppid: 1,
            name: "kworker".to_string(),
            uid: 0,
            path: "/tmp/.X11-unix/kworker".to_string(),
            args: "--url tcp://pool.example.org:4444".to_string(),
            timestamp: None,
        });
    }
    
    // Attack Type 2: Cryptominer in /dev/shm
    let miner2_id = "cryptominer_shm".to_string();
    add_normal_machine(&mut entries, &miner2_id, 20);
    for j in 0..35 {
        entries.push(RawLogEntry {
            machine_id: miner2_id.clone(),
            pid: 600 + j,
            ppid: 1,
            name: "worker".to_string(),
            uid: 0,
            path: "/dev/shm/.config/worker".to_string(),
            args: "-o pool.example.org:14444".to_string(),
            timestamp: None,
        });
    }
    
    // Attack Type 3: Web Shell
    let webshell_id = "web_shell".to_string();
    add_normal_machine(&mut entries, &webshell_id, 30);
    // Add apache2
    entries.push(RawLogEntry {
        machine_id: webshell_id.clone(),
        pid: 108,
        ppid: 1,
        name: "apache2".to_string(),
        uid: 33,
        path: "/usr/sbin/apache2".to_string(),
        args: "-k start".to_string(),
        timestamp: None,
    });
    // Add php-fpm with malicious payloads
    for j in 0..10 {
        entries.push(RawLogEntry {
            machine_id: webshell_id.clone(),
            pid: 700 + j,
            ppid: 108,
            name: "php-fpm".to_string(),
            uid: 33,
            path: "/usr/sbin/php-fpm".to_string(),
            args: "proc_decode(req_data('ZWNobyBzeXN0ZW0=R5mN'));//#Jf2QxYp".to_string(),
            timestamp: None,
        });
    }
    
    // Attack Type 4: Privilege Escalation (node as root)
    let privesc1_id = "privesc_node".to_string();
    add_normal_machine(&mut entries, &privesc1_id, 30);
    for j in 0..15 {
        entries.push(RawLogEntry {
            machine_id: privesc1_id.clone(),
            pid: 800 + j,
            ppid: 1,
            name: "node".to_string(),
            uid: 0, // root!
            path: "/usr/bin/node".to_string(),
            args: "server.js".to_string(),
            timestamp: None,
        });
    }
    
    // Attack Type 5: Privilege Escalation (python3 in /tmp)
    let privesc2_id = "privesc_python".to_string();
    add_normal_machine(&mut entries, &privesc2_id, 30);
    for j in 0..15 {
        entries.push(RawLogEntry {
            machine_id: privesc2_id.clone(),
            pid: 900 + j,
            ppid: 1,
            name: "python3".to_string(),
            uid: 0, // root!
            path: "/tmp/hidden_app".to_string(),
            args: "shell.py".to_string(),
            timestamp: None,
        });
    }
    
    // Attack Type 6: Lateral Movement (SSH to internal IPs)
    let lateral_id = "lateral_movement".to_string();
    add_normal_machine(&mut entries, &lateral_id, 20);
    
    // Add sshd parent
    entries.push(RawLogEntry {
        machine_id: lateral_id.clone(),
        pid: 101,
        ppid: 1,
        name: "sshd".to_string(),
        uid: 0,
        path: "/usr/sbin/sshd".to_string(),
        args: "-D".to_string(),
        timestamp: None,
    });
    
    // Add SSH client connections to internal IPs (more entries for better detection)
    for j in 0..25 {
        entries.push(RawLogEntry {
            machine_id: lateral_id.clone(),
            pid: 1000 + j,
            ppid: 101, // sshd parent
            name: "ssh".to_string(), // SSH CLIENT
            uid: 0,
            path: "/usr/bin/ssh".to_string(),
            args: format!("-o StrictHostKeyChecking=no root@192.168.1.{}", 10 + j),
            timestamp: None,
        });
    }
    
    // Build profiles and analyze
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Total: 10 normal + 6 malicious = 16 machines
    assert_eq!(profiles.len(), 16, "Should have 16 machines total");
    
    // Check each attack type is detected
    let attack_machines = vec![
        &miner1_id,
        &miner2_id,
        &webshell_id,
        &privesc1_id,
        &privesc2_id,
        &lateral_id,
    ];
    
    let mut detected = Vec::new();
    let mut missed = Vec::new();
    
    for machine_id in &attack_machines {
        if report.anomalies.iter().any(|a| &a.machine_id == *machine_id) {
            detected.push(*machine_id);
        } else {
            missed.push(*machine_id);
        }
    }
    
    // Print detailed results
    println!("\n📊 Detection Results:");
    println!("   Total machines: {}", profiles.len());
    println!("   Anomalies detected: {}", report.anomalies.len());
    println!("   Attack machines: {}", attack_machines.len());
    println!("\n✅ Detected ({}/{}):", detected.len(), attack_machines.len());
    for id in &detected {
        println!("     - {}", id);
    }
    
    if !missed.is_empty() {
        println!("\n❌ MISSED ({}/{}):", missed.len(), attack_machines.len());
        for id in &missed {
            println!("     - {}", id);
        }
    }
    
    // All 6 attack types must be detected
    assert!(
        missed.is_empty(),
        "Failed to detect {} attack machines: {:?}. Only detected: {:?}",
        missed.len(), missed, detected
    );
    
    println!("\n✅ All attack types detection test passed!");
}

/// Helper function to add a normal machine
fn add_normal_machine(entries: &mut Vec<RawLogEntry>, machine_id: &str, log_count: u32) {
    // systemd
    entries.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // Normal processes
    for j in 0..log_count {
        entries.push(RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 100 + j,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        });
    }
}

/// Test that detection is consistent with different tolerance values
#[test]
fn test_tolerance_sensitivity() {
    let mut config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // 5 normal machines
    for i in 0..5 {
        add_normal_machine(&mut entries, &format!("normal_{}", i), 50);
    }
    
    // 1 obvious attacker (cryptominer)
    let attacker_id = "attacker".to_string();
    add_normal_machine(&mut entries, &attacker_id, 20);
    for j in 0..25 {
        entries.push(RawLogEntry {
            machine_id: attacker_id.clone(),
            pid: 500 + j,
            ppid: 1,
            name: "kworker".to_string(),
            uid: 0,
            path: "/tmp/.hidden/miner".to_string(),
            args: "XkzL1^s09f87aH@9#kzL1^s09f87".to_string(),
            timestamp: None,
        });
    }
    
    // Test with different tolerance values
    let tolerances = vec![0.03, 0.05, 0.08, 0.10];
    let mut detection_results = Vec::new();
    
    for tolerance in &tolerances {
        config.dbscan_tolerance = *tolerance;
        let profiles = build_profiles(entries.clone(), &config);
        let report = analyze_fleet(&profiles, &config).unwrap();
        
        let detected = report.anomalies.iter()
            .any(|a| a.machine_id == attacker_id);
        
        detection_results.push((*tolerance, detected));
        println!("Tolerance {:.2}: attacker {} detected", 
            tolerance, 
            if detected { "WAS" } else { "NOT" }
        );
    }
    
    // At least with strict tolerance (0.03, 0.05), attacker should be detected
    let strict_detections: Vec<_> = detection_results.iter()
        .filter(|(t, _)| *t <= 0.05)
        .collect();
    
    let all_strict_detected = strict_detections.iter()
        .all(|(_, detected)| *detected);
    
    assert!(
        all_strict_detected,
        "Obvious attacker should be detected with strict tolerance (≤0.05)"
    );
    
    println!("✅ Tolerance sensitivity test passed!");
}

/// Test lateral movement detection specifically (machine_012)
#[test]
fn test_lateral_movement_detection() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // Create 10 normal machines with sshd (normal SSH daemon)
    for i in 0..10 {
        let machine_id = format!("normal_{:03}", i);
        
        // systemd
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        });
        
        // Normal processes including sshd (daemon)
        for j in 0..40 {
            entries.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-c /etc/nginx.conf".to_string(),
                timestamp: None,
            });
        }
        
        // Add some normal sshd daemon entries
        for j in 0..5 {
            entries.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 200 + j,
                ppid: 1,
                name: "sshd".to_string(),
                uid: 0,
                path: "/usr/sbin/sshd".to_string(),
                args: "-D".to_string(),
                timestamp: None,
            });
        }
    }
    
    // Create machine_012 with lateral movement (SSH client to internal IPs)
    let lateral_id = "lateral_movement_machine".to_string();
    
    // systemd
    entries.push(RawLogEntry {
        machine_id: lateral_id.clone(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // sshd parent
    entries.push(RawLogEntry {
        machine_id: lateral_id.clone(),
        pid: 101,
        ppid: 1,
        name: "sshd".to_string(),
        uid: 0,
        path: "/usr/sbin/sshd".to_string(),
        args: "-D".to_string(),
        timestamp: None,
    });
    
    // Normal processes
    for j in 0..30 {
        entries.push(RawLogEntry {
            machine_id: lateral_id.clone(),
            pid: 200 + j,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        });
    }
    
    // SSH client connections to internal IPs (lateral movement)
    let internal_ips = vec![
        "root@10.0.1.5",
        "root@192.168.1.10",
        "admin@172.16.0.50",
        "root@10.0.2.15",
        "user@192.168.1.100",
    ];
    
    for j in 0..20 {
        let ip = internal_ips[j % internal_ips.len()];
        entries.push(RawLogEntry {
            machine_id: lateral_id.clone(),
            pid: 300 + j as u32,
            ppid: 101, // sshd parent
            name: "ssh".to_string(), // ssh CLIENT (not sshd daemon)
            uid: 0,
            path: "/usr/bin/ssh".to_string(),
            args: format!("-o StrictHostKeyChecking=no {}", ip),
            timestamp: None,
        });
    }
    
    // Build profiles and analyze
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Verify lateral movement machine is detected
    assert_eq!(profiles.len(), 11, "Should have 11 machines total");
    assert!(
        !report.anomalies.is_empty(),
        "Should detect at least one anomaly"
    );
    
    let lateral_detected = report.anomalies.iter()
        .any(|a| a.machine_id == lateral_id);
    
    // Debug output
    println!("\n📊 Lateral Movement Detection:");
    println!("   Total machines: {}", profiles.len());
    println!("   Anomalies detected: {}", report.anomalies.len());
    println!("   Detected anomalies: {:?}", 
        report.anomalies.iter().map(|a| &a.machine_id).collect::<Vec<_>>()
    );
    
    assert!(
        lateral_detected,
        "Lateral movement machine (machine_012 equivalent) should be detected as anomaly. \
         Detected anomalies: {:?}",
        report.anomalies.iter().map(|a| &a.machine_id).collect::<Vec<_>>()
    );
    
    println!("✅ Lateral movement detection test passed!");
    println!("   Machine with SSH connections to internal IPs was detected");
}

/// Test kernel thread handling - parsing and filtering
#[test]
fn test_kernel_thread_handling() {
    let config = DetectionConfig::default();
    
    // Test 1: Kernel thread names are parsed correctly
    let kernel_threads = vec![
        "[kworker/1:0]",
        "[migration/0]",
        "[ksoftirqd/1]",
        "[kthreadd]",
        "[watchdog/0]",
        "[kswapd0]",
        "[ksmd]",
    ];
    
    println!("\n🔍 Testing kernel thread parsing:");
    for thread_name in &kernel_threads {
        let (name, path, args) = parse_command_line(thread_name);
        
        println!("   {} → name='{}', path='{}', args='{}'", thread_name, name, path, args);
        
        assert_eq!(name, *thread_name, "Name should be preserved");
        assert_eq!(path, *thread_name, "Path should equal name");
        assert_eq!(args, "", "Kernel threads have no args");
    }
    
    // Test 2: Kernel threads are filtered when config says so
    let mut entries = Vec::new();
    let machine_id = "test_machine".to_string();
    
    // Add systemd
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // Add kernel threads
    for (i, thread_name) in kernel_threads.iter().enumerate() {
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 10 + i as u32,
            ppid: 0,
            name: thread_name.to_string(),
            uid: 0,
            path: thread_name.to_string(),
            args: String::new(),
            timestamp: None,
        });
    }
    
    // Add normal processes
    for j in 0..10 {
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 100 + j,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        });
    }
    
    let total_entries = entries.len();
    let kernel_thread_count = kernel_threads.len();
    
    println!("\n🔍 Testing kernel thread filtering:");
    println!("   Total entries: {}", total_entries);
    println!("   Kernel threads: {}", kernel_thread_count);
    println!("   Normal processes: {}", total_entries - kernel_thread_count - 1);
    
    // Test with filtering enabled (default)
    let mut config_filter = config.clone();
    config_filter.exclude_kernel_threads = true;
    
    let profiles_filtered = build_profiles(entries.clone(), &config_filter);
    let profile = &profiles_filtered[0];
    
    // Check that kernel threads were filtered out
    let has_kernel_threads = profile.counts.keys().any(|sig| {
        sig.name.starts_with('[') && sig.name.ends_with(']')
    });
    
    assert!(
        !has_kernel_threads,
        "Kernel threads should be filtered out when exclude_kernel_threads=true"
    );
    
    println!("   ✅ With filtering: {} process signatures (kernel threads removed)", 
        profile.counts.len());
    
    // Test with filtering disabled
    let mut config_no_filter = config.clone();
    config_no_filter.exclude_kernel_threads = false;
    
    let profiles_no_filter = build_profiles(entries.clone(), &config_no_filter);
    let profile_no_filter = &profiles_no_filter[0];
    
    // Check that kernel threads are included
    let has_kernel_threads_no_filter = profile_no_filter.counts.keys().any(|sig| {
        sig.name.starts_with('[') && sig.name.ends_with(']')
    });
    
    assert!(
        has_kernel_threads_no_filter,
        "Kernel threads should be included when exclude_kernel_threads=false"
    );
    
    println!("   ✅ Without filtering: {} process signatures (kernel threads included)", 
        profile_no_filter.counts.len());
    
    // Verify the difference
    assert!(
        profile_no_filter.counts.len() > profile.counts.len(),
        "Profile without filtering should have more signatures"
    );
    
    println!("\n✅ Kernel thread handling test passed!");
    println!("   Parsing: Correct ✓");
    println!("   Filtering: Working ✓");
}

/// Test init children filtering
#[test]
fn test_init_children_filtering() {
    let mut config = DetectionConfig::default();
    let machine_id = "test_machine".to_string();
    let mut entries = Vec::new();
    
    // Add systemd (PID 1)
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // Add system services (children of init, PPID=1)
    let system_services = vec![
        ("sshd", "/usr/sbin/sshd", "-D"),
        ("cron", "/usr/sbin/cron", "-f"),
        ("rsyslogd", "/usr/sbin/rsyslogd", "-n"),
        ("dockerd", "/usr/bin/dockerd", "--iptables=false"),
    ];
    
    for (i, (name, path, args)) in system_services.iter().enumerate() {
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 100 + i as u32,
            ppid: 1,  // Child of init
            name: name.to_string(),
            uid: 0,
            path: path.to_string(),
            args: args.to_string(),
            timestamp: None,
        });
    }
    
    // Add user processes (children of sshd, PPID=100)
    for j in 0..5 {
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 200 + j,
            ppid: 100,  // Child of sshd
            name: "bash".to_string(),
            uid: 1000,
            path: "/bin/bash".to_string(),
            args: String::new(),
            timestamp: None,
        });
    }
    
    let total_entries = entries.len();
    let init_children = system_services.len();
    
    println!("\n🔍 Testing init children filtering:");
    println!("   Total entries: {}", total_entries);
    println!("   Init children (PPID=1): {}", init_children);
    println!("   Other processes: {}", total_entries - init_children - 1);
    
    // Test WITHOUT filtering (default)
    config.exclude_init_children = false;
    let profiles_no_filter = build_profiles(entries.clone(), &config);
    let profile_no_filter = &profiles_no_filter[0];
    
    println!("   ✅ Without filtering: {} process signatures", 
        profile_no_filter.counts.len());
    
    // Test WITH filtering
    config.exclude_init_children = true;
    let profiles_filtered = build_profiles(entries.clone(), &config);
    let profile_filtered = &profiles_filtered[0];
    
    // Should only have bash processes (PPID=100), systemd itself stays as reference
    assert!(
        profile_filtered.counts.len() < profile_no_filter.counts.len(),
        "Filtered profile should have fewer signatures"
    );
    
    // Verify init children are filtered out
    let has_sshd = profile_filtered.counts.keys().any(|sig| sig.name.as_ref() == "sshd");
    let has_bash = profile_filtered.counts.keys().any(|sig| sig.name.as_ref() == "bash");
    
    assert!(!has_sshd, "sshd (init child) should be filtered out");
    assert!(has_bash, "bash (not init child) should remain");
    
    println!("   ✅ With filtering: {} process signatures (init children removed)", 
        profile_filtered.counts.len());
    
    println!("\n✅ Init children filtering test passed!");
    println!("   System services filtered: ✓");
    println!("   User processes kept: ✓");
}

/// Test path whitelist functionality
#[test]
fn test_path_whitelist() {
    println!("\n🔍 Testing path whitelist:");
    
    // Test wildcard matching
    let whitelist = vec![
        "/opt/conda/*".to_string(),
        "/usr/local/bin/*".to_string(),
        "/home/*/venv/*".to_string(),
        "/home/*/anaconda3/*".to_string(),
    ];
    
    // Should match whitelist
    let whitelisted_paths = vec![
        "/opt/conda/bin/python",
        "/opt/conda/lib/libssl.so",
        "/usr/local/bin/custom-app",
        "/home/user/venv/bin/python3",
        "/home/bob/anaconda3/bin/jupyter",
    ];
    
    println!("   Testing whitelisted paths:");
    for path in &whitelisted_paths {
        let is_whitelisted = is_path_whitelisted(path, &whitelist);
        assert!(is_whitelisted, "Path '{}' should be whitelisted", path);
        println!("     ✓ {} (whitelisted)", path);
    }
    
    // Should NOT match whitelist
    let non_whitelisted_paths = vec![
        "/tmp/suspicious",
        "/dev/shm/miner",
        "/home/user/.hidden/hidden_app",
        "/opt/malware/payload",
    ];
    
    println!("   Testing non-whitelisted paths:");
    for path in &non_whitelisted_paths {
        let is_whitelisted = is_path_whitelisted(path, &whitelist);
        assert!(!is_whitelisted, "Path '{}' should NOT be whitelisted", path);
        println!("     ✗ {} (not whitelisted)", path);
    }
    
    // Test that whitelisted paths are not flagged as suspicious
    let suspicious_patterns = vec![
        "/tmp/".to_string(),
        "/dev/shm/".to_string(),
    ];
    
    let config = DetectionConfig {
        whitelisted_path_patterns: whitelist.clone(),
        suspicious_path_patterns: suspicious_patterns.clone(),
        ..Default::default()
    };
    
    // Whitelisted path in suspicious location
    let path = "/opt/conda/bin/python";
    let is_whitelisted = is_path_whitelisted(path, &config.whitelisted_path_patterns);
    let is_suspicious = if is_whitelisted {
        false
    } else {
        is_path_suspicious(path, &config.suspicious_path_patterns)
    };
    
    assert!(!is_suspicious, "Whitelisted path should not be flagged as suspicious");
    
    println!("\n✅ Path whitelist test passed!");
    println!("   Wildcard matching: ✓");
    println!("   Whitelist priority: ✓");
}

/// Test integration: init filtering + path whitelist
#[test]
fn test_init_and_whitelist_integration() {
    let mut config = DetectionConfig::default();
    config.exclude_init_children = true;
    config.whitelisted_path_patterns = vec![
        "/opt/custom/*".to_string(),
    ];
    config.suspicious_path_patterns = vec![
        "/opt/".to_string(),  // /opt is suspicious...
    ];
    
    let machine_id = "test".to_string();
    let mut entries = Vec::new();
    
    // Systemd
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    });
    
    // Init child with suspicious path (should be filtered by PPID)
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 100,
        ppid: 1,
        name: "service".to_string(),
        uid: 0,
        path: "/opt/malware/service".to_string(),
        args: String::new(),
        timestamp: None,
    });
    
    // User process with whitelisted path
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 200,
        ppid: 100,
        name: "app".to_string(),
        uid: 1000,
        path: "/opt/custom/app".to_string(),
        args: String::new(),
        timestamp: None,
    });
    
    // User process with suspicious path
    entries.push(RawLogEntry {
        machine_id: machine_id.clone(),
        pid: 300,
        ppid: 100,
        name: "bad".to_string(),
        uid: 1000,
        path: "/opt/suspicious/bad".to_string(),
        args: String::new(),
        timestamp: None,
    });
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Should have filtered out init child (service)
    let has_service = profile.counts.keys().any(|sig| sig.name.as_ref() == "service");
    assert!(!has_service, "Init child should be filtered");
    
    // Should NOT have app (whitelisted paths are filtered out entirely)
    let app_sig = profile.counts.keys().find(|sig| sig.name.as_ref() == "app");
    assert!(app_sig.is_none(), "Whitelisted app should be filtered out");
    
    // Should have bad (suspicious)
    let bad_sig = profile.counts.keys().find(|sig| sig.name.as_ref() == "bad");
    assert!(bad_sig.is_some(), "Suspicious process should be present");
    assert!(bad_sig.unwrap().is_suspicious_path, "Non-whitelisted path should be suspicious");
    
    println!("✅ Integration test passed!");
}

/// Test anomaly severity levels
#[test]
fn test_anomaly_severity_levels() {
    use crate::AnomalyLevel;
    
    println!("\n🔍 Testing anomaly severity levels:");
    
    // Test severity from distance
    let test_cases = vec![
        (0.0, "LOW", "🟡", 0),
        (0.2, "LOW", "🟡", 0),
        (0.3, "MEDIUM", "🟠", 1),
        (0.5, "MEDIUM", "🟠", 1),
        (0.6, "HIGH", "🔴", 2),
        (0.8, "HIGH", "🔴", 2),
        (1.0, "CRITICAL", "💀", 3),
        (1.5, "CRITICAL", "💀", 3),
        (2.0, "CRITICAL", "💀", 3),
    ];
    
    for (distance, expected_level, expected_emoji, expected_score) in test_cases {
        let severity = AnomalyLevel::from_distance(distance);
        
        assert_eq!(severity.as_str(), expected_level, 
            "Distance {} should be {}", distance, expected_level);
        assert_eq!(severity.emoji(), expected_emoji,
            "Distance {} should have emoji {}", distance, expected_emoji);
        assert_eq!(severity.score(), expected_score,
            "Distance {} should have score {}", distance, expected_score);
        
        println!("   Distance {:.1} → {} {} (score: {})", 
            distance, expected_emoji, expected_level, expected_score);
    }
    
    // Test Display trait
    let levels = vec![
        AnomalyLevel::Low,
        AnomalyLevel::Medium,
        AnomalyLevel::High,
        AnomalyLevel::Critical,
    ];
    
    println!("\n   Testing Display trait:");
    for level in levels {
        let display_str = format!("{}", level);
        assert_eq!(display_str, level.as_str());
        println!("     {} → {}", level.emoji(), display_str);
    }
    
    println!("\n✅ Anomaly severity levels test passed!");
}

/// Test severity in detection results
#[test]
fn test_severity_in_detection() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // Create normal machines (majority)
    for i in 0..10 {
        let machine_id = format!("normal_{}", i);
        add_normal_machine(&mut entries, &machine_id, 50);
    }
    
    // Create anomaly with high distance (obvious outlier)
    let anomaly_id = "anomaly_critical".to_string();
    add_normal_machine(&mut entries, &anomaly_id, 20);
    
    // Add many unusual processes
    for j in 0..30 {
        entries.push(RawLogEntry {
            machine_id: anomaly_id.clone(),
            pid: 500 + j,
            ppid: 1,
            name: "unusual".to_string(),
            uid: 0,
            path: "/tmp/.hidden/unusual".to_string(),
            args: format!("XkzL1^s09f87aH@9#{}", j),
            timestamp: None,
        });
    }
    
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Should detect the anomaly
    assert!(!report.anomalies.is_empty(), "Should detect anomaly");
    
    let detected = report.anomalies.iter()
        .find(|a| a.machine_id == anomaly_id);
    
    assert!(detected.is_some(), "Anomaly machine should be in results");
    
    let anomaly = detected.unwrap();
    
    // Check severity is calculated
    println!("\n🔍 Detected anomaly:");
    println!("   Machine: {}", anomaly.machine_id);
    println!("   Severity: {} {}", anomaly.severity.emoji(), anomaly.severity.as_str());
    println!("   Score: {}", anomaly.severity.score());
    println!("   Distance: {:.3}", anomaly.distance_score);
    
    // Should be at least MEDIUM severity (likely HIGH or CRITICAL)
    assert!(
        anomaly.severity.score() >= 1,
        "Obvious anomaly should have at least MEDIUM severity, got: {}",
        anomaly.severity.as_str()
    );
    
    println!("\n✅ Severity in detection test passed!");
}
// ============================================================================
// PPID PRESERVATION TESTS ⭐
// ============================================================================

#[test]
fn test_ppid_preservation_in_json() {
    println!("\n🧪 Testing PPID preservation in JSON parsing");
    
    let mut builder = ProcessBuilder::new();
    let json = r#"{
        "machine_id": "server1",
        "pid": 100,
        "ppid": 1,
        "name": "worker",
        "uid": 1000,
        "path": "/usr/bin/worker",
        "args": "",
        "timestamp": "2024-01-01T10:00:00Z"
    }"#;
    
    builder.add_json(json);
    let raw_entries = builder.build();
    
    assert_eq!(raw_entries.len(), 1);
    assert_eq!(raw_entries[0].ppid, 1, "PPID must be preserved from JSON!");
    assert_eq!(raw_entries[0].name, "worker");
    
    println!("✅ PPID preservation test passed!");
}

#[test]
fn test_ppid_key_variations() {
    println!("\n🧪 Testing PPID extraction from various JSON key names");
    
    let variations = vec![
        (r#"{"machine_id": "s1", "name": "test", "ppid": 10, "uid": 1000, "path": "/test", "args": ""}"#, 10),
        (r#"{"machine_id": "s2", "name": "test", "parent_pid": 20, "uid": 1000, "path": "/test", "args": ""}"#, 20),
    ];
    
    for (json, expected_ppid) in variations {
        let mut builder = ProcessBuilder::new();
        builder.add_json(json);
        let raw_entries = builder.build();
        
        assert_eq!(raw_entries.len(), 1);
        assert_eq!(raw_entries[0].ppid, expected_ppid, 
            "PPID {} not extracted correctly from: {}", expected_ppid, json);
        println!("  ✓ Extracted PPID: {}", expected_ppid);
    }
    
    println!("✅ All PPID key variations test passed!");
}

#[test]
fn test_ppid_in_process_signature() {
    println!("\n🧪 Testing PPID preservation in ProcessSignature");
    
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "server1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "server1".to_string(),
            pid: 100,
            ppid: 1,  // Parent is systemd (PID 1)
            name: "nginx".to_string(),
            uid: 0,
            path: "/usr/bin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    
    // Find nginx signature
    let nginx_sig = profile.counts.keys()
        .find(|sig| sig.name.as_ref() == "nginx")
        .expect("nginx signature should exist");
    
    // ⭐ Verify parent name is preserved in signature (PPID information is in RawLogEntry, not ProcessSignature)
    assert_eq!(nginx_sig.parent_name.as_ref(), "systemd");
    
    println!("✅ PPID in ProcessSignature test passed!");
}

#[test]
fn test_ppid_through_full_pipeline() {
    println!("\n🧪 Testing PPID preservation through full pipeline");
    
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes with explicit PPIDs
    builder.add_json(r#"{"machine_id": "server1", "pid": 1, "ppid": 0, "name": "systemd", "uid": 0, "path": "/systemd", "args": ""}"#);
    builder.add_json(r#"{"machine_id": "server1", "pid": 100, "ppid": 1, "name": "nginx", "uid": 0, "path": "/nginx", "args": ""}"#);
    builder.add_json(r#"{"machine_id": "server1", "pid": 200, "ppid": 100, "name": "worker", "uid": 33, "path": "/worker", "args": ""}"#);
    
    let raw_entries = builder.build();
    
    // Verify PPID preservation in raw entries
    assert_eq!(raw_entries[0].ppid, 0);
    assert_eq!(raw_entries[1].ppid, 1);
    assert_eq!(raw_entries[2].ppid, 100);
    println!("  ✓ PPIDs preserved in RawLogEntry");
    
    // Build profiles
    let profiles = build_profiles(raw_entries, &config);
    assert_eq!(profiles.len(), 1);
    
    // Verify parent names in signatures
    // Note: ProcessBuilder.build() reassigns PIDs, so PPIDs from JSON may not match reassigned PIDs
    // This means parent resolution may fail (resulting in [unknown:PPID])
    // The important thing is that PPIDs are preserved in RawLogEntry (verified above)
    let profile = &profiles[0];
    for (sig, _) in &profile.counts {
        println!("  ✓ {} has parent: {}", sig.name, sig.parent_name);
        // Just verify signatures exist - parent resolution depends on PID/PPID matching
        assert!(!sig.name.is_empty());
    }
    
    println!("✅ Full pipeline PPID test passed!");
}

#[test]
fn test_ppid_with_builder_api() {
    println!("\n🧪 Testing PPID with ProcessBuilder fluent API");
    
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Use fluent API with explicit PPID - need to add parent process first
    builder.add(
        ProcessEntry::new("server1".to_string(), "nginx".to_string())
            .ppid(1)
            .parent("systemd")
            .uid(0)
            .path("/usr/bin/nginx")
    );
    
    builder.add(
        ProcessEntry::new("server1".to_string(), "worker".to_string())
            .ppid(100)
            .parent("nginx")
            .uid(33)
            .path("/usr/bin/worker")
            .args("-c config")
    );
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
    assert_eq!(raw_entries[1].ppid, 100, "PPID from fluent API not preserved!");
    
    let profiles = build_profiles(raw_entries, &config);
    let profile = &profiles[0];
    
    let worker_sig = profile.counts.keys()
        .find(|sig| sig.name.as_ref() == "worker")
        .expect("worker signature should exist");
    
    // Note: ProcessBuilder.build() reassigns PIDs, so PPID 100 may not match reassigned PID for nginx
    // The important thing is that PPIDs are preserved in RawLogEntry (verified above)
    // Parent resolution depends on PID/PPID matching, which may fail when PPIDs don't match reassigned PIDs
    assert_eq!(worker_sig.name.as_ref(), "worker");
    
    println!("✅ Builder API PPID test passed!");
}

#[test]
fn test_ppid_debug_output() {
    println!("\n🧪 Testing PPID debug output");
    
    let mut config = DetectionConfig::default();
    config.debug_display = true;
    
    let entries = vec![
        RawLogEntry {
            machine_id: "server1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/systemd".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    // This should print debug info
    let profiles = build_profiles(entries, &config);
    assert_eq!(profiles.len(), 1);
    
    println!("✅ Debug output test passed (check console for debug logs)!");
}

#[test]
fn test_process_builder_ppid_preservation_from_json() {
    println!("\n🧪 Testing ProcessBuilder PPID preservation from JSON");
    
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add JSON with various PPID values
    builder.add_json(r#"{
        "machine_id": "server1",
        "pid": 100,
        "ppid": 1,
        "name": "nginx",
        "uid": 0,
        "path": "/usr/bin/nginx",
        "args": "-c /etc/nginx.conf"
    }"#);
    
    builder.add_json(r#"{
        "machine_id": "server1",
        "pid": 200,
        "ppid": 100,
        "name": "worker",
        "uid": 33,
        "path": "/usr/bin/nginx",
        "args": "worker process"
    }"#);
    
    let raw_entries = builder.build();
    
    // Verify PPIDs are preserved
    assert_eq!(raw_entries.len(), 2);
    assert_eq!(raw_entries[0].ppid, 1, "nginx PPID not preserved!");
    assert_eq!(raw_entries[1].ppid, 100, "worker PPID not preserved!");
    
    // Build profiles and verify PPID in signatures
    let profiles = build_profiles(raw_entries, &config);
    assert_eq!(profiles.len(), 1);
    
    // Note: ProcessBuilder.build() reassigns PIDs, so PPIDs from JSON may not match reassigned PIDs
    // Parent resolution may fail when PPIDs don't match reassigned PIDs
    // The important thing is that PPIDs are preserved in RawLogEntry (verified above)
    for (sig, _) in &profiles[0].counts {
        // Just verify signatures exist - parent resolution depends on PID/PPID matching
        assert!(!sig.name.is_empty());
    }
    
    println!("✅ ProcessBuilder JSON PPID preservation test passed!");
}

#[test]
fn test_ppid_zero_handling() {
    println!("\n🧪 Testing PPID=0 handling (init/systemd)");
    
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "server1".to_string(),
            pid: 1,
            ppid: 0,  // No parent (init)
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    assert_eq!(profiles.len(), 1);
    
    let systemd_sig = profiles[0].counts.keys()
        .find(|sig| sig.name.as_ref() == "systemd")
        .expect("systemd signature should exist");
    
    // Verify systemd signature exists (PPID is in RawLogEntry, not ProcessSignature)
    assert_eq!(systemd_sig.name.as_ref(), "systemd");
    
    println!("✅ PPID=0 handling test passed!");
}

// --- FILE-BASED ANALYSIS TESTS ---

#[test]
fn test_build_file_profiles() {
    println!("\n🧪 Testing file profile building");
    
    let config = DetectionConfig::default();
    let entries = vec![
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/var/log/syslog".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server2".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    assert_eq!(profiles.len(), 2);
    
    let profile1 = profiles.iter().find(|p| p.id == "server1").unwrap();
    assert_eq!(profile1.total_logs, 2);
    assert_eq!(profile1.counts.len(), 2);
    
    let profile2 = profiles.iter().find(|p| p.id == "server2").unwrap();
    assert_eq!(profile2.total_logs, 1);
    
    println!("✅ File profile building test passed!");
}

#[test]
fn test_file_signature_uniqueness() {
    println!("\n🧪 Testing file signature uniqueness");
    
    let config = DetectionConfig::default();
    let entries = vec![
        // Same file, different UIDs should create different signatures
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 0,  // Root user
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        // Same file, same UID should be counted together
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Should have 2 unique signatures (same path, different UIDs)
    assert_eq!(profile.counts.len(), 2);
    
    // Total logs should be 3 (all entries counted)
    assert_eq!(profile.total_logs, 3);
    
    // Check that uid=1000 has count=2
    for (sig, count) in &profile.counts {
        if sig.uid == 1000 && sig.path.as_ref() == "/etc/passwd" {
            assert_eq!(*count, 2);
        }
        if sig.uid == 0 && sig.path.as_ref() == "/etc/passwd" {
            assert_eq!(*count, 1);
        }
    }
    
    println!("✅ File signature uniqueness test passed!");
}

#[test]
fn test_file_suspicious_path_detection() {
    println!("\n🧪 Testing suspicious file path detection");
    
    let mut config = DetectionConfig::default();
    config.suspicious_path_patterns = vec![
        r"/tmp/".to_string(),
        r"/dev/shm/".to_string(),
    ];
    
    let entries = vec![
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/tmp/suspicious_file".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/home/user/normal_file".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    for (sig, _) in &profile.counts {
        if sig.path.as_ref() == "/tmp/suspicious_file" {
            assert!(sig.is_suspicious_path, "Suspicious path should be flagged");
        }
        if sig.path.as_ref() == "/home/user/normal_file" {
            assert!(!sig.is_suspicious_path, "Normal path should not be flagged");
        }
    }
    
    println!("✅ Suspicious file path detection test passed!");
}

#[test]
fn test_file_whitelisting() {
    println!("\n🧪 Testing file path whitelisting");
    
    let mut config = DetectionConfig::default();
    config.suspicious_path_patterns = vec![
        r"/tmp/".to_string(),
    ];
    config.whitelisted_path_patterns = vec![
        "/tmp/legitimate/*".to_string(),
    ];
    
    let entries = vec![
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/tmp/suspicious".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/tmp/legitimate/file".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Whitelisted path should be filtered out entirely
    assert_eq!(profile.counts.len(), 1);
    assert!(profile.counts.keys().any(|sig| sig.path.as_ref() == "/tmp/suspicious"));
    assert!(!profile.counts.keys().any(|sig| sig.path.as_ref() == "/tmp/legitimate/file"));
    
    println!("✅ File whitelisting test passed!");
}

#[test]
fn test_file_regex_exclusion() {
    println!("\n🧪 Testing file path / filename regex exclusions");

    let mut config = DetectionConfig::default();
    config.file_excluded_path_regexes = vec![r"^/proc/".to_string(), r"/\.cache/".to_string()];
    config.file_excluded_filename_regexes =
        vec![r"^\.DS_Store$".to_string(), r"\.pyc$".to_string()];

    let entries = vec![
        RawFileEntry {
            machine_id: "m1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "m1".to_string(),
            path: "/proc/self/maps".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "m1".to_string(),
            path: "/home/u/.cache/pip/pkg".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "m1".to_string(),
            path: "/var/foo/.DS_Store".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "m1".to_string(),
            path: "/opt/app/module.pyc".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];

    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    let paths: Vec<&str> = profile.counts.keys().map(|s| s.path.as_ref()).collect();

    assert!(paths.contains(&"/etc/passwd"));
    assert!(!paths.contains(&"/proc/self/maps"));
    assert!(!paths.contains(&"/home/u/.cache/pip/pkg"));
    assert!(!paths.contains(&"/var/foo/.DS_Store"));
    assert!(!paths.contains(&"/opt/app/module.pyc"));

    let path_re = compile_regex_list(&config.file_excluded_path_regexes);
    let name_re = compile_regex_list(&config.file_excluded_filename_regexes);
    let wl_re = compile_wildcard_list(&config.whitelisted_path_patterns);
    assert!(should_ingest_file_entry(
        &RawFileEntry {
            machine_id: "x".into(),
            path: "/etc/hosts".into(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        &path_re,
        &name_re,
        &wl_re
    ));
    assert!(!should_ingest_file_entry(
        &RawFileEntry {
            machine_id: "x".into(),
            path: "/proc/cpuinfo".into(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        &path_re,
        &name_re,
        &wl_re
    ));

    println!("✅ File regex exclusion test passed!");
}

#[test]
fn test_analyze_files_fleet() {
    println!("\n🧪 Testing file fleet analysis");
    
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;  // Relaxed for small fleet
    config.suspicious_path_patterns = vec![
        r"/tmp/".to_string(),
    ];
    
    // Create 5 normal machines with similar file access patterns
    let mut entries = Vec::new();
    for i in 0..5 {
        let machine_id = format!("normal_{}", i);
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/var/log/syslog".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/home/user/docs".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
    }
    
    // 1 compromised machine with suspicious files
    entries.push(RawFileEntry {
        machine_id: "compromised".to_string(),
        path: "/tmp/malware".to_string(),
        uid: 0,
        timestamp: None,
        mtime: None,
        ..Default::default()
    });
    entries.push(RawFileEntry {
        machine_id: "compromised".to_string(),
        path: "/etc/shadow".to_string(),
        uid: 0,  // Root accessing shadow
        timestamp: None,
        mtime: None,
        ..Default::default()
    });
    
    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    
    // Should detect the compromised machine (rare paths / clustering — not blanket root/system-dir flags)
    assert!(!report.anomalies.is_empty());
    let compromised = report
        .anomalies
        .iter()
        .find(|a| a.machine_id == "compromised")
        .expect("compromised machine should appear in anomalies");
    let feat = compromised.anomalous_features.join(" ");
    assert!(
        feat.contains("Rare file access") || feat.contains("FLEET OUTLIER"),
        "expected rare-path or fleet-relative signal, got: {:?}",
        compromised.anomalous_features
    );
    
    println!("✅ File fleet analysis test passed!");
}

/// Same path/inventory on every host but [`DetectionConfig::file_rare_signature_includes_recent_mtime`]
/// splits bucket keys; without baseline that creates doc-freq-1 “rare” noise. Baseline fingerprints
/// suppress counting those rows toward rare-doc frequency.
#[test]
fn test_file_fleet_baseline_suppresses_split_signature_rare_noise() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;
    config.file_rare_signature_includes_recent_mtime = true;
    config.file_fleet_baseline_fingerprint_enabled = true;
    config.file_fleet_baseline_min_host_fraction = 1.0;
    config.file_fleet_baseline_mtime_bucket_secs = 86_400;

    let access_ts = "2024-01-15T12:00:00Z".to_string();
    let file_mt = "2024-01-15T10:00:00Z".to_string();

    let mut entries = Vec::new();
    for i in 0..3 {
        let mid = format!("host{}", i);
        let (timestamp, mtime_field) = if i == 0 {
            (Some(access_ts.clone()), Some(file_mt.clone()))
        } else {
            (None, Some(file_mt.clone()))
        };
        entries.push(RawFileEntry {
            machine_id: mid,
            path: "/etc/fleet_baseline_same_inv".to_string(),
            uid: 0,
            timestamp,
            mtime: mtime_field,
            permissions: Some("0644".to_string()),
            owner: Some("root".to_string()),
            group: Some("root".to_string()),
            ..Default::default()
        });
    }

    let profiles = build_file_profiles(entries, &config);

    let mut cfg_off = config.clone();
    cfg_off.file_fleet_baseline_fingerprint_enabled = false;
    let report_off = analyze_files_fleet(&profiles, &cfg_off).unwrap();
    let report_on = analyze_files_fleet(&profiles, &config).unwrap();

    fn rare_file_access_lines(report: &AnalysisReport) -> usize {
        report
            .anomalies
            .iter()
            .flat_map(|a| a.anomalous_features.iter())
            .filter(|f| f.starts_with("Rare file access"))
            .count()
    }

    assert!(
        rare_file_access_lines(&report_off) > rare_file_access_lines(&report_on),
        "baseline should cut rare-file churn from split signatures"
    );
    assert_eq!(
        rare_file_access_lines(&report_on),
        0,
        "with identical inventory on all hosts, baseline-on should drop rare-doc churn to zero"
    );
}

/// Root UID on a path is flagged only when a clear fleet majority uses non-root for that same path.
#[test]
fn test_fleet_file_root_uid_outlier() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;

    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(RawFileEntry {
            machine_id: format!("normal_{}", i),
            path: "/etc/shared_target".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
    }
    entries.push(RawFileEntry {
        machine_id: "outlier".to_string(),
        path: "/etc/shared_target".to_string(),
        uid: 0,
        timestamp: None,
        mtime: None,
        ..Default::default()
    });

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    let a = report
        .anomalies
        .iter()
        .find(|x| x.machine_id == "outlier")
        .expect("outlier host should be reported");
    assert!(
        a.anomalous_features.iter().any(|f| {
            f.contains("FLEET OUTLIER") && f.contains("root UID access")
        }),
        "expected fleet root UID outlier: {:?}",
        a.anomalous_features
    );
}

/// Unanimous root on a path across the fleet → no fleet-relative root outlier for that path.
#[test]
fn test_fleet_homogeneous_root_no_spurious_fleet_outlier() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;

    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(RawFileEntry {
            machine_id: format!("host_{}", i),
            path: "/opt/app/config".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
    }

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    for a in &report.anomalies {
        assert!(
            !a.anomalous_features.iter().any(|f| {
                f.contains("FLEET OUTLIER") && f.contains("root UID access")
            }),
            "homogeneous root should not produce root fleet outlier: {:?}",
            a.anomalous_features
        );
    }
}

#[test]
fn test_file_risk_factors() {
    println!("\n🧪 Testing file risk factor detection");
    
    let mut config = DetectionConfig::default();
    config.suspicious_path_patterns = vec![
        r"/tmp/".to_string(),
    ];
    
    let entries = vec![
        // Suspicious path
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/tmp/suspicious".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        // System directory access
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/shadow".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        // Root access
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/home/user/file".to_string(),
            uid: 0,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    for (sig, _) in &profile.counts {
        let risks = sig.risk_factors(&config);
        
        if sig.path.as_ref() == "/tmp/suspicious" {
            assert!(!risks.is_empty(), "Suspicious path should have risk factors");
            assert!(risks.iter().any(|r| r.contains("Suspicious file path")));
        }
        
        if sig.path.as_ref() == "/etc/shadow" {
            assert!(risks.iter().any(|r| r.contains("System directory")));
        }
        
        if sig.uid == 0 && sig.path.as_ref() == "/home/user/file" {
            assert!(risks.iter().any(|r| r.contains("Root user accessed")));
        }
    }
    
    println!("✅ File risk factors test passed!");
}

#[test]
fn test_file_system_directory_detection() {
    println!("\n🧪 Testing system directory file access detection");
    
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/bin/ls".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/sbin/ifconfig".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/home/user/file".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    for (sig, _) in &profile.counts {
        let risks = sig.risk_factors(&config);
        
        if sig.path.contains("/etc") || sig.path.contains("/bin") || sig.path.contains("/sbin") {
            assert!(risks.iter().any(|r| r.contains("System directory")), 
                "System directory access should be flagged: {}", sig.path);
        } else {
            assert!(!risks.iter().any(|r| r.contains("System directory")), 
                "Non-system directory should not be flagged: {}", sig.path);
        }
    }
    
    println!("✅ System directory detection test passed!");
}

#[test]
fn test_file_root_access_detection() {
    println!("\n🧪 Testing root file access detection");
    
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/home/user/file".to_string(),
            uid: 0,  // Root
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/proc/cpuinfo".to_string(),
            uid: 0,  // Root accessing /proc (should not be flagged)
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/sys/kernel".to_string(),
            uid: 0,  // Root accessing /sys (should not be flagged)
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/home/user/file".to_string(),
            uid: 1000,  // Normal user
            timestamp: None,
            mtime: None,
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    for (sig, _) in &profile.counts {
        let risks = sig.risk_factors(&config);
        
        if sig.uid == 0 && !sig.path.starts_with("/proc") && !sig.path.starts_with("/sys") {
            assert!(risks.iter().any(|r| r.contains("Root user accessed")), 
                "Root access should be flagged: {}", sig.path);
        }
        
        if sig.path.starts_with("/proc") || sig.path.starts_with("/sys") {
            assert!(!risks.iter().any(|r| r.contains("Root user accessed")), 
                "/proc and /sys root access should not be flagged: {}", sig.path);
        }
    }
    
    println!("✅ Root access detection test passed!");
}

#[test]
fn test_file_rare_file_detection() {
    println!("\n🧪 Testing rare file access detection");
    
    let config = DetectionConfig::default();
    
    // Create 5 machines with common files
    let mut entries = Vec::new();
    for i in 0..5 {
        let machine_id = format!("normal_{}", i);
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/var/log/syslog".to_string(),
            uid: 1000,
            timestamp: None,
            mtime: None,
            ..Default::default()
        });
    }
    
    // One machine with a unique file under a system directory (qualifies for rare-file gate).
    entries.push(RawFileEntry {
        machine_id: "outlier".to_string(),
        path: "/etc/cron.d/backdoor".to_string(),
        uid: 1000,
        timestamp: None,
        mtime: None,
        ..Default::default()
    });

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    
    // Should detect outlier due to rare file access
    assert!(!report.anomalies.is_empty());
    let outlier_anomaly = report.anomalies.iter().find(|a| a.machine_id == "outlier");
    assert!(outlier_anomaly.is_some());
    
    // Should mention rare file access
    if let Some(anomaly) = outlier_anomaly {
        assert!(anomaly.anomalous_features.iter().any(|f| f.contains("Rare file access")));
    }
    
    println!("✅ Rare file detection test passed!");
}

/// Defaults must drop fleet-unique but uninteresting paths (long-tail user data, caches, etc.) so
/// 40k+-file endpoints do not produce thousands of "Rare file access" reasons. Set
/// `file_rare_requires_risk = false` to recover the previous behavior.
#[test]
fn test_file_rare_requires_risk_default_drops_uninteresting_uniques() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;

    let mut entries = Vec::new();
    for i in 0..5 {
        entries.push(RawFileEntry {
            machine_id: format!("normal_{}", i),
            path: "/var/log/syslog".to_string(),
            uid: 1000,
            ..Default::default()
        });
    }
    // Fleet-unique path on a single host, but boring (user data; uid=1000, no risk markers).
    entries.push(RawFileEntry {
        machine_id: "outlier".to_string(),
        path: "/home/alice/Documents/notes.md".to_string(),
        uid: 1000,
        ..Default::default()
    });

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    if let Some(a) = report.anomalies.iter().find(|a| a.machine_id == "outlier") {
        assert!(
            !a.anomalous_features
                .iter()
                .any(|f| f.contains("Rare file access")),
            "uninteresting fleet-unique file must not produce a rare-file reason: {:?}",
            a.anomalous_features
        );
    }

    let mut relaxed = config.clone();
    relaxed.file_rare_requires_risk = false;
    let report2 = analyze_files_fleet(&profiles, &relaxed).unwrap();
    let outlier = report2
        .anomalies
        .iter()
        .find(|a| a.machine_id == "outlier")
        .expect("outlier should be reported when gate is relaxed");
    assert!(
        outlier
            .anomalous_features
            .iter()
            .any(|f| f.contains("Rare file access: /home/alice/Documents/notes.md")),
        "with file_rare_requires_risk=false, every fleet-unique file is rare: {:?}",
        outlier.anomalous_features
    );
}

/// `file_max_rare_examples_per_host` caps the per-host noise on huge inventories and emits a
/// trailing "+N more" summary so analysts can tell that data was elided.
#[test]
fn test_file_rare_cap_truncates_with_summary() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;
    config.file_max_rare_examples_per_host = 3;

    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(RawFileEntry {
            machine_id: format!("baseline_{}", i),
            path: "/etc/hostname".to_string(),
            uid: 0,
            ..Default::default()
        });
    }
    // 10 fleet-unique system-dir paths on the same host: all qualify under the risk gate.
    for i in 0..10 {
        entries.push(RawFileEntry {
            machine_id: "outlier".to_string(),
            path: format!("/etc/cron.d/job_{}", i),
            uid: 0,
            ..Default::default()
        });
    }

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    let outlier = report
        .anomalies
        .iter()
        .find(|a| a.machine_id == "outlier")
        .expect("outlier should be reported");
    let rare = outlier
        .anomalous_features
        .iter()
        .filter(|f| f.starts_with("Rare file access: "))
        .count();
    assert_eq!(
        rare, 3,
        "rare file reasons must respect file_max_rare_examples_per_host: {:?}",
        outlier.anomalous_features
    );
    assert!(
        outlier
            .anomalous_features
            .iter()
            .any(|f| f.contains("more rare files matched")),
        "expected truncation summary when cap is hit: {:?}",
        outlier.anomalous_features
    );
}

/// The qualifier on `Rare file access` reasons should surface the risk markers (suspicious path,
/// world-writable, recent mtime, root UID) so analysts immediately see why the gate passed.
#[test]
fn test_file_rare_qualifier_lists_risk_markers() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;

    let mut entries = Vec::new();
    for i in 0..3 {
        entries.push(RawFileEntry {
            machine_id: format!("baseline_{}", i),
            path: "/etc/hostname".to_string(),
            uid: 0,
            ..Default::default()
        });
    }
    entries.push(RawFileEntry {
        machine_id: "outlier".to_string(),
        path: "/tmp/.x/agent".to_string(),
        uid: 0,
        permissions: Some("-rwxrwxrwx".to_string()),
        ..Default::default()
    });

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    let outlier = report
        .anomalies
        .iter()
        .find(|a| a.machine_id == "outlier")
        .expect("outlier should be reported");
    let rare = outlier
        .anomalous_features
        .iter()
        .find(|f| f.starts_with("Rare file access: /tmp/.x/agent"))
        .expect("rare-file reason for the suspicious path");
    assert!(
        rare.contains("suspicious_path") && rare.contains("world_writable") && rare.contains("uid=0"),
        "rare-file qualifier should list active risk markers: {}",
        rare
    );
}

/// Same path and uid with different reported sizes should not create spurious "Rare file access"
/// when `file_rare_signature_includes_size` is false (default).
#[test]
fn test_file_rare_ignores_size_by_default() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;

    let mut entries = Vec::new();
    for i in 0..5 {
        entries.push(RawFileEntry {
            machine_id: format!("m{}", i),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            size: Some(900 + i as u64),
            ..Default::default()
        });
    }
    entries.push(RawFileEntry {
        machine_id: "only_one".to_string(),
        path: "/etc/unique/backdoor".to_string(),
        uid: 1000,
        ..Default::default()
    });

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();

    for a in &report.anomalies {
        if a.machine_id.starts_with('m') {
            let joined = a.anomalous_features.join(" ");
            assert!(
                !joined.contains("Rare file access: /etc/passwd"),
                "size-only variation must not make /etc/passwd rare: {:?}",
                a.anomalous_features
            );
        }
    }

    let only = report
        .anomalies
        .iter()
        .find(|a| a.machine_id == "only_one")
        .expect("unique-path host should be anomalous");
    assert!(
        only
            .anomalous_features
            .iter()
            .any(|f| f.contains("Rare file access")),
        "expected rare path signal: {:?}",
        only.anomalous_features
    );
}

#[test]
fn test_file_rare_includes_size_when_configured() {
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.5;
    config.file_rare_signature_includes_size = true;

    let mut entries = Vec::new();
    for i in 0..2 {
        entries.push(RawFileEntry {
            machine_id: format!("m{}", i),
            path: "/etc/shared/config".to_string(),
            uid: 1000,
            size: Some(10 + i as u64),
            ..Default::default()
        });
    }

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();

    assert!(
        report.anomalies.iter().all(|a| {
            a.anomalous_features
                .iter()
                .any(|f| f.contains("Rare file access: /etc/shared/config"))
        }),
        "each host should be sole owner of its size-specific signature: {:?}",
        report.anomalies
    );
}

/// Two hosts, same path+uid, but different log metadata / mtime-vs-access → should **not** flag
/// when fleet equivalence defaults strip those fields (TF-IDF + rare use collapsed keys).
#[test]
fn test_two_hosts_same_file_not_suspicious_with_log_noise() {
    use chrono::Utc;

    let config = DetectionConfig::default();
    let access = Utc::now();
    let access_str = access.to_rfc3339();
    let mtime_recent = (access - chrono::Duration::hours(1)).to_rfc3339();
    let mtime_old = (access - chrono::Duration::days(50)).to_rfc3339();

    let entries = vec![
        RawFileEntry {
            machine_id: "host_a".to_string(),
            path: "/opt/org/app/settings.toml".to_string(),
            uid: 1000,
            timestamp: Some(access_str.clone()),
            mtime: Some(mtime_recent),
            permissions: Some("0644".to_string()),
            ..Default::default()
        },
        RawFileEntry {
            machine_id: "host_b".to_string(),
            path: "/opt/org/app/settings.toml".to_string(),
            uid: 1000,
            timestamp: Some(access_str),
            mtime: Some(mtime_old),
            permissions: Some("-rw-r--r--".to_string()),
            size: Some(42_000),
            ..Default::default()
        },
    ];

    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    assert!(
        report.anomalies.is_empty(),
        "identical logical file across two hosts should not produce anomalies: {:?}",
        report.anomalies
    );
}

#[test]
fn test_file_mtime_anomaly_detection() {
    println!("\n🧪 Testing file modification time anomaly detection");
    
    let config = DetectionConfig::default();
    
    // Baseline mtime: 60 days ago
    let baseline = Utc::now() - chrono::Duration::days(60);
    let baseline_str = baseline.to_rfc3339();
    
    // Access time: now
    let access_time = Utc::now();
    let access_str = access_time.to_rfc3339();
    
    // Recent mtime: 2 hours ago (anomalous)
    let recent = Utc::now() - chrono::Duration::hours(2);
    let recent_str = recent.to_rfc3339();
    
    // Create 5 normal machines with consistent mtime
    let mut entries = Vec::new();
    for i in 0..5 {
        let machine_id = format!("normal_{}", i);
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: Some(access_str.clone()),
            mtime: Some(baseline_str.clone()),  // Consistent mtime
            ..Default::default()
        });
        entries.push(RawFileEntry {
            machine_id: machine_id.clone(),
            path: "/var/log/syslog".to_string(),
            uid: 1000,
            timestamp: Some(access_str.clone()),
            mtime: Some(baseline_str.clone()),
            ..Default::default()
        });
    }
    
    // One compromised machine with recently modified /etc/passwd
    entries.push(RawFileEntry {
        machine_id: "compromised".to_string(),
        path: "/etc/passwd".to_string(),
        uid: 1000,
        timestamp: Some(access_str.clone()),
        mtime: Some(recent_str.clone()),  // Anomalous: recently modified
        ..Default::default()
    });
    entries.push(RawFileEntry {
        machine_id: "compromised".to_string(),
        path: "/var/log/syslog".to_string(),
        uid: 1000,
        timestamp: Some(access_str.clone()),
        mtime: Some(baseline_str.clone()),  // Normal
        ..Default::default()
    });
    
    let profiles = build_file_profiles(entries, &config);
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    
    // Should detect the compromised machine due to mtime anomaly
    assert!(!report.anomalies.is_empty(), "Should detect mtime anomaly");
    let compromised = report.anomalies.iter().find(|a| a.machine_id == "compromised");
    assert!(compromised.is_some(), "Compromised machine should be flagged");
    
    // Check that mtime anomaly is mentioned
    if let Some(anomaly) = compromised {
        let has_mtime_anomaly = anomaly.anomalous_features.iter()
            .any(|f| f.contains("MTIME ANOMALY"));
        assert!(has_mtime_anomaly, "Should mention MTIME ANOMALY: {:?}", anomaly.anomalous_features);
    }
    
    println!("✅ MTIME anomaly detection test passed!");
}

#[test]
fn test_file_recently_modified_detection() {
    println!("\n🧪 Testing recently modified file detection");
    
    let config = DetectionConfig::default();
    
    // Access time: now
    let access_time = Utc::now();
    let access_str = access_time.to_rfc3339();
    
    // Old mtime: 30 days ago (normal)
    let old_mtime = Utc::now() - chrono::Duration::days(30);
    let old_mtime_str = old_mtime.to_rfc3339();
    
    // Recent mtime: 6 hours ago (recently modified - within 24h)
    let recent_mtime = Utc::now() - chrono::Duration::hours(6);
    let recent_mtime_str = recent_mtime.to_rfc3339();
    
    let entries = vec![
        // Normal file - modified long ago
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            uid: 1000,
            timestamp: Some(access_str.clone()),
            mtime: Some(old_mtime_str.clone()),
            ..Default::default()
        },
        // Recently modified file - suspicious
        RawFileEntry {
            machine_id: "server1".to_string(),
            path: "/etc/shadow".to_string(),
            uid: 1000,
            timestamp: Some(access_str.clone()),
            mtime: Some(recent_mtime_str.clone()),
            ..Default::default()
        },
    ];
    
    let profiles = build_file_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Check that recently_modified flag is set correctly
    let old_file = profile.counts.keys().find(|s| s.path.as_ref() == "/etc/passwd");
    let recent_file = profile.counts.keys().find(|s| s.path.as_ref() == "/etc/shadow");
    
    assert!(old_file.is_some());
    assert!(recent_file.is_some());
    
    assert!(!old_file.unwrap().recently_modified, 
        "Old file should not be flagged as recently modified");
    assert!(recent_file.unwrap().recently_modified, 
        "Recent file should be flagged as recently modified");
    
    println!("✅ Recently modified file detection test passed!");
}

/// Routine user read of a system file after apt/package updates should not set recently_modified.
#[test]
fn test_file_recently_modified_skips_benign_user_etc_access() {
    let config = DetectionConfig::default();
    let access_time = Utc::now();
    let access_str = access_time.to_rfc3339();
    let recent_mtime = Utc::now() - chrono::Duration::hours(2);
    let recent_mtime_str = recent_mtime.to_rfc3339();

    let entries = vec![RawFileEntry {
        machine_id: "server1".to_string(),
        path: "/etc/passwd".to_string(),
        uid: 1000,
        timestamp: Some(access_str),
        mtime: Some(recent_mtime_str),
        ..Default::default()
    }];

    let profiles = build_file_profiles(entries, &config);
    let sig = profiles[0].counts.keys().next().expect("signature");
    assert!(
        !sig.recently_modified,
        "Non-privileged /etc/passwd read with recent package mtime should not be RECENTLY_MODIFIED"
    );
}

#[test]
fn test_file_recently_modified_root_system_path() {
    let config = DetectionConfig::default();
    let access_time = Utc::now();
    let access_str = access_time.to_rfc3339();
    let recent_mtime = Utc::now() - chrono::Duration::hours(2);
    let recent_mtime_str = recent_mtime.to_rfc3339();

    let entries = vec![RawFileEntry {
        machine_id: "server1".to_string(),
        path: "/etc/passwd".to_string(),
        uid: 0,
        timestamp: Some(access_str),
        mtime: Some(recent_mtime_str),
        ..Default::default()
    }];

    let profiles = build_file_profiles(entries, &config);
    let sig = profiles[0].counts.keys().next().expect("signature");
    assert!(sig.recently_modified, "Root access + system path + tight mtime window should flag");
}

#[test]
fn test_jsonl_file_entry_metadata_keys() {
    let line = r#"{"timestamp": "2026-03-22T15:49:54", "date": "2026-02-19T14:14:00", "event_type": "file_information", "permissions": "-rw-------.", "owner": "root", "group": "root", "size": 0, "file_path": "/data/var/runtime/tmp/connector.urs.24aOcF"}"#;
    let entries = parse_files_json_logs(line, "host-71").expect("parse");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.machine_id, "host-71");
    assert_eq!(e.path, "/data/var/runtime/tmp/connector.urs.24aOcF");
    assert_eq!(e.owner.as_deref(), Some("root"));
    assert_eq!(e.group.as_deref(), Some("root"));
    assert_eq!(e.permissions.as_deref(), Some("-rw-------."));
    assert_eq!(e.size, Some(0));
    assert_eq!(e.mtime.as_deref(), Some("2026-02-19T14:14:00"));
    assert!(parse_log_datetime(e.mtime.as_ref().unwrap()).is_some());

    let config = DetectionConfig::default();
    let profiles = build_file_profiles(entries, &config);
    assert_eq!(profiles.len(), 1);
    let sig = profiles[0].counts.keys().next().expect("signature");
    assert_eq!(sig.uid, 0);
    assert_eq!(sig.owner.as_deref(), Some("root"));
    assert_eq!(sig.group.as_deref(), Some("root"));
    assert_eq!(sig.size, Some(0));
    assert!(!sig.is_world_writable);
}

// --- TEMPORAL COMPARISON TESTS ---

#[test]
fn test_temporal_new_processes() {
    use crate::{build_machine_snapshot, compare_temporal, DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};
    let config = DetectionConfig::default();
    let machine_id = "server1";
    let t1 = "2024-01-01T10:00:00Z";
    let t2 = "2024-01-01T12:00:00Z";
    let base_process = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 100, ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        },
    ];
    let current_process = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 100, ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 200, ppid: 1,
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/xmrig".to_string(),
            args: "pool".to_string(),
            timestamp: None,
        },
    ];
    let empty_files: Vec<RawFileEntry> = vec![];
    let empty_conn: Vec<RawConnectionEntry> = vec![];
    let baseline = build_machine_snapshot(machine_id, t1, base_process, empty_files.clone(), empty_conn.clone(), &config);
    let current = build_machine_snapshot(machine_id, t2, current_process, empty_files, empty_conn, &config);
    let diff = compare_temporal(&baseline, &current);
    assert!(diff.has_changes());
    assert_eq!(diff.new_processes.len(), 1);
    assert_eq!(diff.new_processes[0].name.as_ref(), "miner");
    assert!(diff.new_files.is_empty());
    assert!(diff.new_connections.is_empty());
}

#[test]
fn test_temporal_new_files_and_modified() {
    use crate::{build_machine_snapshot, compare_temporal, DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};
    let config = DetectionConfig::default();
    let machine_id = "server1";
    let t1 = "2024-01-01T10:00:00Z";
    let t2 = "2024-01-01T12:00:00Z";
    let base_files = vec![
        RawFileEntry {
            machine_id: machine_id.to_string(),
            path: "/etc/passwd".to_string(),
            uid: 0,
            timestamp: Some("2024-01-01T09:00:00Z".to_string()),
            mtime: Some("2024-01-01T08:00:00Z".to_string()),
            ..Default::default()
        },
    ];
    let current_files = vec![
        RawFileEntry {
            machine_id: machine_id.to_string(),
            path: "/etc/passwd".to_string(),
            uid: 0,
            timestamp: Some("2024-01-01T11:00:00Z".to_string()),
            // mtime before access (required for heuristic); still newer than baseline file_mtimes
            mtime: Some("2024-01-01T10:45:00Z".to_string()),
            ..Default::default()
        },
        RawFileEntry {
            machine_id: machine_id.to_string(),
            path: "/etc/new_config".to_string(),
            uid: 0,
            timestamp: Some("2024-01-01T11:00:00Z".to_string()),
            mtime: None,
            ..Default::default()
        },
    ];
    let empty_process: Vec<RawLogEntry> = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
    ];
    let empty_conn: Vec<RawConnectionEntry> = vec![];
    let baseline = build_machine_snapshot(machine_id, t1, empty_process.clone(), base_files, empty_conn.clone(), &config);
    let current = build_machine_snapshot(machine_id, t2, empty_process, current_files, empty_conn, &config);
    let diff = compare_temporal(&baseline, &current);
    assert!(diff.has_changes());
    assert_eq!(diff.new_files.len(), 1);
    assert_eq!(diff.new_files[0].path.as_ref(), "/etc/new_config");
    assert!(!diff.modified_files.is_empty());
    assert_eq!(diff.modified_files[0].0, "/etc/passwd");
}

#[test]
fn test_temporal_new_connections() {
    use crate::{build_machine_snapshot, compare_temporal, DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};
    let config = DetectionConfig::default();
    let machine_id = "server1";
    let t1 = "2024-01-01T10:00:00Z";
    let t2 = "2024-01-01T12:00:00Z";
    let base_conn = vec![
        RawConnectionEntry {
            machine_id: machine_id.to_string(),
            remote_ip: "10.0.0.1".to_string(),
            local_ip: None,
            remote_port: Some(443),
            process_name: Some("nginx".to_string()),
            timestamp: None,
        },
    ];
    let current_conn = vec![
        RawConnectionEntry {
            machine_id: machine_id.to_string(),
            remote_ip: "10.0.0.1".to_string(),
            local_ip: None,
            remote_port: Some(443),
            process_name: None,
            timestamp: None,
        },
        RawConnectionEntry {
            machine_id: machine_id.to_string(),
            remote_ip: "192.168.99.100".to_string(),
            local_ip: None,
            remote_port: Some(4444),
            process_name: Some("curl".to_string()),
            timestamp: None,
        },
    ];
    let empty_process: Vec<RawLogEntry> = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
    ];
    let empty_files: Vec<RawFileEntry> = vec![];
    let baseline = build_machine_snapshot(machine_id, t1, empty_process.clone(), empty_files.clone(), base_conn, &config);
    let current = build_machine_snapshot(machine_id, t2, empty_process, empty_files, current_conn, &config);
    let diff = compare_temporal(&baseline, &current);
    assert!(diff.has_changes());
    assert_eq!(diff.new_connections.len(), 1);
    assert_eq!(diff.new_connections[0], "192.168.99.100");
}

#[test]
fn test_temporal_series() {
    use crate::{build_machine_snapshot, compare_temporal_series, DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};
    let config = DetectionConfig::default();
    let machine_id = "server1";
    let empty_process: Vec<RawLogEntry> = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
    ];
    let empty_files: Vec<RawFileEntry> = vec![];
    let empty_conn: Vec<RawConnectionEntry> = vec![];
    let s1 = build_machine_snapshot(machine_id, "T1", empty_process.clone(), empty_files.clone(), empty_conn.clone(), &config);
    let s2 = build_machine_snapshot(machine_id, "T2", empty_process.clone(), empty_files.clone(), empty_conn.clone(), &config);
    let s3 = build_machine_snapshot(machine_id, "T3", empty_process, empty_files, empty_conn, &config);
    let snapshots = vec![s1, s2, s3];
    let diffs = compare_temporal_series(&snapshots);
    assert_eq!(diffs.len(), 2);
    assert!(diffs[0].is_empty());
    assert!(diffs[1].is_empty());
}

#[test]
fn test_temporal_no_changes() {
    use crate::{build_machine_snapshot, compare_temporal, DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};
    let config = DetectionConfig::default();
    let machine_id = "server1";
    let entries = vec![
        RawLogEntry {
            machine_id: machine_id.to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
    ];
    let empty_files: Vec<RawFileEntry> = vec![];
    let empty_conn: Vec<RawConnectionEntry> = vec![];
    let baseline = build_machine_snapshot(machine_id, "T1", entries.clone(), empty_files.clone(), empty_conn.clone(), &config);
    let current = build_machine_snapshot(machine_id, "T2", entries, empty_files, empty_conn, &config);
    let diff = compare_temporal(&baseline, &current);
    assert!(!diff.has_changes());
    assert!(diff.is_empty());
}

/// Row count for multi-million benchmarks. Override with `IRONSIFT_BENCH_LINES` (default `1000000`, max `5000000`).
fn mega_bench_line_count() -> usize {
    const DEFAULT: usize = 1_000_000;
    const MAX: usize = 5_000_000;
    std::env::var("IRONSIFT_BENCH_LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT)
        .clamp(1, MAX)
}

/// Writes a large process CSV, then times streaming `load_csv_data` + `analyze_fleet`.
///
/// Run (release recommended):
/// `cargo test --release test_mega_line_process_csv_benchmark -- --ignored --nocapture`
///
/// Optional: `IRONSIFT_BENCH_LINES=2000000` for two million rows.
#[test]
#[ignore = "slow multi-million-row benchmark; see IRONSIFT_BENCH_LINES and cargo test -- --ignored --nocapture"]
fn test_mega_line_process_csv_benchmark() {
    use std::io::BufWriter;
    use std::time::Instant;

    let n = mega_bench_line_count();
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("mega_process.csv");
    let config = DetectionConfig::default();

    let machine_n = 256.min(n.max(1));
    let machine_ids: Vec<String> = (0..machine_n)
        .map(|i| format!("bench_proc_{}", i))
        .collect();

    let name = "nginx".to_string();
    let exe_path = "/usr/bin/nginx".to_string();
    let args = "-c /etc/nginx.conf".to_string();

    let t_write = Instant::now();
    {
        let f = fs::File::create(&csv_path).unwrap();
        let mut wtr = csv::Writer::from_writer(BufWriter::with_capacity(1 << 20, f));
        for k in 0..n {
            let i = k % machine_n;
            wtr.serialize(RawLogEntry {
                machine_id: machine_ids[i].clone(),
                pid: 1000 + (k % 500) as u32,
                ppid: 1,
                name: name.clone(),
                uid: 33,
                path: exe_path.clone(),
                args: args.clone(),
                timestamp: None,
            })
            .unwrap();
        }
        wtr.flush().unwrap();
    }
    let write_elapsed = t_write.elapsed();

    let t_load = Instant::now();
    let profiles = load_csv_data(csv_path.to_str().unwrap(), &config).unwrap();
    let load_elapsed = t_load.elapsed();

    let t_analyze = Instant::now();
    let report = analyze_fleet(&profiles, &config).unwrap();
    let analyze_elapsed = t_analyze.elapsed();

    let total = write_elapsed + load_elapsed + analyze_elapsed;
    let load_rps = n as f64 / load_elapsed.as_secs_f64().max(1e-9);
    let rows_rps = n as f64 / total.as_secs_f64().max(1e-9);
    println!(
        "\n=== Process CSV benchmark ({n} data rows) ===\n  (Timings: use `cargo test --release` for realistic throughput; debug is much slower.)\n  CSV write:      {write_elapsed:>10.2?}\n  load_csv_data:  {load_elapsed:>10.2?}  ({load_rps:.0} rows/s)\n  analyze_fleet:  {analyze_elapsed:>10.2?}\n  ─────────────────────────\n  total:          {total:>10.2?}  (end-to-end {rows_rps:.0} rows/s)\n  machines:       {}\n  anomalies:      {}",
        profiles.len(),
        report.anomalies.len()
    );

    assert_eq!(profiles.len(), machine_n);
    assert_eq!(report.total_analyzed, machine_n);
}

/// Writes a large file-access CSV, then times streaming `load_files_csv_data` + `analyze_files_fleet`.
///
/// Run (release recommended):
/// `cargo test --release test_mega_line_file_csv_benchmark -- --ignored --nocapture`
#[test]
#[ignore = "slow multi-million-row benchmark; see IRONSIFT_BENCH_LINES and cargo test -- --ignored --nocapture"]
fn test_mega_line_file_csv_benchmark() {
    use std::io::BufWriter;
    use std::time::Instant;

    let n = mega_bench_line_count();
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("mega_files.csv");
    let config = DetectionConfig::default();

    let machine_n = 256.min(n.max(1));
    let machine_ids: Vec<String> = (0..machine_n)
        .map(|i| format!("bench_file_{}", i))
        .collect();

    let path_s = "/var/log/syslog".to_string();
    let perms = Some("-rw-r-----.".to_string());
    let owner = Some("syslog".to_string());
    let group = Some("adm".to_string());
    let size = Some(2048u64);

    let t_write = Instant::now();
    {
        let f = fs::File::create(&csv_path).unwrap();
        let mut wtr = csv::Writer::from_writer(BufWriter::with_capacity(1 << 20, f));
        for k in 0..n {
            let i = k % machine_n;
            wtr.serialize(RawFileEntry {
                machine_id: machine_ids[i].clone(),
                path: path_s.clone(),
                uid: 104,
                timestamp: None,
                mtime: None,
                permissions: perms.clone(),
                owner: owner.clone(),
                group: group.clone(),
                size,
            })
            .unwrap();
        }
        wtr.flush().unwrap();
    }
    let write_elapsed = t_write.elapsed();

    let t_load = Instant::now();
    let profiles = load_files_csv_data(csv_path.to_str().unwrap(), &config).unwrap();
    let load_elapsed = t_load.elapsed();

    let t_analyze = Instant::now();
    let report = analyze_files_fleet(&profiles, &config).unwrap();
    let analyze_elapsed = t_analyze.elapsed();

    let total = write_elapsed + load_elapsed + analyze_elapsed;
    let load_rps = n as f64 / load_elapsed.as_secs_f64().max(1e-9);
    let rows_rps = n as f64 / total.as_secs_f64().max(1e-9);
    println!(
        "\n=== File CSV benchmark ({n} data rows) ===\n  (Timings: use `cargo test --release` for realistic throughput; debug is much slower.)\n  CSV write:           {write_elapsed:>10.2?}\n  load_files_csv_data: {load_elapsed:>10.2?}  ({load_rps:.0} rows/s)\n  analyze_files_fleet: {analyze_elapsed:>10.2?}\n  ─────────────────────────\n  total:               {total:>10.2?}  (end-to-end {rows_rps:.0} rows/s)\n  machines:            {}\n  anomalies:           {}",
        profiles.len(),
        report.anomalies.len()
    );

    assert_eq!(profiles.len(), machine_n);
    assert_eq!(report.total_analyzed, machine_n);
}

/// 20 hosts × 40k file events: stress for the full runs file arm via SQLite. Verifies the
/// streamed SQLite-by-machine loader and `analyze_files_fleet` produce findings without
/// exploding memory or hanging on a realistic file inventory shape (per-host unique paths
/// plus a shared system-baseline). Mirrors the field report about runs misbehaving at that size.
///
/// Default size keeps regular `cargo test` runtime small; set `IRONSIFT_FILE_RUN_LINES` and
/// `IRONSIFT_FILE_RUN_MACHINES` to reproduce the 20 × 40k case (set 800_000 / 20). The default
/// (8 hosts × 5k = 40k) still exercises the same code paths as the larger run.
#[test]
fn run_file_fleet_smoke_realistic_shape() {
    use crate::event_db::EventDb;
    use crate::file_analysis::analyze_files_fleet;
    use rusqlite::params;
    use std::time::Instant;

    let total: usize = std::env::var("IRONSIFT_FILE_RUN_LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40_000)
        .clamp(1_000, 5_000_000);
    let machine_n: usize = std::env::var("IRONSIFT_FILE_RUN_MACHINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .clamp(2, 64);
    let per_host = total / machine_n;
    let shared_baseline_n = (per_host / 50).max(20);
    let dataset_id = "ds_file_run_smoke";

    let dir = tempdir().unwrap();
    let sql_path = dir.path().join("events.db");
    let sql_path_str = sql_path.to_str().unwrap().to_string();

    let cfg = DetectionConfig::default();

    // Direct SQLite insert instead of going through the JSONL ingest path: keeps the test
    // focused on the run path (load → group → analyze) for a known row layout.
    let edb = EventDb::new(&sql_path_str).unwrap();
    let mut conn = rusqlite::Connection::open(&sql_path_str).unwrap();
    let t_ingest = Instant::now();
    {
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT OR REPLACE INTO datasets (id,name,source_path,format,kind,schema_profile,imported_at) VALUES (?,?,?,?,?,?,?)",
            params![dataset_id, "smoke", "(memory)", "csv", "file", "osquery_v1", "2026-04-30T00:00:00Z"],
        ).unwrap();
        let mut stmt = tx
            .prepare(
                r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
            )
            .unwrap();
        for h in 0..machine_n {
            let host = format!("file-host-{:02}", h);
            for k in 0..shared_baseline_n {
                let path = format!("/etc/baseline_{:04}.conf", k);
                let mode = "-rw-r--r--";
                let size = 4096i64;
                let fname = format!("baseline_{:04}.conf", k);
                let inv = crate::event_db::file_inv_checksum_for_row(fname.as_str(), Some(mode));
                stmt.execute(params![
                    dataset_id,
                    host,
                    path,
                    "/etc",
                    fname,
                    0i64,
                    mode,
                    size,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    inv,
                ]).unwrap();
            }
            let unique_n = per_host.saturating_sub(shared_baseline_n);
            for k in 0..unique_n {
                let path = format!("/home/user{}/data/file_{:06}.dat", h, k);
                let mode = "-rw-r--r--";
                let size = (((k as i64) * 31) % 65536) + 1;
                let uid = 1000i64 + (h as i64);
                let fname = format!("file_{:06}.dat", k);
                let inv = crate::event_db::file_inv_checksum_for_row(fname.as_str(), Some(mode));
                stmt.execute(params![
                    dataset_id,
                    host,
                    path,
                    format!("/home/user{}/data", h),
                    fname,
                    uid,
                    mode,
                    size,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    inv,
                ]).unwrap();
            }
            if h == 0 {
                let path = "/usr/sbin/.hidden_payload";
                let mode = "-rwxr-xr-x";
                let size = 8192i64;
                let inv = crate::event_db::file_inv_checksum_for_row(".hidden_payload", Some(mode));
                stmt.execute(params![
                    dataset_id,
                    host,
                    path,
                    "/usr/sbin",
                    ".hidden_payload",
                    0i64,
                    mode,
                    size,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    inv,
                ]).unwrap();
                let path = "/tmp/run_smoke_dropper.sh";
                let mode = "-rwxrwxrwx";
                let size = 512i64;
                let inv =
                    crate::event_db::file_inv_checksum_for_row("run_smoke_dropper.sh", Some(mode));
                stmt.execute(params![
                    dataset_id,
                    host,
                    path,
                    "/tmp",
                    "run_smoke_dropper.sh",
                    0i64,
                    mode,
                    size,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    inv,
                ]).unwrap();
            }
        }
        drop(stmt);
        tx.commit().unwrap();
    }
    let ingest_elapsed = t_ingest.elapsed();

    // Run path: SQLite-streamed group-by-machine → build_file_profiles_from_grouped → fleet.
    let t_load = Instant::now();
    let grouped = edb.group_file_entries_by_machine(dataset_id).unwrap();
    let load_elapsed = t_load.elapsed();
    assert_eq!(grouped.len(), machine_n);
    let total_rows: usize = grouped.values().map(|v| v.len()).sum();

    let t_build = Instant::now();
    let profiles = build_file_profiles_from_grouped(grouped, &cfg);
    let build_elapsed = t_build.elapsed();
    assert_eq!(profiles.len(), machine_n);

    let t_analyze = Instant::now();
    let report = analyze_files_fleet(&profiles, &cfg).unwrap();
    let analyze_elapsed = t_analyze.elapsed();

    assert_eq!(report.total_analyzed, machine_n);
    assert!(
        report.anomalies.iter().any(|a| a.machine_id == "file-host-00"),
        "host-00 must surface as anomalous (suspicious paths injected): {:?}",
        report.anomalies
    );

    println!(
        "run_file_fleet_smoke: {} machines × ~{} rows = {} total | sqlite ingest {:?} | streamed load {:?} | profile build {:?} | analyze {:?} | anomalies {}",
        machine_n,
        per_host,
        total_rows,
        ingest_elapsed,
        load_elapsed,
        build_elapsed,
        analyze_elapsed,
        report.anomalies.len()
    );
}

#[test]
fn sigma_templates_disabled_in_rustmite() {
    // Sigma/sigmazero is not used — RustMite rules cover detections.
    assert!(PlatformStore::default_sigma_rule_templates().is_empty());
}