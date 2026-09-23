use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::env;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Fixed seed so generated datasets and IronSift regression checks are reproducible.
const DATASET_RNG_SEED: u64 = 42;
use chrono::{Utc, Duration};
use serde_json::json;

use rustmite_sift::{RawLogEntry, RawFileEntry};

const NUM_MACHINES: u32 = 20;
const LOGS_PER_MACHINE: u32 = 100;

#[derive(Clone, Copy)]
enum OutputFormat {
    Csv,
    Json,
}

fn print_usage() {
    println!("Usage: generator [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --json    Generate JSON output (test_dataset.json)");
    println!("  --csv     Generate CSV output (test_dataset.csv) [default]");
    println!("  --files   Generate file access logs instead of process logs");
    println!("  --help    Show this help message");
    println!();
    println!("Examples:");
    println!("  generator           # Generate process CSV (default)");
    println!("  generator --json    # Generate process JSON");
    println!("  generator --files   # Generate file CSV");
    println!("  generator --files --json  # Generate file JSON");
    println!("  generator --csv     # Generate process CSV (explicit)");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let mut format = OutputFormat::Csv;
    let mut generate_files = false;
    
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--csv" => format = OutputFormat::Csv,
            "--files" => generate_files = true,
            "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                return Err("Invalid argument".into());
            }
        }
    }
    
    let (output_file, format_name) = match (format, generate_files) {
        (OutputFormat::Csv, false) => ("test_dataset.csv", "CSV"),
        (OutputFormat::Json, false) => ("test_dataset.json", "JSON"),
        (OutputFormat::Csv, true) => ("test_files_dataset.csv", "CSV"),
        (OutputFormat::Json, true) => ("test_files_dataset.json", "JSON"),
    };
    
    let data_type = if generate_files { "file access" } else { "process" };
    
    println!("{:=^60}", " IRONSIFT DATA GENERATOR ");
    println!();
    println!("Format: {}", format_name);
    println!("Type: {}", data_type);
    println!("Generating {} logs for {} machines...", 
        NUM_MACHINES * LOGS_PER_MACHINE, NUM_MACHINES);
    println!("Output: {}", output_file);
    println!();
    
    if generate_files {
        // Generate file access log entries
        let file_entries = generate_file_entries()?;
        
        // Write in the requested format
        match format {
            OutputFormat::Csv => write_files_csv(&file_entries, output_file)?,
            OutputFormat::Json => write_files_json(&file_entries, output_file)?,
        }
        
        println!();
        println!("✅ Done! Dataset written to '{}'", output_file);
        println!("   {} machines, {} total file access logs", NUM_MACHINES, file_entries.len());
        println!();
        print_file_detection_instructions(output_file);
    } else {
        // Generate process log entries (original code)
        let entries = generate_log_entries()?;
        
        // Write in the requested format
        match format {
            OutputFormat::Csv => write_csv(&entries, output_file)?,
            OutputFormat::Json => write_json(&entries, output_file)?,
        }
        
        println!();
        println!("✅ Done! Dataset written to '{}'", output_file);
        println!("   {} machines, {} total process logs", NUM_MACHINES, entries.len());
        println!();
        print_detection_instructions(output_file);
    }
    
    Ok(())
}

fn generate_log_entries() -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(DATASET_RNG_SEED);
    let mut entries = Vec::new();
    
    // Start time: 7 days ago
    let mut current_time = Utc::now() - Duration::days(7);

    // Define normal processes
    let normal_processes = vec![
        ("nginx", 100, "/usr/sbin/nginx", "-c /etc/nginx/nginx.conf", 33),
        ("sshd", 101, "/usr/sbin/sshd", "-D", 0),
        ("postgres", 102, "/usr/lib/postgresql/14/bin/postgres", "-D /var/lib/postgresql/data", 70),
        ("node", 103, "/usr/bin/node", "server.js", 1000),
        ("python3", 104, "/usr/bin/python3", "app.py", 1000),
        ("cron", 105, "/usr/sbin/cron", "-f", 0),
        ("dockerd", 106, "/usr/bin/dockerd", "-H fd://", 0),
        ("redis-server", 107, "/usr/bin/redis-server", "/etc/redis/redis.conf", 999),
        ("apache2", 108, "/usr/sbin/apache2", "-k start", 33),
        ("mysqld", 109, "/usr/sbin/mysqld", "--defaults-file=/etc/mysql/my.cnf", 999),
    ];

    // Attack scenarios
    // Note: These are test patterns designed to trigger ML detection via high entropy
    // They are NOT actual malicious code and won't trigger antivirus
    let miner_processes = [
        ("kworker", "/tmp/.X11-unix/kworker", "--config XkzL9s0f8Ha@2#mK --server pool.example.test:4444", 0),
        ("systemd", "/var/tmp/.cache/systemd", "--threads 8 --algo rx/0 --url test.pool.local:3333", 0),
        ("[kthreadd]", "/dev/shm/.config/worker", "--benchmark QpR5tY8uI2#kL --port 14444", 0),
    ];
    
    // Web shell test patterns (high entropy, not actual code)
    let web_shell_payloads = [
        "proc_handler(req_decode('aGVsbG8gd29ybGQ='));",
        "execute_dynamic($_REQUEST['q']);",
        "<?method invoke_runtime($_DATA['z']);?>",
        "runtime_call(decode_param('ZWNobyBzeXN0ZW0='));",
        "<?dynamic_invoke(uncompress(decode_b64('K0ktSgEA')));?>",
        "run_shell('cmd /c type secrets.txt | encode');",
    ];
    
    let privesc_processes = [
        ("node", "/home/appuser/.npm/node", "suspicious_test.js", 0),
        ("python3", "/tmp/setup.py", "install --unsafe", 0),
        ("bash", "/home/ubuntu/.bashrc.d/init", "", 0),
    ];
    
    let lateral_movement = [
        ("ssh", "/usr/bin/ssh", "-o StrictHostKeyChecking=no root@10.0.1.5", 0),
        ("ssh", "/usr/bin/ssh", "root@192.168.1.10", 0),
        ("ssh", "/usr/bin/ssh", "-i /tmp/.ssh/id_rsa admin@172.16.0.50", 0),
        ("scp", "/usr/bin/scp", "-r /etc/config user@192.168.1.100:/tmp", 0),
        ("ssh", "/usr/bin/ssh", "root@10.0.2.15 'cat /tmp/data.txt'", 0),
    ];

    println!("Scenario Overview:");
    println!("  🔹 14 clean machines (normal operations)");
    println!("  🔸 2 cryptominers (machine_003, machine_017)");
    println!("  🔸 1 web shell (machine_009)");
    println!("  🔸 2 privilege escalation (machine_006, machine_015)");
    println!("  🔸 1 lateral movement (machine_012)");
    println!();
    println!("Malicious Machines Summary:");
    println!("  • machine_003: Cryptominer in /tmp/.X11-unix/kworker");
    println!("  • machine_006: Privilege escalation (node running as root)");
    println!("  • machine_009: Web shell (php-fpm with dynamic code execution)");
    println!("  • machine_012: Lateral movement (SSH to internal IPs)");
    println!("  • machine_015: Privilege escalation (python3 in /tmp)");
    println!("  • machine_017: Cryptominer in /dev/shm/.config/worker");
    println!();

    for i in 0..NUM_MACHINES {
        let machine_id = format!("machine_{:03}", i);
        
        if i % 10 == 0 {
            println!("📊 Processing batch: {}...", machine_id);
        }

        // Always create systemd as PID 1
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: Some(current_time.to_rfc3339()),
        });

        // ⭐ FIX: Use sequential PID counter per machine to avoid collisions
        let mut next_pid = 100u32;  // Start from PID 100
        
        // Track specific parent PIDs for attack scenarios
        let mut apache2_pid: Option<u32> = None;
        let mut node_pid: Option<u32> = None;
        let mut sshd_pid: Option<u32> = None;
        
        for _log_idx in 0..LOGS_PER_MACHINE {
            current_time = current_time + Duration::seconds(rng.gen_range(60..300));
            let timestamp = current_time.to_rfc3339();
            
            let template = normal_processes[rng.gen_range(0..normal_processes.len())];
            let (mut name, _base_pid, mut path, args_ref, mut uid) = template;
            let mut args = args_ref.to_string();
            let pid = next_pid;  // ⭐ Use sequential PID
            next_pid += 1;       // ⭐ Increment for next process
            let mut ppid = 1;
            
            // Track parent processes for later reference
            if name == "apache2" && apache2_pid.is_none() {
                apache2_pid = Some(pid);
            }
            if name == "node" && node_pid.is_none() {
                node_pid = Some(pid);
            }
            if name == "sshd" && sshd_pid.is_none() {
                sshd_pid = Some(pid);
            }

            // Inject attack scenarios
            
            // Cryptominers (Machines 3, 17)
            if (i == 3 || i == 17) && rng.gen_bool(0.15) {
                let miner = miner_processes[rng.gen_range(0..miner_processes.len())];
                name = miner.0;
                path = miner.1;
                args = miner.2.to_string();
                uid = miner.3;
                ppid = 1;
            }

            // Web Shells (Machine 9) - php-fpm with dynamic execution patterns
            if i == 9 && name == "apache2" {
                // Convert most apache2 to php-fpm (its child process)
                if rng.gen_bool(0.60) {
                    name = "php-fpm";
                    path = "/usr/sbin/php-fpm";
                    ppid = apache2_pid.unwrap_or(1); // ⭐ Use tracked apache2 PID or fallback to systemd
                    
                    // 50% of php-fpm processes get malicious payloads
                    if rng.gen_bool(0.50) {
                        args = web_shell_payloads[rng.gen_range(0..web_shell_payloads.len())].to_string();
                    } else {
                        args = "/usr/sbin/php-fpm --fpm-config /etc/php/fpm/php-fpm.conf".to_string();
                    }
                }
            }

            // Privilege Escalation (Machines 6, 15)
            if (i == 6 || i == 15) && rng.gen_bool(0.12) {
                let privesc = privesc_processes[rng.gen_range(0..privesc_processes.len())];
                name = privesc.0;
                path = privesc.1;
                args = privesc.2.to_string();
                uid = privesc.3;
                ppid = node_pid.unwrap_or(1); // ⭐ Use tracked node PID or fallback to systemd
            }

            // Lateral Movement (Machine 12) - SSH to internal IPs
            if i == 12 && rng.gen_bool(0.40) {
                // High frequency of SSH connections to internal IPs
                let lateral = lateral_movement[rng.gen_range(0..lateral_movement.len())];
                name = lateral.0;
                path = lateral.1;
                args = lateral.2.to_string();
                uid = lateral.3;
                ppid = sshd_pid.unwrap_or(1); // ⭐ Use tracked sshd PID or fallback to systemd
            }

            if rng.gen_bool(0.05) {
                args = format!("{} --debug", args);
            }

            entries.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid,
                ppid,
                name: name.to_string(),
                uid,
                path: path.to_string(),
                args,
                timestamp: Some(timestamp),
            });
        }
    }

    Ok(entries)
}

fn write_csv(entries: &[RawLogEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut wtr = csv::Writer::from_writer(file);
    
    for entry in entries {
        wtr.serialize(entry)?;
    }
    
    wtr.flush()?;
    Ok(())
}

fn write_json(entries: &[RawLogEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    
    // JSON Schema for IronSift:
    // 
    // REQUIRED KEYS (at least one from each group):
    //   Machine identifier: "machine_id", "hostname", "host", "server", "node", "container", "pod"
    //   Process info: EITHER:
    //     - "command", "cmd", "cmdline", "commandline" (full command line)
    //     OR
    //     - "name", "process", "process_name", "comm" (process name only)
    //
    // OPTIONAL KEYS (with defaults if missing):
    //   "pid", "process_id" (default: auto-generated)
    //   "ppid", "parent_pid" (default: 0)
    //   "uid", "user_id", "userid" (default: 1000)
    //   "path", "exe", "executable" (default: parsed from command or /usr/bin/{name})
    //   "args", "arguments", "params" (default: parsed from command or empty)
    //   "timestamp", "time", "datetime" (default: none)
    //
    // MINIMAL VALID EXAMPLE:
    //   {"host": "server1", "cmd": "nginx"}
    //
    // FULL EXAMPLE (what this generator produces):
    //   {"machine_id": "server1", "pid": 100, "ppid": 1, "name": "nginx", 
    //    "uid": 33, "path": "/usr/sbin/nginx", "args": "-c /etc/nginx.conf",
    //    "timestamp": "2025-01-06T10:00:00Z"}
    
    writeln!(file, "[")?;
    
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(file, ",")?;
        }
        
        // Write all fields for complete compatibility
        // machine_id: REQUIRED - machine identifier
        // pid/ppid: OPTIONAL - will be auto-generated if not provided
        // name: REQUIRED (or can be derived from command)
        // uid: OPTIONAL - defaults to 1000 if not provided
        // path: OPTIONAL - can be parsed from command or name
        // args: OPTIONAL - can be parsed from command
        // timestamp: OPTIONAL - used for temporal analysis if provided
        write!(file, r#"  {{"machine_id": "{}", "pid": {}, "ppid": {}, "name": "{}", "uid": {}, "path": "{}", "args": "{}", "timestamp": "{}"}}"#,
            entry.machine_id,  // REQUIRED: machine identifier
            entry.pid,         // OPTIONAL: process ID (auto-generated if 0)
            entry.ppid,        // OPTIONAL: parent process ID (defaults to 0)
            entry.name,        // REQUIRED: process name
            entry.uid,         // OPTIONAL: user ID (defaults to 1000)
            entry.path,        // OPTIONAL: executable path
            entry.args.replace('"', "\\\""),  // OPTIONAL: command arguments
            entry.timestamp.as_ref().unwrap_or(&"".to_string())  // OPTIONAL: timestamp
        )?;
    }
    
    writeln!(file)?;
    writeln!(file, "]")?;
    
    Ok(())
}

fn print_detection_instructions(output_file: &str) {
    println!("{:=^80}", " DETECTION INSTRUCTIONS ");
    println!();
    println!("🎯 RECOMMENDED PARAMETERS FOR OPTIMAL DETECTION:");
    println!();
    println!("1. DEFAULT DETECTION (Good starting point):");
    println!("   cargo run --bin ironsift -- --input {}", output_file);
    println!();
    println!("2. TUNING (--tolerance, DBSCAN epsilon):");
    println!("   • This dataset is small; changing epsilon changes which hosts land in the noise cluster.");
    println!("   • Very low values often mark most of the fleet as outliers — not just the 6 scenario hosts.");
    println!("   • Adjust up or down while watching the anomaly count; default DetectionConfig is a practical baseline.");
    println!();
    println!("3. JSON EXPORT (forensics / scripting):");
    println!("   cargo run --bin ironsift -- --input {} --export-json report.json", output_file);
    println!("   • Field investigation_targets lists machine_id for each anomaly.");
    println!();
    println!("{:-^80}", "");
    println!();
    println!("📊 INJECTED SCENARIO HOSTS (reproducible seed):");
    println!("   The generator uses a fixed RNG seed so output is reproducible.");
    println!("   These six hosts contain the crafted attack patterns.");
    println!("   Regression tests run IronSift with --tolerance 0.40 so exactly these six appear as anomalies");
    println!("   (default tolerance 0.35 may also flag one or two benign statistical outliers).");
    println!();
    println!("   ⚠️  machine_003 (CRYPTOMINER)");
    println!("       • Process: kworker, systemd, [kthreadd] (fake kernel names)");
    println!("       • Path: /tmp/.X11-unix/kworker, /var/tmp/.cache/systemd");
    println!("       • Args: High entropy mining pool configs");
    println!("       • Risk: UID 0 (root), suspicious paths, high entropy");
    println!();
    println!("   ⚠️  machine_006 (PRIVILEGE ESCALATION)");
    println!("       • Process: node, python3, bash");
    println!("       • Path: /home/appuser/.npm/node, /tmp/setup.py");
    println!("       • Risk: Unexpected processes running as root (UID 0)");
    println!("       • Parent: node (PPID tracked)");
    println!();
    println!("   ⚠️  machine_009 (WEB SHELL) 🔴");
    println!("       • Process: php-fpm (child of apache2)");
    println!("       • Path: /usr/sbin/php-fpm");
    println!("       • Args: Dynamic code execution patterns");
    println!("       • Risk: High entropy payloads, runtime code execution");
    println!("       • Parent: apache2 (PPID tracked)");
    println!();
    println!("   ⚠️  machine_012 (LATERAL MOVEMENT)");
    println!("       • Process: ssh, scp");
    println!("       • Path: /usr/bin/ssh, /usr/bin/scp");
    println!("       • Args: Connections to internal IPs (10.0.x.x, 192.168.x.x)");
    println!("       • Risk: High frequency SSH to internal network");
    println!("       • Parent: sshd (PPID tracked)");
    println!();
    println!("   ⚠️  machine_015 (PRIVILEGE ESCALATION)");
    println!("       • Process: node, python3, bash");
    println!("       • Path: /home/appuser/.npm/node, /tmp/setup.py");
    println!("       • Risk: Unexpected processes running as root (UID 0)");
    println!("       • Parent: node (PPID tracked)");
    println!();
    println!("   ⚠️  machine_017 (CRYPTOMINER)");
    println!("       • Process: kworker, systemd, [kthreadd] (fake kernel names)");
    println!("       • Path: /dev/shm/.config/worker, /tmp/.X11-unix/kworker");
    println!("       • Args: High entropy mining pool configs");
    println!("       • Risk: UID 0 (root), suspicious paths, high entropy");
    println!();
    println!("💡 TIPS:");
    println!("   • Start with default, then lower tolerance if needed");
    println!("   • Check 'Attack Pattern Categorization' in output");
    println!("   • Export JSON for detailed forensic analysis");
    println!("   • All malicious processes have PPID correctly tracked");
    println!("   • Edit ironsift_config.json to customize detection");
    println!();
}

// --- FILE GENERATION FUNCTIONS ---

/// Synthetic `ls -l` style metadata aligned with JSONL file snapshot fields (`permissions`, `owner`, `group`, `size`).
fn file_row_metadata(path: &str, uid: u32, rng: &mut StdRng) -> (String, String, String, u64) {
    let (owner, group) = match uid {
        0 => ("root".to_string(), "root".to_string()),
        33 => ("www-data".to_string(), "www-data".to_string()),
        70 => ("postgres".to_string(), "postgres".to_string()),
        104 => ("syslog".to_string(), "adm".to_string()),
        999 => ("redis".to_string(), "redis".to_string()),
        _ => (format!("user{}", uid), "users".to_string()),
    };

    let mut perms = if path.contains("/bin/") || path.contains("/sbin/") || path.starts_with("/usr/bin/")
    {
        "-rwxr-xr-x.".to_string()
    } else if path == "/etc/shadow" || path == "/etc/sudoers" {
        "-rw-------.".to_string()
    } else {
        "-rw-r--r--.".to_string()
    };

    if path.contains("/tmp/")
        && (path.contains("malware") || path.contains("backdoor") || path.contains(".hidden"))
        && rng.gen_bool(0.35)
    {
        perms = "-rw-rw-rw-.".to_string();
    }

    let size = if rng.gen_bool(0.12) {
        0u64
    } else {
        rng.gen_range(64u64..4_194_304u64)
    };

    (perms, owner, group, size)
}

fn generate_file_entries() -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(DATASET_RNG_SEED);
    let mut entries = Vec::new();
    
    // Start time: 7 days ago
    let mut current_time = Utc::now() - Duration::days(7);
    
    // Baseline modification times for common files (30-90 days ago)
    // These represent the "expected" mtimes for files across the fleet
    let baseline_mtime = Utc::now() - Duration::days(60);

    // Define normal file paths with their baseline mtimes
    let normal_files = vec![
        "/etc/passwd",
        "/etc/group",
        "/var/log/syslog",
        "/var/log/auth.log",
        "/home/user/.bashrc",
        "/home/user/.profile",
        "/usr/bin/python3",
        "/usr/bin/node",
        "/var/www/html/index.html",
        "/etc/nginx/nginx.conf",
        "/etc/mysql/my.cnf",
        "/var/lib/postgresql/data",
        "/tmp/temp_data.txt",
        "/var/cache/apt/archives",
        "/opt/application/config.json",
    ];

    // Suspicious file paths for attack scenarios
    let suspicious_files = vec![
        "/tmp/malware",
        "/tmp/.hidden/file",
        "/dev/shm/secret",
        "/var/tmp/backdoor",
        "/etc/shadow",  // Root access to shadow file
        "/etc/sudoers",
        "/root/.ssh/authorized_keys",
        "/usr/bin/suspicious",
        "/opt/custom/payload",
    ];

    println!("File Generation Scenario Overview:");
    println!("  🔹 12 clean machines (normal file access, consistent mtimes)");
    println!("  🔸 2 machines with suspicious file access (machine_003, machine_017)");
    println!("  🔸 1 machine accessing system directories (machine_009)");
    println!("  🔸 1 machine with root file access (machine_006)");
    println!("  🔸 2 machines with rare file patterns (machine_012, machine_015)");
    println!("  🔸 2 machines with MTIME ANOMALIES (machine_005, machine_014)");
    println!("  🔸 3 machines with FLEET METADATA outliers (owner/group/size vs majority)");
    println!();
    println!("Anomalous Machines Summary:");
    println!("  • machine_003: Suspicious files in /tmp and /dev/shm");
    println!("  • machine_005: ⏰ MTIME ANOMALY - files modified recently (tampered)");
    println!("  • machine_006: Root access to sensitive files");
    println!("  • machine_007: METADATA ANOMALY - /var/log/syslog group differs from fleet");
    println!("  • machine_009: Access to system configuration files");
    println!("  • machine_012: Rare file access patterns");
    println!("  • machine_011: METADATA ANOMALY - /etc/passwd size differs from fleet");
    println!("  • machine_014: ⏰ MTIME ANOMALY + wrong owner on /etc/passwd vs fleet");
    println!("  • machine_015: Access to unusual file locations");
    println!("  • machine_017: Suspicious files + recently modified");
    println!();

    for i in 0..NUM_MACHINES {
        let machine_id = format!("machine_{:03}", i);
        
        if i % 10 == 0 {
            println!("📊 Processing batch: {}...", machine_id);
        }

        for _log_idx in 0..LOGS_PER_MACHINE {
            current_time = current_time + Duration::seconds(rng.gen_range(60..300));
            let timestamp = current_time.to_rfc3339();
            
            let mut path = normal_files[rng.gen_range(0..normal_files.len())].to_string();
            let mut uid = rng.gen_range(1000..10000);  // Normal user UIDs
            
            // Default mtime: baseline + small random variation (within hours)
            // This simulates consistent file mtimes across the fleet
            let mut mtime = baseline_mtime + Duration::hours(rng.gen_range(-12..12));
            
            // Inject attack scenarios for specific machines
            
            // MTIME ANOMALY: Machine 5 has files with very recent modification times
            // This simulates a compromised machine where system files were tampered
            if i == 5 && rng.gen_bool(0.30) {
                // Files modified within last 2 days (suspicious!)
                mtime = current_time - Duration::hours(rng.gen_range(1..48));
            }
            
            // MTIME ANOMALY: Machine 14 has /etc/passwd with recent mtime
            // This is a classic sign of user tampering
            if i == 14 && path == "/etc/passwd" {
                // /etc/passwd modified 6 hours ago on this machine only
                mtime = current_time - Duration::hours(6);
            }
            
            // Suspicious files (Machines 3, 17) - with recent mtimes
            if (i == 3 || i == 17) && rng.gen_bool(0.20) {
                path = suspicious_files[rng.gen_range(0..suspicious_files.len())].to_string();
                if rng.gen_bool(0.30) {
                    uid = 0;  // Some accessed as root
                }
                // Suspicious files are recently created
                if i == 17 {
                    mtime = current_time - Duration::hours(rng.gen_range(1..24));
                }
            }
            
            // System directory access (Machine 9)
            if i == 9 && rng.gen_bool(0.25) {
                let system_files = vec![
                    "/etc/shadow",
                    "/etc/sudoers",
                    "/etc/passwd",
                    "/etc/group",
                    "/bin/ls",
                    "/bin/cat",
                    "/sbin/ifconfig",
                ];
                path = system_files[rng.gen_range(0..system_files.len())].to_string();
            }
            
            // Root file access (Machine 6)
            if i == 6 && rng.gen_bool(0.30) {
                uid = 0;  // Root user accessing files
                let root_files = vec![
                    "/etc/shadow",
                    "/etc/sudoers",
                    "/root/.bashrc",
                    "/root/.ssh/config",
                    "/var/log/secure",
                ];
                if rng.gen_bool(0.50) {
                    path = root_files[rng.gen_range(0..root_files.len())].to_string();
                }
            }
            
            // Rare file patterns (Machines 12, 15)
            if (i == 12 || i == 15) && rng.gen_bool(0.15) {
                let rare_files = vec![
                    "/opt/unusual/application",
                    "/home/rare_user/.config",
                    "/var/custom/data",
                    "/usr/local/special/bin",
                ];
                path = rare_files[rng.gen_range(0..rare_files.len())].to_string();
            }

            // Only include mtime for files that would normally have it tracked
            // (skip /tmp files which are expected to be transient)
            let mtime_str = if !path.starts_with("/tmp") {
                Some(mtime.to_rfc3339())
            } else {
                None
            };

            let (mut permissions, mut owner, mut group, mut size) =
                file_row_metadata(&path, uid, &mut rng);

            // Stable metadata for common system paths so the fleet agrees on owner/group/size;
            // deliberate per-host overrides below produce METADATA ANOMALY detections.
            if !path.starts_with("/tmp") {
                match path.as_str() {
                    "/etc/passwd" => {
                        permissions = "-rw-r--r--.".to_string();
                        owner = "root".to_string();
                        group = "root".to_string();
                        size = 1852;
                    }
                    "/etc/group" => {
                        permissions = "-rw-r--r--.".to_string();
                        owner = "root".to_string();
                        group = "root".to_string();
                        size = 968;
                    }
                    "/var/log/syslog" => {
                        permissions = "-rw-r-----.".to_string();
                        owner = "syslog".to_string();
                        group = "adm".to_string();
                        size = 2_048_000;
                    }
                    "/var/log/auth.log" => {
                        permissions = "-rw-r-----.".to_string();
                        owner = "root".to_string();
                        group = "adm".to_string();
                        size = 512_000;
                    }
                    "/usr/bin/python3" => {
                        permissions = "-rwxr-xr-x.".to_string();
                        owner = "root".to_string();
                        group = "root".to_string();
                        size = 6_004_000;
                    }
                    "/usr/bin/node" => {
                        permissions = "-rwxr-xr-x.".to_string();
                        owner = "root".to_string();
                        group = "root".to_string();
                        size = 95_000_000;
                    }
                    _ => {}
                }
            }

            if path == "/etc/passwd" {
                if i == 14 {
                    owner = "nobody".to_string();
                } else if i == 11 {
                    size = 94_000_000;
                }
            }
            if path == "/var/log/syslog" && i == 7 {
                group = "root".to_string();
            }

            entries.push(RawFileEntry {
                machine_id: machine_id.clone(),
                path,
                uid,
                timestamp: Some(timestamp),
                mtime: mtime_str,
                permissions: Some(permissions),
                owner: Some(owner),
                group: Some(group),
                size: Some(size),
            });
        }
    }

    Ok(entries)
}

fn write_files_csv(entries: &[RawFileEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut wtr = csv::Writer::from_writer(file);
    
    for entry in entries {
        wtr.serialize(entry)?;
    }
    
    wtr.flush()?;
    Ok(())
}

fn write_files_json(entries: &[RawFileEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    
    writeln!(file, "[")?;
    
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(file, ",")?;
        }
        let line = json!({
            "machine_id": entry.machine_id,
            "file_path": entry.path,
            "uid": entry.uid,
            "timestamp": entry.timestamp,
            "date": entry.mtime,
            "permissions": entry.permissions,
            "owner": entry.owner,
            "group": entry.group,
            "size": entry.size,
            "event_type": "file_information",
        });
        write!(file, "  {}", serde_json::to_string(&line)?)?;
    }
    
    writeln!(file)?;
    writeln!(file, "]")?;
    
    Ok(())
}

fn print_file_detection_instructions(output_file: &str) {
    println!("{:=^80}", " FILE DETECTION INSTRUCTIONS ");
    println!();
    println!("📄 This dataset contains file access logs for anomaly detection.");
    println!();
    println!("🎯 RECOMMENDED PARAMETERS FOR FILE DETECTION:");
    println!();
    println!("1. Load and analyze file data:");
    println!("   // In your Rust code:");
    println!("   use rustmite_sift::{{build_file_profiles, analyze_files_fleet, DetectionConfig}};");
    println!("   use std::fs::File;");
    println!("   use csv::Reader;");
    println!("   use rustmite_sift::RawFileEntry;");
    println!();
    println!("   let config = DetectionConfig::default();");
    println!("   let mut rdr = Reader::from_path(\"{}\")?;", output_file);
    println!("   let entries: Vec<RawFileEntry> = rdr.deserialize().collect::<Result<Vec<_>, _>>()?;");
    println!("   let profiles = build_file_profiles(entries, &config);");
    println!("   let report = analyze_files_fleet(&profiles, &config)?;");
    println!("   report.print_detailed(None);");
    println!();
    println!("{:-^80}", "");
    println!();
    println!("📊 EXPECTED RESULTS:");
    println!("   The file analysis should detect:");
    println!();
    println!("   ⚠️  machine_003 (SUSPICIOUS FILES)");
    println!("       • Files: /tmp/malware, /dev/shm/secret, /tmp/.hidden/file");
    println!("       • Risk: Suspicious paths, some root access");
    println!();
    println!("   💀 machine_005 (MTIME ANOMALY - CRITICAL)");
    println!("       • Files: System files with recent modification times");
    println!("       • Risk: Files modified much more recently than fleet baseline");
    println!("       • Indicates: Possible file tampering or malicious modification");
    println!();
    println!("   ⚠️  machine_006 (ROOT FILE ACCESS)");
    println!("       • Files: /etc/shadow, /etc/sudoers, /root/.bashrc");
    println!("       • Risk: Root user accessing sensitive files");
    println!();
    println!("   ⚠️  machine_009 (SYSTEM DIRECTORY ACCESS)");
    println!("       • Files: /etc/shadow, /etc/sudoers, /bin/ls, /sbin/ifconfig");
    println!("       • Risk: Access to system configuration and binaries");
    println!();
    println!("   ⚠️  machine_012 (RARE FILE PATTERNS)");
    println!("       • Files: /opt/unusual/application, /var/custom/data");
    println!("       • Risk: Statistical rarity (unique file access patterns)");
    println!();
    println!("   💀 machine_014 (MTIME ANOMALY - CRITICAL)");
    println!("       • Files: /etc/passwd with recent modification time");
    println!("       • Risk: Critical system file modified recently");
    println!("       • Also: owner on /etc/passwd differs from fleet majority (metadata outlier)");
    println!("       • Indicates: User account tampering or backdoor creation");
    println!();
    println!("   💀 machine_007 / machine_011 (FLEET METADATA ANOMALY)");
    println!("       • machine_007: /var/log/syslog group differs from fleet");
    println!("       • machine_011: /etc/passwd size differs from fleet");
    println!("       • Risk: Same path should match peers on owner/group/size in a uniform fleet");
    println!();
    println!("   ⚠️  machine_015 (RARE FILE PATTERNS)");
    println!("       • Files: /home/rare_user/.config, /usr/local/special/bin");
    println!("       • Risk: Statistical rarity (unique file access patterns)");
    println!();
    println!("   💀 machine_017 (SUSPICIOUS + RECENTLY MODIFIED)");
    println!("       • Files: /tmp/malware, /var/tmp/backdoor with recent mtime");
    println!("       • Risk: Suspicious paths + files modified within 24h of access");
    println!("       • Indicates: Active malware deployment");
    println!();
    println!("💡 TIPS:");
    println!("   • CSV/JSON include file_path (or path), date/mtime, permissions, owner, group, size");
    println!("   • File analysis focuses on which files are accessed and WHEN modified");
    println!("   • MTIME ANOMALY: Compares file modification times across fleet");
    println!("       - Same file should have consistent mtime across machines");
    println!("       - A machine with different mtime indicates tampering");
    println!("   • METADATA ANOMALY: For system paths, compares owner, group, and size across fleet");
    println!("       - Same path on most hosts should share owner/group/size; outliers are flagged");
    println!("   • RECENTLY MODIFIED: File modified within 24h of access");
    println!("       - System files shouldn't change frequently");
    println!("   • Configure suspicious_path_patterns in config to flag specific paths");
    println!("   • Use whitelisted_path_patterns to exclude known-good paths");
    println!("   • Root access (UID 0) to non-/proc,/sys files is flagged as risk");
    println!("   • System directories (/etc, /bin, /sbin) are flagged as risk indicators");
    println!("   • Statistical rarity detects files accessed by only one machine");
    println!();
}