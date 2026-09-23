//! Anomaly detection results: severity levels, details, and analysis report.

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use chrono::Utc;
use log;
use serde::Serialize;

use crate::config::DetectionConfig;
use crate::types::MachineProfile;

#[derive(Debug, Clone, Serialize)]
pub enum AnomalyLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalyLevel {
    pub fn from_distance(distance: f64) -> Self {
        if distance >= 1.0 {
            AnomalyLevel::Critical
        } else if distance >= 0.6 {
            AnomalyLevel::High
        } else if distance >= 0.3 {
            AnomalyLevel::Medium
        } else {
            AnomalyLevel::Low
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyLevel::Low => "LOW",
            AnomalyLevel::Medium => "MEDIUM",
            AnomalyLevel::High => "HIGH",
            AnomalyLevel::Critical => "CRITICAL",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            AnomalyLevel::Low => "🟡",
            AnomalyLevel::Medium => "🟠",
            AnomalyLevel::High => "🔴",
            AnomalyLevel::Critical => "💀",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            AnomalyLevel::Low => 0,
            AnomalyLevel::Medium => 1,
            AnomalyLevel::High => 2,
            AnomalyLevel::Critical => 3,
        }
    }
}

impl std::fmt::Display for AnomalyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyDetails {
    pub machine_id: String,
    pub severity: AnomalyLevel,
    pub distance_score: f64,
    pub cluster_assignment: Option<usize>,
    pub anomalous_features: Vec<String>,
    pub process_count: u32,
    pub suspicious_process_count: u32,
}

impl AnomalyDetails {
    fn severity_emoji(&self) -> &'static str {
        self.severity.emoji()
    }

    fn severity_str(&self) -> &'static str {
        self.severity.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AnalysisType {
    Process,
    File,
}

pub struct AnalysisReport {
    pub anomalies: Vec<AnomalyDetails>,
    pub cluster_stats: HashMap<Option<usize>, usize>,
    pub total_analyzed: usize,
    pub config_used: DetectionConfig,
    pub analysis_type: AnalysisType,
}

impl AnalysisReport {
    pub fn print(&self) {
        self.print_detailed(None);
    }

    pub fn print_summary(&self) {
        if self.anomalies.is_empty() {
            println!("CLEAN");
        } else {
            let c = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Critical)).count();
            let h = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::High)).count();
            let m = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Medium)).count();
            let l = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Low)).count();
            println!(
                "ANOMALIES: {} (Critical: {}, High: {}, Medium: {}, Low: {})",
                self.anomalies.len(), c, h, m, l
            );
        }
    }

    pub fn print_detailed(&self, profiles: Option<&[MachineProfile]>) {
        if self.config_used.quiet {
            self.print_summary();
            return;
        }
        println!("\n{:=^80}", " IRONSIFT ANALYSIS REPORT ");
        println!("Fleet Size: {} machines", self.total_analyzed);
        println!(
            "Detection Sensitivity: {}",
            if self.config_used.dbscan_tolerance < 0.05 {
                "High"
            } else if self.config_used.dbscan_tolerance < 0.10 {
                "Medium"
            } else {
                "Low"
            }
        );

        println!("\n--- Configuration ---");
        println!("  DBSCAN Tolerance: {}", self.config_used.dbscan_tolerance);
        println!("  Entropy Threshold: {}", self.config_used.entropy_threshold);
        println!(
            "  Minority Cluster Ratio: {}%",
            self.config_used.minority_cluster_ratio * 100.0
        );

        println!("\n--- Cluster Distribution ---");
        let mut cluster_ids: Vec<_> = self.cluster_stats.keys().filter_map(|k| *k).collect();
        cluster_ids.sort();
        for cluster_id in cluster_ids {
            let count = self.cluster_stats.get(&Some(cluster_id)).unwrap_or(&0);
            let pct = (*count as f64 / self.total_analyzed as f64) * 100.0;
            println!("  Cluster {}: {} machines ({:.1}%)", cluster_id, count, pct);
        }
        if let Some(&noise_count) = self.cluster_stats.get(&None) {
            let pct = (noise_count as f64 / self.total_analyzed as f64) * 100.0;
            println!("  Noise (Outliers): {} machines ({:.1}%)", noise_count, pct);
        }

        let entity_name = if self.analysis_type == AnalysisType::File {
            "file accesses"
        } else {
            "processes"
        };

        if self.anomalies.is_empty() {
            println!("\n{:=^80}", "");
            println!("Status: ✅ CLEAN (No anomalies detected)");
            println!("{:=^80}", "");
            println!("\nAll machines appear to be operating normally.");
            println!("No suspicious {} or unusual behavior patterns detected.", entity_name);
        } else {
            println!("\n{:=^80}", "");
            println!("Status: 🚨 ANOMALIES DETECTED");
            println!("{:=^80}", "");
            println!("Suspicious Machines: {}", self.anomalies.len());

            let critical: Vec<_> = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Critical)).collect();
            let high: Vec<_> = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::High)).collect();
            let medium: Vec<_> = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Medium)).collect();
            let low: Vec<_> = self.anomalies.iter().filter(|a| matches!(a.severity, AnomalyLevel::Low)).collect();

            println!("\nSeverity Breakdown:");
            if !critical.is_empty() {
                println!("  💀 CRITICAL: {} machine(s)", critical.len());
            }
            if !high.is_empty() {
                println!("  🔴 HIGH: {} machine(s)", high.len());
            }
            if !medium.is_empty() {
                println!("  🟠 MEDIUM: {} machine(s)", medium.len());
            }
            if !low.is_empty() {
                println!("  🟡 LOW: {} machine(s)", low.len());
            }

            if !critical.is_empty() {
                println!("\n💀 CRITICAL ({}):", critical.len());
                println!("   These machines are isolated outliers - likely compromised");
                for anomaly in critical {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            if !high.is_empty() {
                println!("\n🔴 HIGH ({}):", high.len());
                println!("   Strong deviation from baseline - investigate immediately");
                for anomaly in high {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            if !medium.is_empty() {
                println!("\n🟠 MEDIUM ({}):", medium.len());
                println!("   Moderate anomaly - worth reviewing");
                for anomaly in medium {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            if !low.is_empty() {
                println!("\n🟡 LOW ({}):", low.len());
                println!("   Minor deviation - may be benign");
                for anomaly in low {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }

            self.print_attack_summary(profiles);

            println!("\n{:=^80}", "");
            println!("Recommended Actions:");
            if self.analysis_type == AnalysisType::File {
                println!("  1. Review flagged machines and investigate anomalous file accesses");
                println!("  2. Check file access paths and user permissions");
                println!("  3. Verify file access patterns and system directory access");
                println!("  4. Cross-reference with process logs and network logs");
            } else {
                println!("  1. Review flagged machines and investigate anomalous processes");
                println!("  2. Check process execution paths and command arguments");
                println!("  3. Verify parent-child process relationships");
                println!("  4. Cross-reference with network logs and file access logs");
            }
            println!("  5. Export detailed report: cargo run --bin ironsift -- --export-json");
            println!("{:=^80}", "");
        }
    }

    fn print_anomaly_detailed(&self, anomaly: &AnomalyDetails, profiles: Option<&[MachineProfile]>) {
        println!(
            "\n  {} {} [{}] (Distance: {:.3})",
            anomaly.severity_emoji(),
            anomaly.machine_id,
            anomaly.severity_str(),
            anomaly.distance_score
        );
        if let Some(cluster) = anomaly.cluster_assignment {
            println!("     ├─ Cluster: {}", cluster);
        } else {
            println!("     ├─ Cluster: Noise (isolated outlier)");
        }
        let entity_label = if self.analysis_type == AnalysisType::File {
            "file accesses"
        } else {
            "processes"
        };
        println!("     ├─ Total {}: {}", entity_label, anomaly.process_count);
        if anomaly.suspicious_process_count > 0 {
            println!("     ├─ Suspicious {}: {} ⚠️", entity_label, anomaly.suspicious_process_count);
        }
        if !anomaly.anomalous_features.is_empty() {
            let rare_label = if self.analysis_type == AnalysisType::File {
                "Rare file accesses (< 5% of fleet):"
            } else {
                "Rare processes (< 5% of fleet):"
            };
            println!("     ├─ {}", rare_label);
            let display_count = anomaly.anomalous_features.len().min(5);
            for feature in &anomaly.anomalous_features[..display_count] {
                println!("     │  • {}", feature);
            }
            if anomaly.anomalous_features.len() > 5 {
                println!("     │  • ... and {} more", anomaly.anomalous_features.len() - 5);
            }
        }
        if let Some(profiles) = profiles {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                self.print_suspicious_processes(profile);
                if profile.first_seen.is_some() && profile.last_seen.is_some() {
                    println!(
                        "     └─ Activity period: {} to {}",
                        profile.first_seen.unwrap().format("%Y-%m-%d %H:%M:%S"),
                        profile.last_seen.unwrap().format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
        } else {
            let info_label = if self.analysis_type == AnalysisType::File {
                "file access information"
            } else {
                "process information"
            };
            println!("     └─ Run with profiles for detailed {}", info_label);
        }
    }

    fn print_suspicious_processes(&self, profile: &MachineProfile) {
        let mut suspicious: Vec<_> = profile
            .counts
            .iter()
            .filter(|(sig, _)| sig.is_high_entropy || sig.is_suspicious_path || sig.uid == 0)
            .collect();
        if suspicious.is_empty() {
            return;
        }
        suspicious.sort_by(|(a, _), (b, _)| {
            let a_score = (a.is_high_entropy as i32)
                + (a.is_suspicious_path as i32)
                + ((a.uid == 0 && a.name.as_ref() != "systemd" && a.name.as_ref() != "init") as i32);
            let b_score = (b.is_high_entropy as i32)
                + (b.is_suspicious_path as i32)
                + ((b.uid == 0 && b.name.as_ref() != "systemd" && b.name.as_ref() != "init") as i32);
            b_score.cmp(&a_score)
        });
        println!("     ├─ Suspicious processes detected:");
        for (sig, count) in suspicious.iter().take(3) {
            println!("     │");
            println!("     │  📛 {} (count: {})", sig.name, count);
            println!("     │     Path: {}", sig.path);
            if sig.uid == 0 {
                println!("     │     UID: {} (root) ⚠️", sig.uid);
            } else {
                println!("     │     UID: {}", sig.uid);
            }
            let risks = sig.risk_factors(&self.config_used);
            if !risks.is_empty() {
                println!("     │     Risk factors:");
                for risk in risks {
                    println!("     │       🚨 {}", risk);
                }
            }
        }
        if suspicious.len() > 3 {
            println!("     │  ... and {} more suspicious processes", suspicious.len() - 3);
        }
    }

    fn print_attack_summary(&self, profiles: Option<&[MachineProfile]>) {
        let profiles = match profiles {
            Some(p) => p,
            None => return,
        };
        let mut cryptominers = Vec::new();
        let mut web_shells = Vec::new();
        let mut privilege_escalation = Vec::new();
        let mut suspicious_paths = Vec::new();
        for anomaly in &self.anomalies {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                for (sig, _) in &profile.counts {
                    if (sig.name.contains("miner") || sig.name.contains("xmr") || sig.name.contains("kworker") || sig.name.contains("worker"))
                        && (sig.is_suspicious_path || sig.uid == 0)
                    {
                        cryptominers.push(anomaly.machine_id.clone());
                        break;
                    }
                    if (sig.name.contains("php") || sig.name.contains("eval")) && sig.is_high_entropy {
                        web_shells.push(anomaly.machine_id.clone());
                        break;
                    }
                    if sig.uid == 0
                        && sig.name.as_ref() != "systemd"
                        && sig.name.as_ref() != "init"
                        && (sig.is_high_entropy || sig.is_suspicious_path)
                    {
                        privilege_escalation.push(anomaly.machine_id.clone());
                        break;
                    }
                    if sig.is_suspicious_path {
                        suspicious_paths.push(anomaly.machine_id.clone());
                        break;
                    }
                }
            }
        }
        if cryptominers.is_empty() && web_shells.is_empty() && privilege_escalation.is_empty() && suspicious_paths.is_empty() {
            return;
        }
        println!("\n--- Detected Attack Patterns ---");
        if !cryptominers.is_empty() {
            println!("  ⛏️  Cryptomining ({} machines):", cryptominers.len());
            for machine in cryptominers.iter().take(5) {
                println!("     • {}", machine);
            }
            if cryptominers.len() > 5 {
                println!("     • ... and {} more", cryptominers.len() - 5);
            }
        }
        if !web_shells.is_empty() {
            println!("  🕸️  Web Shells ({} machines):", web_shells.len());
            for machine in web_shells.iter().take(5) {
                println!("     • {}", machine);
            }
            if web_shells.len() > 5 {
                println!("     • ... and {} more", web_shells.len() - 5);
            }
        }
        if !privilege_escalation.is_empty() {
            println!("  ⬆️  Privilege Escalation ({} machines):", privilege_escalation.len());
            for machine in privilege_escalation.iter().take(5) {
                println!("     • {}", machine);
            }
            if privilege_escalation.len() > 5 {
                println!("     • ... and {} more", privilege_escalation.len() - 5);
            }
        }
        if !suspicious_paths.is_empty() {
            println!("  📂 Suspicious Execution Paths ({} machines):", suspicious_paths.len());
            for machine in suspicious_paths.iter().take(5) {
                println!("     • {}", machine);
            }
            if suspicious_paths.len() > 5 {
                println!("     • ... and {} more", suspicious_paths.len() - 5);
            }
        }
    }

    pub fn export_json(&self, profiles: &[MachineProfile], path: &str) -> Result<(), Box<dyn Error>> {
        let mut investigation_data = Vec::new();
        for anomaly in &self.anomalies {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                let suspicious_procs: Vec<_> = profile
                    .counts
                    .iter()
                    .filter(|(sig, _)| {
                        let is_common = self.config_used.common_root_processes.iter().any(|p| sig.name.contains(p));
                        sig.is_high_entropy || sig.is_suspicious_path || (sig.uid == 0 && !is_common)
                    })
                    .map(|(sig, count)| {
                        let entropy_status = if sig.is_high_entropy { "HIGH" } else { "NORMAL" };
                        serde_json::json!({
                            "name": sig.name,
                            "path": sig.path,
                            "parent": sig.parent_name,
                            "uid": sig.uid,
                            "count": count,
                            "is_high_entropy": sig.is_high_entropy,
                            "entropy_status": entropy_status,
                            "is_suspicious_path": sig.is_suspicious_path,
                            "risk_factors": sig.risk_factors(&self.config_used),
                        })
                    })
                    .collect();
                let all_procs: Vec<_> = profile
                    .counts
                    .iter()
                    .map(|(sig, count)| {
                        serde_json::json!({
                            "name": sig.name,
                            "parent": sig.parent_name,
                            "uid": sig.uid,
                            "path": sig.path,
                            "count": count,
                            "is_high_entropy": sig.is_high_entropy,
                            "is_suspicious_path": sig.is_suspicious_path,
                        })
                    })
                    .collect();
                investigation_data.push(serde_json::json!({
                    "machine_id": anomaly.machine_id,
                    "severity": {
                        "level": anomaly.severity.as_str(),
                        "score": anomaly.severity.score(),
                        "emoji": anomaly.severity.emoji(),
                    },
                    "distance_score": anomaly.distance_score,
                    "cluster": anomaly.cluster_assignment,
                    "total_processes": profile.total_logs,
                    "unique_processes": profile.counts.len(),
                    "suspicious_processes": suspicious_procs,
                    "all_processes": all_procs,
                    "anomalous_features": &anomaly.anomalous_features,
                    "time_range": {
                        "first_seen": profile.first_seen,
                        "last_seen": profile.last_seen,
                    }
                }));
            }
        }
        let cluster_distribution: serde_json::Map<String, serde_json::Value> = self
            .cluster_stats
            .iter()
            .map(|(k, v)| {
                let key = match k {
                    Some(id) => format!("cluster_{}", id),
                    None => "outliers".to_string(),
                };
                (key, serde_json::json!(v))
            })
            .collect();
        let report = serde_json::json!({
            "report_timestamp": Utc::now(),
            "fleet_size": self.total_analyzed,
            "anomalies_detected": self.anomalies.len(),
            "config": self.config_used,
            "cluster_distribution": cluster_distribution,
            "investigation_targets": investigation_data,
        });
        if path == "-" {
            let out = std::io::stdout();
            serde_json::to_writer_pretty(out, &report)?;
            log::info!("Forensic report written to stdout");
        } else {
            let file = File::create(path)?;
            serde_json::to_writer_pretty(file, &report)?;
            log::info!("Forensic report exported to: {}", path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AnomalyLevel;

    #[test]
    fn anomaly_level_from_distance_buckets() {
        assert!(matches!(
            AnomalyLevel::from_distance(1.0),
            AnomalyLevel::Critical
        ));
        assert!(matches!(AnomalyLevel::from_distance(0.7), AnomalyLevel::High));
        assert!(matches!(
            AnomalyLevel::from_distance(0.45),
            AnomalyLevel::Medium
        ));
        assert!(matches!(AnomalyLevel::from_distance(0.2), AnomalyLevel::Low));
    }

    #[test]
    fn anomaly_level_score_monotonic() {
        assert!(AnomalyLevel::Critical.score() > AnomalyLevel::Low.score());
        assert_eq!(AnomalyLevel::Medium.as_str(), "MEDIUM");
        assert!(!AnomalyLevel::Low.emoji().is_empty());
    }
}
