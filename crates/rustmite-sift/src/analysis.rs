//! Process fleet analysis: DBSCAN clustering and anomaly detection.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use ndarray::Array2;
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use rayon::prelude::*;

use crate::config::DetectionConfig;
use crate::report::{AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel};
use crate::types::{MachineProfile, ProcessSignature};

pub fn analyze_fleet(
    profiles: &[MachineProfile],
    config: &DetectionConfig,
) -> Result<AnalysisReport, Box<dyn Error>> {
    if profiles.is_empty() {
        return Ok(AnalysisReport {
            anomalies: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
            config_used: config.clone(),
            analysis_type: AnalysisType::Process,
        });
    }

    let mut unique_features: HashSet<&ProcessSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() {
            unique_features.insert(key);
        }
    }

    let mut feature_list: Vec<&ProcessSignature> = unique_features.into_iter().collect();
    feature_list.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.path.cmp(&b.path))
            .then(a.parent_name.cmp(&b.parent_name))
            .then(a.uid.cmp(&b.uid))
            .then(a.is_high_entropy.cmp(&b.is_high_entropy))
            .then(a.is_suspicious_path.cmp(&b.is_suspicious_path))
    });

    let n_samples = profiles.len();
    let n_features = feature_list.len();

    // Document frequency per feature — O(features × machines), not O(features × machines²).
    let feature_doc_freq: Vec<usize> = feature_list
        .par_iter()
        .map(|feature| profiles.iter().filter(|p| p.counts.contains_key(*feature)).count())
        .collect();

    let doc_count_map: HashMap<&ProcessSignature, usize> = feature_list
        .iter()
        .enumerate()
        .map(|(i, &f)| (f, feature_doc_freq[i]))
        .collect();

    let data = if n_features == 0 {
        Array2::<f64>::zeros((n_samples, 1))
    } else {
        let n_samples_f = n_samples as f64;
        let mut flat = vec![0.0f64; n_samples * n_features];
        flat.par_chunks_mut(n_features)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let profile = &profiles[row_idx];
                if profile.total_logs == 0 {
                    return;
                }
                let tlog = profile.total_logs as f64;
                for (col_idx, feature) in feature_list.iter().enumerate() {
                    if let Some(&count) = profile.counts.get(feature) {
                        let tf = count as f64 / tlog;
                        let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                        let idf = (n_samples_f / doc_count).ln() + 1.0;
                        row[col_idx] = tf * idf;
                    }
                }
            });

        if config.normalize_features {
            flat.par_chunks_mut(n_features).for_each(|row| {
                let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
                if norm > 0.0 {
                    for x in row.iter_mut() {
                        *x /= norm;
                    }
                }
            });
        }

        Array2::from_shape_vec((n_samples, n_features), flat).map_err(|e| -> Box<dyn Error> {
            format!("internal: TF-IDF matrix shape: {}", e).into()
        })?
    };

    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    let largest_cluster = cluster_counts
        .iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.unwrap());

    let mut anomalies = Vec::new();

    for (i, cluster_id) in clusters.iter().enumerate() {
        let profile = &profiles[i];
        let mut suspicious_count = 0;
        let mut anomalous_features = Vec::new();
        let mut has_genuine_risk = false;

        for (sig, count) in &profile.counts {
            let is_common_root = config.common_root_processes.iter().any(|p| sig.name.contains(p));
            let is_behavioral_risk = sig.is_high_entropy || sig.is_suspicious_path;
            let is_unexpected_root = sig.uid == 0 && !is_common_root;

            if is_behavioral_risk || is_unexpected_root {
                suspicious_count += *count;
                has_genuine_risk = true;
                let mut reasons: Vec<&str> = Vec::with_capacity(3);
                if is_unexpected_root {
                    reasons.push("root_no_whitelist");
                }
                if sig.is_suspicious_path {
                    reasons.push("suspicious_path");
                }
                if sig.is_high_entropy {
                    reasons.push("high_entropy_args");
                }
                let path_disp: &str = if sig.path.as_ref().is_empty() {
                    "(none)"
                } else {
                    sig.path.as_ref()
                };
                let parent_disp: &str = if sig.parent_name.as_ref().is_empty() {
                    "(none)"
                } else {
                    sig.parent_name.as_ref()
                };
                anomalous_features.push(format!(
                    "RISK DETECTED: name={} path={} parent={} uid={} count={} reasons={}",
                    sig.name,
                    path_disp,
                    parent_disp,
                    sig.uid,
                    count,
                    reasons.join(",")
                ));
            }

            let doc_count = doc_count_map.get(sig).copied().unwrap_or(0);
            if doc_count == 1 && !is_common_root {
                anomalous_features.push(format!("Rare process: {}", sig.name));
            }
        }

        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some()
            && cluster_id.unwrap() != largest_cluster.unwrap_or(999);

        if is_noise || is_minority || has_genuine_risk {
            let severity = if has_genuine_risk {
                if suspicious_count > 5 {
                    AnomalyLevel::Critical
                } else {
                    AnomalyLevel::High
                }
            } else if anomalous_features.is_empty() {
                // Pure cluster outlier: no behavioral risk and no "rare process" doc-frequency hints.
                AnomalyLevel::Low
            } else {
                // e.g. fleet-unique process names without stronger risk markers.
                AnomalyLevel::Medium
            };

            if anomalous_features.is_empty() && (is_noise || is_minority) {
                anomalous_features.push(
                    "Process mix differs from fleet majority cluster (no behavioral/root/rare-process flags)."
                        .to_string(),
                );
            }

            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity,
                distance_score: if is_noise { 1.5 } else { 0.8 },
                cluster_assignment: *cluster_id,
                anomalous_features,
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    Ok(AnalysisReport {
        anomalies,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
        config_used: config.clone(),
        analysis_type: AnalysisType::Process,
    })
}

pub fn analyze_fleet2(
    profiles: &[MachineProfile],
    config: &DetectionConfig,
) -> Result<AnalysisReport, Box<dyn Error>> {
    if profiles.is_empty() {
        return Ok(AnalysisReport {
            anomalies: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
            config_used: config.clone(),
            analysis_type: AnalysisType::Process,
        });
    }

    let mut unique_features: HashSet<&ProcessSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() {
            unique_features.insert(key);
        }
    }

    let mut feature_list: Vec<&ProcessSignature> = unique_features.into_iter().collect();
    feature_list.sort_by(|a, b| {
        a.name.cmp(&b.name)
            .then(a.path.cmp(&b.path))
            .then(a.uid.cmp(&b.uid))
    });

    let n_samples = profiles.len();
    let n_features = feature_list.len();

    let feature_doc_freq: Vec<usize> = feature_list
        .par_iter()
        .map(|feature| profiles.iter().filter(|p| p.counts.contains_key(feature)).count())
        .collect();

    let data = if n_features == 0 {
        Array2::<f64>::zeros((n_samples, 1))
    } else {
        let n_samples_f = n_samples as f64;
        let mut flat = vec![0.0f64; n_samples * n_features];
        flat.par_chunks_mut(n_features)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let profile = &profiles[row_idx];
                if profile.total_logs == 0 {
                    return;
                }
                let tlog = profile.total_logs as f64;
                for (col_idx, feature) in feature_list.iter().enumerate() {
                    if let Some(&count) = profile.counts.get(feature) {
                        let tf = count as f64 / tlog;
                        let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                        let idf = (n_samples_f / doc_count).ln() + 1.0;
                        row[col_idx] = tf * idf;
                    }
                }
            });
        if config.normalize_features {
            flat.par_chunks_mut(n_features).for_each(|row| {
                let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
                if norm > 0.0 {
                    for x in row.iter_mut() {
                        *x /= norm;
                    }
                }
            });
        }
        Array2::from_shape_vec((n_samples, n_features), flat).map_err(|e| -> Box<dyn Error> {
            format!("internal: TF-IDF matrix shape (fleet2): {}", e).into()
        })?
    };

    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    let largest_cluster = cluster_counts
        .iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| *k);

    let mut anomalies = Vec::new();
    for (i, cluster_id) in clusters.iter().enumerate() {
        let (is_anomaly, distance_score) = match cluster_id {
            None => (true, 1.5),
            Some(id) => {
                let cluster_size = cluster_counts.get(&Some(*id)).unwrap_or(&0);
                let is_minority =
                    (*cluster_size as f64) < (n_samples as f64 * config.minority_cluster_ratio);
                let is_not_main = Some(*id) != largest_cluster.unwrap();
                if is_minority && is_not_main {
                    (true, 0.7)
                } else {
                    (false, 0.0)
                }
            }
        };

        if is_anomaly {
            let profile = &profiles[i];
            let mut anomalous_features = Vec::new();
            let mut suspicious_count = 0;
            for (sig, count) in &profile.counts {
                let doc_freq_idx = feature_list.iter().position(|&f| f == sig);
                if let Some(idx) = doc_freq_idx {
                    let doc_freq = feature_doc_freq[idx] as f64 / n_samples as f64;
                    if doc_freq < 0.05 {
                        anomalous_features.push(format!("{} (path: {})", sig.name, sig.path));
                    }
                }
                if sig.is_high_entropy || sig.is_suspicious_path {
                    suspicious_count += *count;
                }
            }
            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity: AnomalyLevel::from_distance(distance_score),
                distance_score,
                cluster_assignment: *cluster_id,
                anomalous_features,
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    anomalies.sort_by(|a, b| b.distance_score.partial_cmp(&a.distance_score).unwrap());

    Ok(AnalysisReport {
        anomalies,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
        config_used: config.clone(),
        analysis_type: AnalysisType::Process,
    })
}

#[cfg(test)]
mod tests {
    use super::{analyze_fleet, analyze_fleet2};
    use crate::config::DetectionConfig;
    use crate::report::AnalysisType;

    #[test]
    fn analyze_fleet_empty_profiles_returns_process_report() {
        let config = DetectionConfig::default();
        let r = analyze_fleet(&[], &config).unwrap();
        assert_eq!(r.total_analyzed, 0);
        assert!(r.anomalies.is_empty());
        assert_eq!(r.analysis_type, AnalysisType::Process);
    }

    #[test]
    fn analyze_fleet2_empty_profiles_matches_analyze_fleet() {
        let config = DetectionConfig::default();
        let a = analyze_fleet(&[], &config).unwrap();
        let b = analyze_fleet2(&[], &config).unwrap();
        assert_eq!(a.total_analyzed, b.total_analyzed);
        assert_eq!(a.anomalies.len(), b.anomalies.len());
    }
}
