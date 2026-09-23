//! Configurable check-set plans: which checks (and thus collectors) run for
//! pulse / standard / deep / incident scans.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustmite_checks::CheckEngine;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub const CHECK_SET_IDS: &[&str] = &["pulse", "standard", "deep", "incident"];

/// Built-in collector bundles (docs/01 §8) used to seed defaults.
pub fn default_collectors_for_set(check_set: &str) -> Vec<&'static str> {
    let pulse = [
        "decloak.process",
        "process.inventory",
        "recon.inventory",
    ];
    let standard_extra = [
        "persistence.preload",
        "persistence.accounts",
        "modules.lkm",
        "net.sockets",
        "persistence.services",
        "persistence.scheduled",
        "ssh.keys",
    ];
    let deep_extra = [
        "file.integrity",
        "file.ioc",
        "entropy",
        "dir.hidden",
        "log.integrity",
        "modules.ebpf",
        "cred.audit",
        "session.inventory",
        "mounts.inventory",
        "container.inventory",
    ];
    match check_set {
        "pulse" => pulse.to_vec(),
        "deep" | "incident" => {
            let mut v = Vec::with_capacity(pulse.len() + standard_extra.len() + deep_extra.len());
            v.extend_from_slice(&pulse);
            v.extend_from_slice(&standard_extra);
            v.extend_from_slice(&deep_extra);
            v
        }
        _ => {
            // standard + unknown
            let mut v = Vec::with_capacity(pulse.len() + standard_extra.len());
            v.extend_from_slice(&pulse);
            v.extend_from_slice(&standard_extra);
            v
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckSetFile {
    #[serde(default = "schema_v1")]
    pub schema_version: u32,
    /// check_set id → enabled check IDs
    #[serde(default)]
    pub sets: BTreeMap<String, Vec<String>>,
}

fn schema_v1() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckSetPlanView {
    pub id: String,
    pub title: String,
    pub blurb: String,
    pub checks: Vec<String>,
    pub collectors: Vec<String>,
    pub is_default: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckSetsExport {
    pub path: String,
    pub defaults: BTreeMap<String, Vec<String>>,
    pub effective: BTreeMap<String, CheckSetPlanView>,
    pub catalog: Vec<CheckCatalogEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckCatalogEntry {
    pub id: String,
    pub name: String,
    pub check_type: String,
    pub severity: String,
    pub cost: String,
    pub enabled: bool,
    pub collectors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CheckSetsPutBody {
    /// Full replacement map of check_set → check ids.
    pub sets: BTreeMap<String, Vec<String>>,
}

pub struct CheckSetStore {
    path: PathBuf,
    inner: RwLock<CheckSetFile>,
}

impl CheckSetStore {
    pub fn open(path: impl Into<PathBuf>, engine: &CheckEngine) -> Arc<Self> {
        let path = path.into();
        let file = load_or_default(&path, engine);
        Arc::new(Self {
            path,
            inner: RwLock::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn export(&self, engine: &CheckEngine) -> CheckSetsExport {
        let defaults = default_plans(engine);
        let guard = self.inner.read().await;
        let effective = build_effective(&guard.sets, &defaults, engine);
        CheckSetsExport {
            path: self.path.display().to_string(),
            defaults,
            effective,
            catalog: catalog_entries(engine),
        }
    }

    pub async fn put(
        &self,
        body: CheckSetsPutBody,
        engine: &CheckEngine,
    ) -> Result<CheckSetsExport, String> {
        let mut sets = BTreeMap::new();
        let known: BTreeSet<String> = engine
            .manifests()
            .iter()
            .map(|m| m.id.as_str().to_string())
            .collect();
        for id in CHECK_SET_IDS {
            let mut ids = body
                .sets
                .get(*id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            ids.sort();
            ids.dedup();
            for cid in &ids {
                if !known.contains(cid) {
                    return Err(format!("unknown check id '{cid}' in set {id}"));
                }
            }
            sets.insert((*id).to_string(), ids);
        }
        let file = CheckSetFile {
            schema_version: 1,
            sets,
        };
        save(&self.path, &file)?;
        {
            let mut guard = self.inner.write().await;
            *guard = file;
        }
        Ok(self.export(engine).await)
    }

    /// Strip a check id from every scan-profile plan (after rule delete).
    pub async fn remove_check_id(
        &self,
        check_id: &str,
        engine: &CheckEngine,
    ) -> Result<CheckSetsExport, String> {
        let mut changed = false;
        let file = {
            let mut guard = self.inner.write().await;
            for ids in guard.sets.values_mut() {
                let before = ids.len();
                ids.retain(|c| c != check_id);
                if ids.len() != before {
                    changed = true;
                }
            }
            guard.clone()
        };
        if changed {
            save(&self.path, &file)?;
        }
        Ok(self.export(engine).await)
    }

    pub async fn reset_defaults(&self, engine: &CheckEngine) -> Result<CheckSetsExport, String> {
        let file = CheckSetFile {
            schema_version: 1,
            sets: default_plans(engine),
        };
        save(&self.path, &file)?;
        {
            let mut guard = self.inner.write().await;
            *guard = file;
        }
        Ok(self.export(engine).await)
    }

    /// Resolve collectors + check ids for a named set (falls back to defaults).
    pub async fn resolve(&self, check_set: &str, engine: &CheckEngine) -> ResolvedCheckSet {
        let defaults = default_plans(engine);
        let guard = self.inner.read().await;
        let key = normalize_set(check_set);
        let checks = guard
            .sets
            .get(key)
            .cloned()
            .filter(|v| !v.is_empty())
            .or_else(|| defaults.get(key).cloned())
            .unwrap_or_default();
        let collectors = collectors_for_checks(engine, &checks);
        ResolvedCheckSet {
            check_set: key.to_string(),
            check_ids: checks,
            collectors,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedCheckSet {
    pub check_set: String,
    pub check_ids: Vec<String>,
    pub collectors: Vec<String>,
}

fn normalize_set(s: &str) -> &str {
    match s {
        "pulse" | "deep" | "incident" => s,
        _ => "standard",
    }
}

fn set_meta(id: &str) -> (&'static str, &'static str) {
    match id {
        "pulse" => ("Pulse", "Fast process / decloak / recon — seconds"),
        "standard" => ("Standard", "Pulse + persistence, modules, sockets, SSH keys"),
        "deep" => ("Deep", "Standard + integrity, entropy, logs, containers"),
        "incident" => ("Incident", "Same collectors as deep; full forensic sweep"),
        _ => ("Standard", "Default fleet scan profile"),
    }
}

pub fn default_plans(engine: &CheckEngine) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for id in CHECK_SET_IDS {
        let cols: BTreeSet<&str> = default_collectors_for_set(id).into_iter().collect();
        let mut checks: Vec<String> = engine
            .manifests()
            .iter()
            .filter(|m| m.enabled)
            .filter(|m| {
                let req = m.required_collectors();
                !req.is_empty() && req.iter().all(|c| cols.contains(c.as_str()))
            })
            .map(|m| m.id.as_str().to_string())
            .collect();
        checks.sort();
        checks.dedup();
        out.insert((*id).to_string(), checks);
    }
    out
}

fn collectors_for_checks(engine: &CheckEngine, check_ids: &[String]) -> Vec<String> {
    let wanted: BTreeSet<&str> = check_ids.iter().map(|s| s.as_str()).collect();
    let mut cols = BTreeSet::new();
    for m in engine.manifests() {
        if wanted.contains(m.id.as_str()) {
            for c in m.required_collectors() {
                cols.insert(c);
            }
        }
    }
    // Always include recon for host fingerprint-ish inventory when empty.
    if cols.is_empty() {
        for c in default_collectors_for_set("pulse") {
            cols.insert(c.to_string());
        }
    }
    cols.into_iter().collect()
}

fn build_effective(
    stored: &BTreeMap<String, Vec<String>>,
    defaults: &BTreeMap<String, Vec<String>>,
    engine: &CheckEngine,
) -> BTreeMap<String, CheckSetPlanView> {
    let mut out = BTreeMap::new();
    for id in CHECK_SET_IDS {
        let (title, blurb) = set_meta(id);
        let default_ids = defaults.get(*id).cloned().unwrap_or_default();
        let checks = stored
            .get(*id)
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default_ids.clone());
        let is_default = stored.get(*id).map(|v| v == &default_ids).unwrap_or(true)
            || stored.get(*id).map(|v| v.is_empty()).unwrap_or(true);
        let collectors = collectors_for_checks(engine, &checks);
        out.insert(
            (*id).to_string(),
            CheckSetPlanView {
                id: (*id).to_string(),
                title: title.into(),
                blurb: blurb.into(),
                checks,
                collectors,
                is_default,
            },
        );
    }
    out
}

fn catalog_entries(engine: &CheckEngine) -> Vec<CheckCatalogEntry> {
    engine
        .manifests()
        .iter()
        .map(|m| CheckCatalogEntry {
            id: m.id.as_str().to_string(),
            name: m.name.clone(),
            check_type: format!("{:?}", m.check_type).to_ascii_lowercase(),
            severity: format!("{:?}", m.severity).to_ascii_lowercase(),
            cost: m.cost.clone(),
            enabled: m.enabled,
            collectors: m.required_collectors(),
        })
        .collect()
}

fn load_or_default(path: &Path, engine: &CheckEngine) -> CheckSetFile {
    if path.is_file() {
        if let Ok(raw) = std::fs::read_to_string(path) {
            if let Ok(mut file) = serde_json::from_str::<CheckSetFile>(&raw) {
                // Fill any missing sets from defaults.
                let defaults = default_plans(engine);
                for (k, v) in defaults {
                    file.sets.entry(k).or_insert(v);
                }
                return file;
            }
        }
    }
    CheckSetFile {
        schema_version: 1,
        sets: default_plans(engine),
    }
}

fn save(path: &Path, file: &CheckSetFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
    }
    let raw = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    std::fs::write(path, raw).map_err(|e| format!("write {}: {e}", path.display()))
}
