//! Reloadable on-disk check catalog (`checks/*.toml`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustmite_checks::{load_manifest, CheckEngine, CheckError, CheckManifest};
use rustmite_expr::compile;
use tokio::sync::RwLock;

pub struct CheckCatalog {
    dir: PathBuf,
    engine: RwLock<Arc<CheckEngine>>,
}

impl CheckCatalog {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Arc<Self>, CheckError> {
        let dir = dir.into();
        let engine = Arc::new(CheckEngine::from_dir(&dir)?);
        Ok(Arc::new(Self {
            dir,
            engine: RwLock::new(engine),
        }))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub async fn snapshot(&self) -> Arc<CheckEngine> {
        self.engine.read().await.clone()
    }

    pub async fn len(&self) -> usize {
        self.engine.read().await.len()
    }

    pub async fn reload(&self) -> Result<usize, CheckError> {
        let engine = Arc::new(CheckEngine::from_dir(&self.dir)?);
        let n = engine.len();
        *self.engine.write().await = engine;
        Ok(n)
    }

    pub fn path_for_id(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.toml"))
    }

    pub fn read_toml(&self, id: &str) -> Result<(PathBuf, String), String> {
        let path = self.path_for_id(id);
        if !path.is_file() {
            return Err(format!("check file not found: {}", path.display()));
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let m = load_manifest(&text).map_err(|e| e.to_string())?;
        if m.id.as_str() != id {
            return Err(format!(
                "check id mismatch: file declares '{}' but path is '{id}'",
                m.id.as_str()
            ));
        }
        Ok((path, text))
    }

    /// Validate, write, and hot-reload the catalog.
    pub async fn write_toml(&self, id: &str, toml_text: &str) -> Result<CheckManifest, String> {
        let m = load_manifest(toml_text).map_err(|e| e.to_string())?;
        if m.id.as_str() != id {
            return Err(format!(
                "body id '{}' must match path id '{id}'",
                m.id.as_str()
            ));
        }
        compile(&m.where_expr).map_err(|e| format!("where expression: {e}"))?;
        let path = self.path_for_id(id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out = toml_text.to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        fs::write(&path, out.as_bytes()).map_err(|e| e.to_string())?;
        self.reload().await.map_err(|e| e.to_string())?;
        Ok(m)
    }

    /// Create a new check file; fails if `{id}.toml` already exists.
    pub async fn create_toml(&self, toml_text: &str) -> Result<CheckManifest, String> {
        let m = load_manifest(toml_text).map_err(|e| e.to_string())?;
        let id = m.id.as_str();
        let path = self.path_for_id(id);
        if path.is_file() {
            return Err(format!("check '{id}' already exists"));
        }
        self.write_toml(id, toml_text).await
    }

    /// Delete `{id}.toml` and hot-reload. Returns the removed path.
    pub async fn delete_toml(&self, id: &str) -> Result<PathBuf, String> {
        let path = self.path_for_id(id);
        if !path.is_file() {
            return Err(format!("check file not found: {}", path.display()));
        }
        // Ensure the on-disk id matches before removing.
        let _ = self.read_toml(id)?;
        fs::remove_file(&path).map_err(|e| e.to_string())?;
        self.reload().await.map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// Flip `enabled = …` in the on-disk TOML (preserves the rest of the file).
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<CheckManifest, String> {
        let (path, text) = self.read_toml(id)?;
        let needle_true = "enabled = true";
        let needle_false = "enabled = false";
        let replacement = if enabled { needle_true } else { needle_false };
        let updated = if text.contains(needle_true) {
            text.replacen(needle_true, replacement, 1)
        } else if text.contains(needle_false) {
            text.replacen(needle_false, replacement, 1)
        } else {
            // Insert after version line if present, else after id.
            let insert = format!("{replacement}\n");
            if let Some(pos) = text.find("version") {
                let after = text[pos..]
                    .find('\n')
                    .map(|i| pos + i + 1)
                    .unwrap_or(text.len());
                let mut s = String::with_capacity(text.len() + insert.len());
                s.push_str(&text[..after]);
                s.push_str(&insert);
                s.push_str(&text[after..]);
                s
            } else {
                format!("{insert}{text}")
            }
        };
        if updated == text && enabled == text.contains(needle_true) {
            // already in desired state
            return load_manifest(&text).map_err(|e| e.to_string());
        }
        let m = load_manifest(&updated).map_err(|e| e.to_string())?;
        compile(&m.where_expr).map_err(|e| format!("where expression: {e}"))?;
        fs::write(&path, updated.as_bytes()).map_err(|e| e.to_string())?;
        self.reload().await.map_err(|e| e.to_string())?;
        Ok(m)
    }
}
