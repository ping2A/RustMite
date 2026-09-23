//! Check compilation and observation evaluation.

use std::path::Path;

use regex::Regex;
use rustmite_expr::{compile, eval, observation_context, CompiledExpr, EvalContext, Value as EValue};
use rustmite_proto::{
    CheckId, CheckType, CollectionPlan, CollectorSpec, Confidence, Observation, Severity,
};
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

use crate::error::CheckError;
use crate::manifest::{
    load_dir, load_manifest, match_observation, union_collectors, CheckManifest,
};

/// Raw finding produced by the check engine (no finding/scan/host IDs yet).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FindingDraft {
    pub check_id: CheckId,
    pub check_version: u32,
    pub check_type: CheckType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub evidence: Map<String, JsonValue>,
    pub attack: Vec<String>,
    pub match_kind: String,
}

struct CompiledCheck {
    manifest: CheckManifest,
    expr: CompiledExpr,
}

/// Compiles check manifests and evaluates them over observations.
pub struct CheckEngine {
    checks: Vec<CompiledCheck>,
    manifests: Vec<CheckManifest>,
}

impl CheckEngine {
    pub fn from_manifests(manifests: Vec<CheckManifest>) -> Result<Self, CheckError> {
        let all = manifests;
        let mut checks = Vec::with_capacity(all.len());
        for manifest in &all {
            if !manifest.enabled {
                continue;
            }
            let expr = compile(&manifest.where_expr).map_err(|source| CheckError::Expr {
                check_id: manifest.id.as_str().to_string(),
                source,
            })?;
            checks.push(CompiledCheck {
                manifest: manifest.clone(),
                expr,
            });
        }
        // Deterministic order by check id.
        checks.sort_by(|a, b| a.manifest.id.as_str().cmp(b.manifest.id.as_str()));
        Ok(Self {
            checks,
            manifests: all,
        })
    }

    pub fn from_toml(toml_text: &str) -> Result<Self, CheckError> {
        Self::from_manifests(vec![load_manifest(toml_text)?])
    }

    /// Like [`Self::from_toml`], but force-enables the check so dry-runs work on disabled rules.
    pub fn from_toml_for_test(toml_text: &str) -> Result<Self, CheckError> {
        let mut m = load_manifest(toml_text)?;
        m.enabled = true;
        Self::from_manifests(vec![m])
    }

    /// Compile a single saved/draft manifest for testing (always enabled).
    pub fn from_manifest_for_test(mut manifest: CheckManifest) -> Result<Self, CheckError> {
        manifest.enabled = true;
        Self::from_manifests(vec![manifest])
    }

    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self, CheckError> {
        Self::from_manifests(load_dir(dir)?)
    }

    /// Alias for [`Self::load_dir`].
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, CheckError> {
        Self::load_dir(dir)
    }

    pub fn len(&self) -> usize {
        self.checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// All loaded manifests (including disabled).
    pub fn manifests(&self) -> &[CheckManifest] {
        &self.manifests
    }

    /// Union of collector IDs required by loaded manifests (enabled or not).
    pub fn collection_plan(&self) -> CollectionPlan {
        let ids = union_collectors(&self.manifests);
        CollectionPlan {
            collectors: ids
                .into_iter()
                .map(|id| CollectorSpec {
                    id,
                    options: serde_json::Map::new(),
                })
                .collect(),
            ..CollectionPlan::default()
        }
    }

    /// Evaluate all enabled checks against the given observations.
    pub fn evaluate(&self, observations: &[Observation]) -> Vec<FindingDraft> {
        self.evaluate_filtered(observations, None)
    }

    /// Evaluate enabled checks, optionally restricted to `allow` check IDs.
    pub fn evaluate_filtered(
        &self,
        observations: &[Observation],
        allow: Option<&std::collections::HashSet<&str>>,
    ) -> Vec<FindingDraft> {
        let mut out = Vec::new();
        for (seq, obs) in observations.iter().enumerate() {
            let ctx = observation_context(obs);
            for check in &self.checks {
                if let Some(allow) = allow {
                    if !allow.contains(check.manifest.id.as_str()) {
                        continue;
                    }
                }
                if !match_observation(&check.manifest.match_on, obs) {
                    continue;
                }
                match eval(&check.expr, &ctx) {
                    Ok(true) => {
                        out.push(build_finding(&check.manifest, &ctx, obs));
                    }
                    Ok(false) => {}
                    Err(_) => {
                        let _ = seq;
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            a.check_id
                .as_str()
                .cmp(b.check_id.as_str())
                .then_with(|| a.title.cmp(&b.title))
        });
        out
    }
}

fn build_finding(manifest: &CheckManifest, ctx: &EvalContext, _obs: &Observation) -> FindingDraft {
    let title = render_template(&manifest.title, ctx);
    let mut evidence = Map::new();
    for field in &manifest.evidence_fields {
        let v = lookup_evidence(ctx, &manifest.match_on, field);
        evidence.insert(field.clone(), evalue_to_json(&v));
    }
    FindingDraft {
        check_id: manifest.id.clone(),
        check_version: manifest.version,
        check_type: manifest.check_type,
        severity: manifest.severity,
        confidence: manifest.confidence,
        title,
        evidence,
        attack: manifest.attack.clone(),
        match_kind: manifest.match_on.clone(),
    }
}

fn lookup_evidence(ctx: &EvalContext, match_on: &str, field: &str) -> EValue {
    if field.contains('.') {
        let parts: Vec<&str> = field.split('.').collect();
        return ctx.lookup_path(&parts);
    }
    // Prefer root.match_on.field, then any root.field.
    let scoped = ctx.lookup_path(&[match_on, field]);
    if !matches!(scoped, EValue::Null) {
        return scoped;
    }
    for root in ctx.roots.values() {
        let v = root.get_field(field);
        if !matches!(v, EValue::Null) {
            return v;
        }
    }
    EValue::Null
}

fn render_template(template: &str, ctx: &EvalContext) -> String {
    // Replace {{path.to.field}} placeholders.
    let re = Regex::new(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}").expect("static regex");
    re.replace_all(template, |caps: &regex::Captures| {
        let path = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let parts: Vec<&str> = path.split('.').collect();
        ctx.lookup_path(&parts).to_display_string()
    })
    .into_owned()
}

fn evalue_to_json(v: &EValue) -> JsonValue {
    match v {
        EValue::Null => JsonValue::Null,
        EValue::Bool(b) => JsonValue::Bool(*b),
        EValue::Int(i) => JsonValue::Number((*i).into()),
        EValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        EValue::String(s) => JsonValue::String(s.clone()),
        EValue::Bytes(b) => JsonValue::String(String::from_utf8_lossy(b).into_owned()),
        EValue::List(items) => JsonValue::Array(items.iter().map(evalue_to_json).collect()),
        EValue::Record(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), evalue_to_json(v));
            }
            JsonValue::Object(out)
        }
    }
}
