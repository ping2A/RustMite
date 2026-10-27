fn main() {
    println!("cargo:rerun-if-env-changed=RUSTMITE_VERSION");
    // Prefer RUSTMITE_VERSION (share-image / dev.sh) so the console tag matches the
    // image or local release line; fall back to the crate/workspace Cargo version.
    let version = std::env::var("RUSTMITE_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".into());
    let version = version.strip_prefix('v').unwrap_or(&version).to_string();
    println!("cargo:rustc-env=RUSTMITE_RELEASE_VERSION={version}");
}
