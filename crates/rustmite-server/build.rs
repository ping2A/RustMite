fn main() {
    println!("cargo:rerun-if-env-changed=RUSTMITE_VERSION");
    let version = std::env::var("RUSTMITE_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".into());
    println!("cargo:rustc-env=RUSTMITE_RELEASE_VERSION={version}");
}
