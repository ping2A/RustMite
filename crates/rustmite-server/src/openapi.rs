//! Minimal hand-written OpenAPI 3.1 document.

pub fn openapi_json() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "RustMite Operator API",
            "version": "0.1.0"
        },
        "paths": {
            "/v1/health": {
                "get": {
                    "summary": "Health check",
                    "responses": { "200": { "description": "ok" } }
                }
            },
            "/v1/version": {
                "get": {
                    "summary": "Server and agentless (probe/loader) versions with SHA-256 digests per platform"
                }
            },
            "/v1/hosts": {
                "get": { "summary": "List hosts" },
                "post": { "summary": "Register host" }
            },
            "/v1/hosts/test": {
                "post": { "summary": "Test SSH reachability / credentials before or after adding a host" }
            },
            "/v1/hosts/delete": {
                "post": { "summary": "Bulk delete hosts (cascades findings/scans for those hosts)" }
            },
            "/v1/hosts/{id}": {
                "get": { "summary": "Host detail" },
                "patch": { "summary": "Update host (name, address, labels, timeouts)" },
                "delete": { "summary": "Delete host and associated results" }
            },
            "/v1/hosts/{id}/scan": {
                "post": { "summary": "Enqueue on-demand scan" }
            },
            "/v1/hosts/{id}/processes": {
                "get": { "summary": "Latest process inventory for a host (from last scan observations)" }
            },
            "/v1/hosts/{id}/connections": {
                "get": { "summary": "Latest open network connections for a host (from last scan observations)" }
            },
            "/v1/findings": {
                "get": { "summary": "List findings" }
            },
            "/v1/scans/{id}": {
                "get": { "summary": "Scan status" }
            },
            "/v1/metrics": {
                "get": { "summary": "Control-plane CPU / memory / disk metrics" }
            },
            "/v1/settings": {
                "get": { "summary": "Exportable settings catalog + effective runtime values (secrets redacted; includes probe agent limits)" },
                "put": { "summary": "Patch settings (scan history and/or probe_limits resource envelope)" }
            },
            "/v1/credentials/ssh-identity": {
                "post": { "summary": "Seal an SSH private key for scanner nodes only (server cannot decrypt again; Sandfly-style)" }
            },
            "/v1/credentials/ssh-password": {
                "post": { "summary": "Seal an SSH password for scanner nodes only (server cannot decrypt again)" }
            },
            "/v1/ssh/summary": {
                "get": { "summary": "SSH Hunter dashboard summary" }
            },
            "/v1/ssh/keys": {
                "get": { "summary": "List SSH public keys (Key Investigation)" },
                "post": { "summary": "Bulk tag SSH keys (Tag Workbench)" }
            },
            "/v1/ssh/keys/{fingerprint}": {
                "get": { "summary": "SSH key detail + placements" }
            },
            "/v1/ssh/users": {
                "get": { "summary": "Users with authorized SSH keys" }
            },
            "/v1/ssh/hosts": {
                "get": { "summary": "Hosts with SSH key inventory" }
            },
            "/v1/ssh/graph": {
                "get": { "summary": "SSH Hunter key↔user↔host graph" }
            },
            "/v1/ssh/tags": {
                "get": { "summary": "Unique SSH key tags" }
            },
            "/v1/ssh/zones": {
                "get": { "summary": "SSH security zones" },
                "post": { "summary": "Create SSH security zone" }
            },
            "/v1/ssh/zones/{id}": {
                "delete": { "summary": "Delete SSH security zone" }
            },
            "/v1/checks": {
                "get": { "summary": "List detection rules (manifests + per-scan-profile membership)" },
                "post": { "summary": "Create a new rule from TOML (fails if id already exists)" }
            },
            "/v1/checks/reload": {
                "post": { "summary": "Hot-reload checks/*.toml from disk" }
            },
            "/v1/checks/validate": {
                "post": { "summary": "Compile a draft TOML rule and dry-run over recent observations" }
            },
            "/v1/checks/{id}": {
                "get": { "summary": "Rule detail including raw TOML source" },
                "put": { "summary": "Replace rule TOML (validated + hot-reload)" },
                "patch": { "summary": "Toggle enabled and/or scan-profile membership" },
                "delete": { "summary": "Delete rule TOML from disk and strip from scan profiles" }
            },
            "/v1/checks/{id}/validate": {
                "post": { "summary": "Compile saved/override rule and dry-run (Mobipwn-style preview)" }
            },
            "/v1/checks/{id}/test": {
                "post": { "summary": "Dry-run test a rule over stored observations (no findings created)" }
            },
            "/v1/hosts/virtual": {
                "post": { "summary": "Create a virtual (agentless) host for log ingest" }
            },
            "/v1/hosts/virtual/import-tree": {
                "post": { "summary": "Import a directory tree: each subdirectory = one host; name from dirname, IronSift segment, or PulseSecure" }
            },
            "/v1/hosts/virtual/import-tree-upload": {
                "post": { "summary": "Browser folder upload: each top-level subdirectory = one virtual host (same naming as import-tree)" }
            },
            "/v1/hosts/{id}/ingest/import": {
                "post": { "summary": "Import raw JSONL/JSON/CSV files or a directory into a virtual agent (IronSift-style)" }
            },
            "/v1/ingest/logs": {
                "post": { "summary": "Append NDJSON process/file logs for a virtual agent (Bearer ingest token)" }
            },
            "/v1/anomark/models": {
                "get": { "summary": "List AnoMark trained models" },
                "post": { "summary": "Train a new AnoMark model from hosts, path, or pasted lines" }
            },
            "/v1/anomark/models/{id}": {
                "get": { "summary": "AnoMark model detail" },
                "delete": { "summary": "Delete an AnoMark training" }
            },
            "/v1/anomark/models/{id}/favorite": {
                "put": { "summary": "Pin/unpin AnoMark model in pickers" }
            },
            "/v1/anomark/models/{id}/inspect": {
                "get": { "summary": "Inspect AnoMark model stats" }
            },
            "/v1/anomark/score": {
                "post": { "summary": "Score a single command against a model" }
            },
            "/v1/anomark/apply": {
                "post": { "summary": "Score process inventories on one or more hosts" }
            },
            "/v1/anomark/auto": {
                "get": { "summary": "Get post-scan AnoMark auto-run config" },
                "put": { "summary": "Update post-scan AnoMark auto-run config" }
            },
            "/v1/anomark/availability": {
                "get": { "summary": "AnoMark training / model availability" }
            },
            "/v1/check-sets": {
                "get": { "summary": "Scan profile → rule plans (pulse/standard/deep/incident)" },
                "put": { "summary": "Replace scan profile rule plans" },
                "post": { "summary": "Reset scan profile plans to defaults" }
            },
            "/v1/activity": {
                "get": { "summary": "Operator activity / scan progress log" }
            },
            "/v1/queue": {
                "get": { "summary": "Scan task queue snapshot" }
            },
            "/v1/openapi.json": {
                "get": { "summary": "This document" }
            }
        }
    })
}
