// SPDX-License-Identifier: EUPL-1.2

//! Compiles `../proto` (the Kotlin <-> Rust schema) with prost, and embeds the
//! pinned attestation roots (`data/roots/*.der`) and a snapshot of Google's
//! attestation revocation list into the library.
//!
//! The revocation list is read from the file named by `HWBP_REVOCATION_STATUS`
//! (the Gradle build downloads it fresh). Android builds with chain verification
//! enabled fail without it. Host builds fall back to an empty list so `cargo test` works offline.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::UNIX_EPOCH;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=../proto");
    let fds = protox::compile(["hwbp/v1/core.proto"], ["../proto"]).unwrap_or_else(|e| panic!("{e}"));
    prost_build::Config::new()
        .compile_fds(fds)
        .unwrap_or_else(|e| panic!("prost-build: {e}"));

    println!("cargo:rerun-if-changed=data/roots");
    println!("cargo:rerun-if-env-changed=HWBP_REVOCATION_STATUS");
    if env::var_os("CARGO_FEATURE_CHAIN_VERIFICATION").is_none() {
        return;
    }

    let mut out = String::new();

    // --- roots ---
    let mut roots: Vec<_> = fs::read_dir("data/roots")
        .expect("data/roots")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "der"))
        .collect();
    roots.sort();
    assert!(!roots.is_empty(), "no pinned roots in data/roots");
    out.push_str("pub static ROOTS: &[(&str, &[u8])] = &[\n");
    for p in &roots {
        let name = p.file_stem().unwrap().to_str().unwrap();
        let abs = fs::canonicalize(p).unwrap();
        writeln!(out, "    ({name:?}, include_bytes!({:?})),", abs.to_str().unwrap()).unwrap();
    }
    out.push_str("];\n");

    // --- revocation list ---
    let target = env::var("TARGET").unwrap_or_default();
    let (entries, snapshot) = match env::var("HWBP_REVOCATION_STATUS") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            load_status(Path::new(&path))
        }
        _ if target.contains("android") => panic!(
            "HWBP_REVOCATION_STATUS is not set. Build through Gradle, which downloads \
             https://android.googleapis.com/attestation/status, or build with \
             --no-default-features to disable chain verification."
        ),
        _ => (BTreeMap::new(), None),
    };
    out.push_str("/// (normalised lowercase hex serial, reason), sorted by serial.\n");
    out.push_str("pub static REVOKED: &[(&str, &str)] = &[\n");
    for (serial, reason) in &entries {
        writeln!(out, "    ({serial:?}, {reason:?}),").unwrap();
    }
    out.push_str("];\n");
    writeln!(out, "pub static REVOCATION_SNAPSHOT_UNIX: Option<u64> = {snapshot:?};").unwrap();

    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("trust.rs");
    fs::write(dest, out).unwrap();
}

fn load_status(path: &Path) -> (BTreeMap<String, String>, Option<u64>) {
    let raw = fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let json: serde_json::Value =
        serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
    let entries = json
        .get("entries")
        .and_then(|e| e.as_object())
        .unwrap_or_else(|| panic!("{} has no \"entries\" object", path.display()));

    let mut out = BTreeMap::new();
    for (serial, v) in entries {
        // Only REVOKED entries matter; SUSPENDED is also treated as revoked.
        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "REVOKED" && status != "SUSPENDED" {
            continue;
        }
        let reason = v.get("reason").and_then(|s| s.as_str()).unwrap_or(status);
        out.insert(normalise_serial(serial), reason.to_owned());
    }
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    (out, mtime)
}

/// Must match `chain::serial_hex`.
fn normalise_serial(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}
