//! Verification against the real Xcode 27.3 beta 2 archive.
//!
//! `#[ignore]`d by default (multi-GB file, minutes to verify). Run with:
//!
//! ```sh
//! cargo test --release -- --ignored --nocapture fixture
//! ```
//!
//! Override the path with `AEA_FIXTURE=/path/to/file.aea`.

mod common;

use common::check;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires the multi-GB Xcode fixture; run with --ignored"]
fn real_fixture_verifies_green() {
    let path = std::env::var("AEA_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("fixtures/Xcode_27.3_beta_2.aea"));
    if !path.exists() {
        eprintln!("SKIP: fixture not found at {}", path.display());
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_xaea"))
        .arg("inspect")
        .arg(&path)
        .arg("--verify")
        .arg("--json")
        .output()
        .expect("run xaea inspect");
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();

    // Geometry recorded from the real artifact.
    assert_eq!(v["profile"], 0);
    assert_eq!(v["segments"], 624);
    assert_eq!(v["clusters"], 3);
    assert_eq!(v["root"]["original_size"], 10_464_202_071u64);

    // Everything green, through Apple's own root.
    assert_eq!(check(&v, "root_mac_ok"), true);
    assert_eq!(check(&v, "cluster_macs_ok"), true);
    assert_eq!(check(&v, "segment_macs_ok"), true);
    assert_eq!(check(&v, "checksums_failed").as_array().unwrap().len(), 0);
    assert_eq!(check(&v, "content_signature_ok"), true);
    assert_eq!(check(&v, "signature_padded_ok"), true);
    assert_eq!(check(&v, "trusted_root"), true);
    let chain = check(&v, "chain_ok").as_array().unwrap().clone();
    assert!(!chain.is_empty());
    assert!(
        chain.iter().all(|c| c == &Value::Bool(true)),
        "chain: {chain:?}"
    );
}
