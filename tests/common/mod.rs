//! Helpers shared by the integration tests: running the binary, private
//! temp directories, and building synthetic archives with
//! `scripts/make_test_aea.py`.
//!
//! Each test target compiles its own copy of this module and uses a
//! different subset of it.
#![allow(dead_code, reason = "each test target uses a different subset")]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A `Command` for the binary under test.
pub fn xaea() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xaea"))
}

/// A fresh, uniquely named directory under the system temp dir, prefixed
/// with the test target's name so leftovers are easy to attribute.
pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "xaea-{}-{}-{}-{}",
        env!("CARGO_CRATE_NAME"),
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

/// Build a synthetic signed archive (seed 1, plus `builder_args`) into a
/// fresh directory and return that directory; the archive is
/// `archive.aea` and its manifest `manifest.json`. `None` means skip: the
/// builder needs python3 with the `cryptography` package, and `cargo test`
/// must never fail merely for missing tooling.
pub fn build_archive(tag: &str, builder_args: &[&str]) -> Option<PathBuf> {
    let has_crypto = Command::new("python3")
        .args(["-I", "-c", "import cryptography"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_crypto {
        eprintln!("SKIP {tag}: python3 with `cryptography` not available");
        return None;
    }
    let dir = tmpdir(tag);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/make_test_aea.py");
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(&dir)
        .args(["--seed", "1"])
        .args(builder_args)
        .output()
        .expect("run builder");
    assert!(
        out.status.success(),
        "builder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(dir)
}

/// The builder's `manifest.json` in `dir`.
pub fn manifest(dir: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap()
}

/// The value of `key` in whichever `inspect --json` check object holds it.
pub fn check<'a>(v: &'a Value, key: &str) -> &'a Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c.get(key).is_some())
        .unwrap_or_else(|| panic!("no check object containing {key}"))
        .get(key)
        .unwrap()
}
