//! Helpers shared by the integration tests for running the binary, creating
//! private temp directories, and reading checked-in synthetic fixtures.
//!
//! Each test target compiles its own copy of this module and uses a
//! different subset of it.
#![allow(dead_code, reason = "each test target uses a different subset")]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf, absolute};
use std::process::Command;

/// A `Command` for the binary under test.
pub fn xaea() -> Command {
    Command::new(absolute(env!("CARGO_BIN_EXE_xaea")).expect("resolve the xaea test binary"))
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

/// Absolute path to a checked-in synthetic archive or manifest.
pub fn fixture(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    absolute(path).expect("resolve the synthetic fixture path")
}

pub fn fixture_json(name: &str) -> Value {
    let path = fixture(name);
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
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

/// Byte offset of the signature field: 12-byte header ("AEA1" + 4 zeros +
/// the u32 length of the encoded auth section) followed by the whole
/// encoded auth section (length prefix, key, terminator, values). The
/// signature sits after that entire section, not after the first auth
/// value.
pub fn sig_off(path: &Path) -> usize {
    let b = fs::read(path).unwrap();
    let auth_len = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    12 + auth_len
}
