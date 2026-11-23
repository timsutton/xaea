//! Exit-code contract (issue #25): every reachable failure class must exit
//! with the code documented in doc/ERROR-CODES.md. These tests assert exit
//! codes only — never stderr message text, which is not a stable interface.
//!
//! Classes exercised with synthetic inputs: success (0), usage (2),
//! unreadable input (3), rejected archive (4), verification failure (5),
//! extraction failure (6). The 5/6 split needs the fully signed synthetic
//! archive from scripts/make_test_aea.py (same builder tests/e2e.rs uses);
//! those tests skip when python3 or its `cryptography` package is missing.

mod common;

use common::{build_archive, tmpdir, xaea};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Run xaea, return its exit code.
fn code(args: &[&str]) -> i32 {
    let out = xaea().args(args).output().expect("run xaea");
    assert!(
        out.status.code().is_some(),
        "xaea died from a signal on {args:?}"
    );
    out.status.code().unwrap()
}

/// Build the synthetic signed archive; returns its path. `None` = skip.
fn synthetic(tag: &str) -> Option<PathBuf> {
    build_archive(tag, &["--evil"]).map(|dir| dir.join("archive.aea"))
}

/// Copy `src` to `dst`, flipping one bit at `off`.
fn flip_copy(src: &Path, dst: &Path, off: usize) {
    let mut b = fs::read(src).unwrap();
    b[off] ^= 0x01;
    fs::write(dst, &b).unwrap();
}

/// Byte offset of the signature field: 12-byte header + first auth blob.
fn sig_off(aea: &Path) -> usize {
    let out = xaea()
        .arg("inspect")
        .arg(aea)
        .arg("--json")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    12 + v["auth"][0]["bytes"].as_u64().unwrap() as usize
}

#[test]
fn success_and_usage_codes() {
    assert_eq!(code(&["--version"]), 0, "--version succeeds");
    assert_eq!(code(&["--help"]), 0, "--help succeeds");
    assert_eq!(code(&[]), 2, "missing subcommand is a usage error");
    assert_eq!(code(&["bogus"]), 2, "unknown subcommand is a usage error");
    assert_eq!(code(&["inspect", "--bogus-flag", "x"]), 2, "unknown flag");
    assert_eq!(code(&["inspect"]), 2, "missing required argument");
}

#[test]
fn unreadable_input_exits_3() {
    let dir = tmpdir("unreadable");
    let missing = dir.join("nope.aea");
    let out = xaea().arg("inspect").arg(&missing).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "missing path");
    assert!(!out.stderr.is_empty(), "failures still report on stderr");
    assert_eq!(
        code(&[
            "extract",
            missing.to_str().unwrap(),
            dir.join("out").to_str().unwrap()
        ]),
        3,
        "missing path on extract"
    );
    // A directory opens fine but cannot be mmap'd: still unreadable input.
    assert_eq!(
        code(&["inspect", dir.to_str().unwrap()]),
        3,
        "directory input"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn rejected_archive_exits_4() {
    let dir = tmpdir("rejected");
    let garbage = dir.join("garbage.aea");
    fs::write(&garbage, b"not an AEA file, not even close").unwrap();
    assert_eq!(
        code(&["inspect", garbage.to_str().unwrap()]),
        4,
        "bad magic"
    );
    let empty = dir.join("empty.aea");
    fs::write(&empty, b"").unwrap();
    assert_eq!(code(&["inspect", empty.to_str().unwrap()]), 4, "empty file");
    assert_eq!(
        code(&[
            "extract",
            garbage.to_str().unwrap(),
            dir.join("out").to_str().unwrap()
        ]),
        4,
        "bad magic on extract"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn verification_failures_exit_5() {
    let Some(aea) = synthetic("verify5") else {
        return;
    };
    let dir = aea.parent().unwrap();
    let off = sig_off(&aea);

    // Baseline: the clean archive verifies green.
    assert_eq!(
        code(&["inspect", aea.to_str().unwrap()]),
        0,
        "clean inspect"
    );
    assert_eq!(
        code(&[
            "inspect",
            aea.to_str().unwrap(),
            "--verify",
            "--no-checksums"
        ]),
        0,
        "clean verify"
    );

    // Corrupt signature field: refused outright (undecodable DER) or
    // content_signature_ok false — both are verification failures.
    let sigflip = dir.join("sigflip.aea");
    flip_copy(&aea, &sigflip, off + 10);
    assert_eq!(
        code(&[
            "inspect",
            sigflip.to_str().unwrap(),
            "--verify",
            "--no-checksums"
        ]),
        5,
        "corrupt signature"
    );

    // Corrupt root MAC field: a compared check, reported false and bailed.
    // Header(12) + auth + signature(128) + root hash(32) + root salt(32).
    let macflip = dir.join("macflip.aea");
    flip_copy(&aea, &macflip, off + 128 + 32 + 32 + 5);
    assert_eq!(
        code(&[
            "inspect",
            macflip.to_str().unwrap(),
            "--verify",
            "--no-checksums"
        ]),
        5,
        "corrupt root MAC"
    );
    // The JSON report path bails with the same code after printing.
    assert_eq!(
        code(&[
            "inspect",
            macflip.to_str().unwrap(),
            "--verify",
            "--no-checksums",
            "--json"
        ]),
        5,
        "corrupt root MAC, --json"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn extraction_failures_exit_6() {
    let Some(aea) = synthetic("extract6") else {
        return;
    };
    let dir = aea.parent().unwrap();

    // Baseline: clean dry-run and full extract succeed.
    assert_eq!(
        code(&[
            "extract",
            aea.to_str().unwrap(),
            dir.join("clean").to_str().unwrap(),
            "--dry-run"
        ]),
        0,
        "clean dry-run"
    );

    // Top-level entry collision on the second extract.
    let out = dir.join("twice");
    assert_eq!(
        code(&["extract", aea.to_str().unwrap(), out.to_str().unwrap()]),
        0,
        "first extract"
    );
    assert_eq!(
        code(&["extract", aea.to_str().unwrap(), out.to_str().unwrap()]),
        6,
        "collision aborts"
    );

    // Output directory cannot be created (parent is a regular file).
    let blocker = dir.join("blocker");
    fs::write(&blocker, b"x").unwrap();
    assert_eq!(
        code(&[
            "extract",
            aea.to_str().unwrap(),
            blocker.join("sub").to_str().unwrap()
        ]),
        6,
        "unwritable output path"
    );

    // Verification failure detected mid-extract lands on 6, not 5: the
    // streaming extractor folds verification into the pipeline, so the
    // main boundary cannot separate it from I/O (documented merge).
    let off = sig_off(&aea);
    let macflip = dir.join("macflip.aea");
    flip_copy(&aea, &macflip, off + 128 + 32 + 32 + 5);
    assert_eq!(
        code(&[
            "extract",
            macflip.to_str().unwrap(),
            dir.join("refused").to_str().unwrap()
        ]),
        6,
        "extract verifies by default"
    );
    // --no-verify is the override hatch and still succeeds.
    assert_eq!(
        code(&[
            "extract",
            macflip.to_str().unwrap(),
            dir.join("forced").to_str().unwrap(),
            "--no-verify"
        ]),
        0,
        "--no-verify extracts anyway"
    );

    // A truncated archive is rejected (4) before extraction starts.
    let truncated = dir.join("truncated.aea");
    let b = fs::read(&aea).unwrap();
    fs::write(&truncated, &b[..b.len() / 2]).unwrap();
    assert_eq!(
        code(&["inspect", truncated.to_str().unwrap()]),
        4,
        "truncated archive"
    );
    fs::remove_dir_all(dir).ok();
}
