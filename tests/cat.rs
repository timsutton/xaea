//! End-to-end tests for `xaea cat` (issue #18's feature, built independently).
//!
//! Prints one regular file from an archive to stdout: byte-exact against
//! the manifest, refusing directories/symlinks, missing members and
//! tampered payloads.
//!
//! Skipped (with a notice) when python3 or the `cryptography` package is
//! unavailable, so `cargo test` never fails merely for missing tooling.

mod common;

use common::{build_archive, manifest, xaea};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Build the signed synthetic archive; returns (dir, manifest). None = skip.
fn synthetic(tag: &str) -> Option<(PathBuf, Value)> {
    let dir = build_archive(tag, &["--evil"])?;
    let m = manifest(&dir);
    Some((dir, m))
}

fn cat(dir: &Path, member: &str) -> std::process::Output {
    xaea()
        .arg("cat")
        .arg(dir.join("archive.aea"))
        .arg(member)
        .output()
        .expect("run xaea cat")
}

#[test]
fn every_file_is_byte_exact() {
    let Some((dir, m)) = synthetic("cat-exact") else {
        return;
    };
    let files: Vec<&Value> = m["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["t"] == "F")
        .collect();
    assert!(files.len() >= 10, "fixture should carry many files");
    for e in files {
        let path = e["path"].as_str().unwrap();
        let want = unhex(e["hex"].as_str().unwrap());
        let out = cat(&dir, path);
        let stdout = out.stdout.clone();
        assert!(
            out.status.success(),
            "cat {path} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(stdout, want, "content of {path}");
    }
}

#[test]
fn member_path_normalization_matches_extraction() {
    let Some((dir, _)) = synthetic("cat-norm") else {
        return;
    };
    let out = cat(&dir, "T/plain.txt");
    assert!(out.status.success());
    let expect = out.stdout.clone();

    for variant in ["./T/plain.txt", "T/../T/plain.txt"] {
        let out = cat(&dir, variant);
        let stdout = out.stdout.clone();
        assert!(
            out.status.success(),
            "cat {variant} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(stdout, expect, "normalized path {variant}");
    }

    // The record whose path escapes above root must print identically
    // regardless of which traversal spelling is used.
    let out = cat(&dir, "escaped/inside.bin");
    let stdout = out.stdout.clone();
    assert!(out.status.success());
    assert_eq!(stdout, b"clamped\n");
    let out = cat(&dir, "T/../../esc/../escaped/inside.bin");
    let stdout = out.stdout.clone();
    assert!(out.status.success());
    assert_eq!(stdout, b"clamped\n");
}

#[test]
fn empty_file_is_empty_stdout() {
    let Some((dir, _)) = synthetic("cat-empty") else {
        return;
    };
    let out = cat(&dir, "T/empty.bin");
    let stdout = out.stdout.clone();
    assert!(out.status.success());
    assert!(stdout.is_empty(), "empty file prints nothing");
}

#[test]
fn directory_member_is_refused() {
    let Some((dir, _)) = synthetic("cat-dir") else {
        return;
    };
    let out = cat(&dir, "T/sub dir");
    let stdout = out.stdout.clone();
    assert!(!out.status.success(), "directory member must fail");
    assert!(stdout.is_empty(), "directory member prints nothing");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("directory"), "stderr names the reason: {err}");
}

#[test]
fn symlink_member_is_refused() {
    let Some((dir, _)) = synthetic("cat-link") else {
        return;
    };
    let out = cat(&dir, "T/link-rel");
    let stdout = out.stdout.clone();
    assert!(!out.status.success(), "symlink member must fail");
    assert!(stdout.is_empty(), "symlink member prints nothing");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("symlink"), "stderr names the reason: {err}");
}

#[test]
fn missing_member_exits_nonzero_with_empty_stdout() {
    let Some((dir, _)) = synthetic("cat-missing") else {
        return;
    };
    let out = cat(&dir, "T/does-not-exist");
    let stdout = out.stdout.clone();
    assert!(!out.status.success(), "missing member must fail");
    assert_eq!(out.status.code(), Some(6), "extraction-domain exit code");
    assert!(stdout.is_empty(), "missing member prints nothing");
}

#[test]
fn tampered_payload_is_refused() {
    let Some((dir, _)) = synthetic("cat-tamper") else {
        return;
    };
    let aea = dir.join("archive.aea");
    let corrupt = dir.join("corrupt.aea");
    let mut b = fs::read(&aea).unwrap();
    let off = first_segment_data_off(&b);
    b[off + 10] ^= 0xFF;
    fs::write(&corrupt, &b).unwrap();

    let out = xaea()
        .arg("cat")
        .arg(&corrupt)
        .arg("T/plain.txt")
        .output()
        .expect("run xaea cat");
    assert!(
        !out.status.success(),
        "tampered archive must fail verification"
    );
    assert!(
        out.stdout.is_empty(),
        "tampered archive must not print bytes"
    );
}

#[test]
fn stdin_archive_works() {
    let Some((dir, _)) = synthetic("cat-stdin") else {
        return;
    };
    let bytes = fs::read(dir.join("archive.aea")).unwrap();
    let mut child = xaea()
        .args(["cat", "-", "T/plain.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn xaea cat -");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&bytes)
        .expect("write archive to stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stdin archive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hello xcode\n".repeat(7));
}

/// Byte offset of segment 0's stored data within the archive. The segment
/// header and stored checksum are read at the geometry from the root
/// header; the first cluster holds segments 0..segments_per_cluster.
fn first_segment_data_off(b: &[u8]) -> usize {
    let auth_len = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    let root_off = 12 + auth_len + 128 + 32 + 32 + 32;
    let root = &b[root_off..root_off + 0x30];
    let spc = u32::from_le_bytes(root[0x14..0x18].try_into().unwrap()) as usize;
    let seg_hdr_len = 8 + 32; // u32 comp, u32 orig, SHA-256 checksum
    let chmac_off = root_off + 0x30;
    let seghdrs_off = chmac_off + 32; // first cluster MAC
    seghdrs_off + spc * seg_hdr_len + 32 + spc * 32
}

#[test]
fn help_lists_cat() {
    let out = xaea().arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("cat"), "help lists the cat subcommand");
}
