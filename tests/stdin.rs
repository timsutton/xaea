//! Tests for reading the archive from standard input via the conventional
//! `-` path: the spool must preserve every file-path guarantee (full EOF
//! geometry checks, clean refusals for empty/truncated/non-archive input),
//! honour `TMPDIR`, and leave no spool file behind — on success and on
//! every failure path.

mod common;

use common::{fixture, fixture_json, tmpdir, xaea};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Run xaea with `input` piped to stdin, under a private TMPDIR so the
/// spool location is observable. Returns the output plus that TMPDIR.
fn run_piped(args: &[&str], input: &[u8], tag: &str) -> (std::process::Output, PathBuf) {
    let spool_home = tmpdir(&format!("{tag}-tmp"));
    let mut child = xaea()
        .args(args)
        .env("TMPDIR", &spool_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xaea");
    // The child spools stdin to disk before parsing, so it always drains:
    // writing before waiting cannot deadlock on the pipe buffer.
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out, spool_home)
}

fn assert_no_spool_left(home: &Path, ctx: &str) {
    let left: Vec<_> = fs::read_dir(home)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        left.is_empty(),
        "{ctx}: spool files left in TMPDIR: {left:?}"
    );
}

#[test]
fn inspect_reads_archive_from_stdin() {
    let bytes = fs::read(fixture("archive.aea")).unwrap();
    let (out, spool_home) = run_piped(&["inspect", "-", "--verify", "--json"], &bytes, "inspect");
    assert!(
        out.status.success(),
        "inspect -: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["format"], "AEA1");
    assert_eq!(v["file"], "-");
    assert_eq!(v["file_size"], bytes.len() as u64);
    assert_eq!(v["segments"], 7);
    assert_eq!(v["geometry_ok"], true);
    // Same verdict as the file path produces (e2e::synthetic_verifies_green).
    let check = |key: &str| {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c.get(key).is_some())
            .unwrap()
            .get(key)
            .unwrap()
            .clone()
    };
    assert_eq!(check("root_mac_ok"), Value::Bool(true));
    assert_eq!(check("segment_macs_ok"), Value::Bool(true));
    assert_eq!(check("content_signature_ok"), Value::Bool(true));
    assert_no_spool_left(&spool_home, "inspect ok");
    fs::remove_dir_all(&spool_home).ok();
}

#[test]
fn extract_reads_archive_from_stdin() {
    let bytes = fs::read(fixture("archive.aea")).unwrap();
    let man = fixture_json("manifest.json");
    let dir = tmpdir("extract");
    let out_dir = dir.join("out");
    let (run, spool_home) = run_piped(
        &[
            "extract",
            "-",
            out_dir.to_str().unwrap(),
            "--json",
            "--no-compress",
        ],
        &bytes,
        "extract",
    );
    assert!(
        run.status.success(),
        "extract -: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stats: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(stats["dirs"], man["stats"]["dirs"]);
    assert_eq!(stats["files"], man["stats"]["files"]);
    assert_eq!(stats["links"], man["stats"]["links"]);
    assert!(out_dir.join("T/plain.txt").is_file(), "payload landed");
    assert_no_spool_left(&spool_home, "extract ok");
    fs::remove_dir_all(&dir).ok();
    fs::remove_dir_all(&spool_home).ok();
}

#[test]
fn truncated_pipe_is_refused_by_the_eof_check() {
    let bytes = fs::read(fixture("archive.aea")).unwrap();
    // Cut the tail: the segment walk must notice the stream ends early.
    let (out, spool_home) = run_piped(&["inspect", "-"], &bytes[..bytes.len() - 1000], "trunc");
    assert!(!out.status.success(), "truncated stdin must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("EOF") || err.contains("geometry mismatch"),
        "refusal should name the EOF/geometry check, got: {err}"
    );
    assert_no_spool_left(&spool_home, "truncated");
    fs::remove_dir_all(&spool_home).ok();
}

#[test]
fn non_archive_on_stdin_is_refused() {
    let junk = b"this is not an Apple Encrypted Archive, not even close".repeat(8);
    let (out, spool_home) = run_piped(&["inspect", "-"], &junk, "notaea");
    assert!(!out.status.success(), "junk stdin must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not an AEA"), "clear refusal: {err}");
    assert_no_spool_left(&spool_home, "junk");
    fs::remove_dir_all(&spool_home).ok();
}

#[test]
fn empty_stdin_is_refused() {
    let (out, spool_home) = run_piped(&["inspect", "-"], b"", "empty");
    assert!(!out.status.success(), "empty stdin must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("empty"), "clear refusal: {err}");
    assert_no_spool_left(&spool_home, "empty");
    fs::remove_dir_all(&spool_home).ok();
}

#[test]
fn dash_is_rejected_as_output_dir() {
    let run = xaea()
        .arg("extract")
        .arg(fixture("archive.aea"))
        .arg("-")
        .output()
        .unwrap();
    assert!(!run.status.success(), "`-` is not an output directory");
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(err.contains("standard input"), "clear error: {err}");
}
