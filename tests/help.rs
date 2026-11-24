//! CLI-UI contract: bare invocation prints help and exits 0, every
//! subcommand documents copy-pasteable examples and a docs pointer in
//! its help, `version --json` is machine-readable, and `--json` failures
//! produce a JSON error envelope on stderr (stdout stays empty).

use std::process::Command;

fn xaea() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xaea"))
}

#[test]
fn bare_invocation_prints_help_and_succeeds() {
    let out = xaea().output().expect("run xaea");
    assert_eq!(out.status.code(), Some(0), "bare invocation exits 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage:"), "bare invocation prints usage");
    assert!(
        stdout.contains("Examples:"),
        "bare invocation prints examples"
    );
}

#[test]
fn every_subcommand_help_has_examples_and_docs() {
    for sub in ["inspect", "extract", "cat", "completions", "version"] {
        let out = xaea().args([sub, "--help"]).output().unwrap();
        assert!(out.status.success(), "{sub} --help succeeds");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Examples:"), "{sub}: missing Examples");
        assert!(
            stdout.contains("Docs: https://github.com/timsutton/xaea"),
            "{sub}: missing docs pointer"
        );
    }
}

#[test]
fn version_json_is_machine_readable() {
    // Both the flag and the subcommand honor --json.
    for args in [vec!["version", "--json"], vec!["--version", "--json"]] {
        let out = xaea().args(&args).output().unwrap();
        assert!(out.status.success(), "{args:?} succeeds");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }
    let out = xaea().args(["version"]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("xaea {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn usage_error_under_json_is_machine_readable() {
    let out = xaea()
        .args(["inspect", "--bogus-flag", "x", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "stdout stays empty on failure");
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(v["error"]["code"], "USAGE");
    assert_eq!(v["error"]["exit_code"], 2);
}

#[test]
fn runtime_error_under_json_names_the_class() {
    let out = xaea()
        .args(["inspect", "--json", "/nonexistent/nope.aea"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty(), "stdout stays empty on failure");
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(v["error"]["code"], "UNREADABLE");
    assert_eq!(v["error"]["exit_code"], 3);
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty())
    );
}
