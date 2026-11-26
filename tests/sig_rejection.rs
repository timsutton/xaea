//! Corrupt / invalid-signature archives must be refused (issue #49).
//!
//! `scripts/make_test_aea.py --tamper` generates one broken variant of the
//! signed synthetic archive per rejection path: wrong signature bytes, a
//! signature that opens no DER SEQUENCE, a signature length that runs past
//! its field, dirty signature padding, a chain whose leaf was not signed by
//! its stated issuer, and a truncated envelope. `tamper.json` records the
//! expected failures for each variant.
//!
//! For every variant we assert all three of: `extract` exits non-zero without
//! writing an output tree and prints a reason naming the failure mode;
//! `inspect --verify` exits non-zero; and the JSON report marks exactly the
//! expected check false (for variants that still parse). Message matching is
//! on lowercase substrings chosen to distinguish the paths, not exact text.

mod common;

use common::{check, fixture, fixture_json, tmpdir, xaea};
use serde_json::Value;
use std::fs;

fn cases() -> Vec<Value> {
    let man = fixture_json("tamper.json");
    let cases = man["cases"].as_array().unwrap().clone();
    assert!(
        cases.len() >= 4,
        "tamper.json should cover several distinct rejection paths, got {}",
        cases.len()
    );
    cases
}

#[test]
fn corrupt_signature_archives_are_refused() {
    let dir = tmpdir("refuse");
    // The uncorrupted archive must pass, or none of this means anything.
    let clean = xaea()
        .arg("inspect")
        .arg(fixture("archive.aea"))
        .arg("--verify")
        .arg("--no-checksums")
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "baseline archive must verify: {}",
        String::from_utf8_lossy(&clean.stderr)
    );

    for c in cases() {
        let name = c["name"].as_str().unwrap();
        let mode = c["mode"].as_str().unwrap();
        let aea = fixture(name);
        assert!(aea.exists(), "{name}: missing corruption fixture");

        // --- extract: refuse, explain, and touch nothing -------------------
        let out = dir.join(format!("out-{name}"));
        let run = xaea().arg("extract").arg(&aea).arg(&out).output().unwrap();
        assert!(!run.status.success(), "{mode}: extract must fail");
        let err = String::from_utf8_lossy(&run.stderr).to_lowercase();
        assert!(
            !err.trim().is_empty(),
            "{mode}: refusal must print a reason on stderr"
        );
        for needle in c["expect"].as_array().unwrap() {
            let needle = needle.as_str().unwrap();
            assert!(
                err.contains(needle),
                "{mode}: stderr must mention {needle:?}, got: {err}"
            );
        }
        assert!(
            !out.exists() || fs::read_dir(&out).unwrap().next().is_none(),
            "{mode}: refused archive must leave no output tree in {}",
            out.display()
        );
        // And no success summary on stdout either.
        assert!(
            run.stdout.is_empty(),
            "{mode}: refused archive must not report a successful extract: {}",
            String::from_utf8_lossy(&run.stdout)
        );

        // --- inspect --verify: same verdict, machine-readable --------------
        let insp = xaea()
            .arg("inspect")
            .arg(&aea)
            .arg("--verify")
            .arg("--no-checksums")
            .arg("--json")
            .output()
            .unwrap();
        assert!(!insp.status.success(), "{mode}: inspect --verify must fail");
        let report: Option<Value> = serde_json::from_slice(&insp.stdout).ok();
        let Some(report) = report else {
            assert!(
                !c["parses"].as_bool().unwrap(),
                "{mode}: expected a report, got none: {}",
                String::from_utf8_lossy(&insp.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&insp.stderr).trim().is_empty(),
                "{mode}: unparseable archive must still explain itself"
            );
            continue;
        };
        assert!(
            c["parses"].as_bool().unwrap(),
            "{mode}: report produced for an archive expected not to parse"
        );
        for key in c["check_false"].as_array().unwrap() {
            let key = key.as_str().unwrap();
            assert_eq!(check(&report, key), false, "{mode}: {key} must be false");
        }
        for key in c["check_true"].as_array().unwrap() {
            let key = key.as_str().unwrap();
            assert_eq!(check(&report, key), true, "{mode}: {key} must stay true");
        }
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn corrupt_signature_archives_extract_only_when_forced() {
    // `--no-verify` stays the only way through: every archive that still
    // parses extracts when forced, while the truncated envelope is refused
    // as malformed no matter what is asked of it.
    let dir = tmpdir("forced");
    for c in cases() {
        let name = c["name"].as_str().unwrap();
        let mode = c["mode"].as_str().unwrap();
        let out = dir.join(format!("forced-{name}"));
        let run = xaea()
            .arg("extract")
            .arg(fixture(name))
            .arg(&out)
            .arg("--no-verify")
            .output()
            .unwrap();
        if c["parses"].as_bool().unwrap() {
            assert!(
                run.status.success(),
                "{mode}: --no-verify must extract anyway: {}",
                String::from_utf8_lossy(&run.stderr)
            );
        } else {
            assert!(
                !run.status.success(),
                "{mode}: malformed even with --no-verify"
            );
        }
    }
    fs::remove_dir_all(&dir).ok();
}
