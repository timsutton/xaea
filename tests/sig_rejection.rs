//! Corrupt / invalid-signature archives must be refused (issue #49).
//!
//! `scripts/make_test_aea.py --tamper` builds the same fully signed synthetic
//! archive the e2e suite uses, then derives one broken variant per rejection
//! path — wrong signature bytes, a signature that opens no DER SEQUENCE, a
//! signature length that runs past its field, dirty signature padding, a
//! chain whose leaf was not signed by its stated issuer, and a truncated
//! envelope — and records in `tamper.json` what each must trip.
//!
//! For every variant we assert all three of: `extract` exits non-zero without
//! writing an output tree and prints a reason naming the failure mode;
//! `inspect --verify` exits non-zero; and the JSON report marks exactly the
//! expected check false (for variants that still parse). Message matching is
//! on lowercase substrings chosen to distinguish the paths, not exact text.
//!
//! Skipped (with a notice) when python3 or the `cryptography` package is
//! unavailable — unless `AEA_REQUIRE_SYNTHETIC=1` is set, which CI does so a
//! silently-untested rejection path can never go green again.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn xaea() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xaea"))
}

/// Build the signed archive plus its corrupt variants; returns the dir.
/// `tag` keeps concurrent tests in separate directories. `None` = skip
/// (builder tooling missing and not required).
fn tamper_set(tag: &str) -> Option<PathBuf> {
    let has_crypto = Command::new("python3")
        .args(["-I", "-c", "import cryptography"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_crypto {
        let msg = "python3 with `cryptography` not available: the synthetic \
                   AEA builder cannot run, so the corrupt-signature rejection \
                   paths are UNTESTED (pip install cryptography to run them)";
        if std::env::var("AEA_REQUIRE_SYNTHETIC").is_ok_and(|v| v == "1") {
            panic!("{msg}");
        }
        eprintln!("SKIP {tag}: {msg}");
        return None;
    }
    let dir = std::env::temp_dir().join(format!(
        "xaea-sigreject-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let out = Command::new("python3")
        .args(["-I"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/make_test_aea.py"))
        .arg(&dir)
        .arg("--seed")
        .arg("1")
        .arg("--tamper")
        .output()
        .expect("run builder");
    assert!(
        out.status.success(),
        "builder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(dir)
}

fn check<'a>(v: &'a Value, key: &str) -> &'a Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c.get(key).is_some())
        .unwrap_or_else(|| panic!("no check object containing {key}"))
        .get(key)
        .unwrap()
}

fn cases(dir: &Path) -> Vec<Value> {
    let man: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("tamper.json")).unwrap()).unwrap();
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
    let Some(dir) = tamper_set("refuse") else {
        return;
    };
    // The uncorrupted archive must pass, or none of this means anything.
    let clean = xaea()
        .arg("inspect")
        .arg(dir.join("archive.aea"))
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

    for c in cases(&dir) {
        let name = c["name"].as_str().unwrap();
        let mode = c["mode"].as_str().unwrap();
        let aea = dir.join(name);
        assert!(aea.exists(), "{name}: builder did not write it");

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
    let Some(dir) = tamper_set("forced") else {
        return;
    };
    for c in cases(&dir) {
        let name = c["name"].as_str().unwrap();
        let mode = c["mode"].as_str().unwrap();
        let out = dir.join(format!("forced-{name}"));
        let run = xaea()
            .arg("extract")
            .arg(dir.join(name))
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
