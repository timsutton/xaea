//! End-to-end fidelity tests against a synthetic, fully signed profile-0
//! AEA built at test time by scripts/make_test_aea.py.
//!
//! The synthetic archive embeds every structural edge case we rely on:
//! multi-cluster geometry with the last-cluster capacity-padding erratum,
//! a stored (comp == orig) segment, a blob spanning cluster boundaries, a
//! blob ending exactly on a segment boundary, empty files, unicode/space
//! paths, `..`-escaping record and link paths, and non-default modes.
//!
//! Skipped (with a notice) when python3 or the `cryptography` package is
//! unavailable, so `cargo test` never fails merely for missing tooling.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn unaea() -> Command {
    Command::new(env!("CARGO_BIN_EXE_unaea"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "unaea-e2e-{}-{}-{}",
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

/// Build the synthetic archive; returns (dir, manifest). `None` = skip.
fn synthetic(tag: &str) -> Option<(PathBuf, Value)> {
    let has_crypto = Command::new("python3")
        .args(["-I", "-c", "import cryptography"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_crypto {
        eprintln!("SKIP {tag}: python3 with `cryptography` not available");
        return None;
    }
    let dir = tmpdir(tag);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/make_test_aea.py");
    let out = Command::new("python3")
        .args(["-I"])
        .arg(&script)
        .arg(&dir)
        .arg("--seed")
        .arg("1")
        .arg("--evil")
        .output()
        .expect("run builder");
    assert!(
        out.status.success(),
        "builder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    Some((dir, manifest))
}

fn inspect(dir: &Path, extra: &[&str]) -> Value {
    let out = unaea()
        .arg("inspect")
        .arg(dir.join("archive.aea"))
        .args(extra)
        .output()
        .expect("run unaea inspect");
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn walk(dir: &Path, prefix: &str, out: &mut HashMap<String, char>) {
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let rel = format!("{prefix}{}", e.file_name().to_string_lossy());
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            out.insert(rel.clone(), 'D');
            walk(&e.path(), &format!("{rel}/"), out);
        } else if ft.is_symlink() {
            out.insert(rel, 'L');
        } else {
            out.insert(rel, 'F');
        }
    }
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn synthetic_verifies_green() {
    let Some((dir, _)) = synthetic("verify") else {
        return;
    };
    let v = inspect(&dir, &["--verify", "--json"]);
    assert_eq!(v["format"], "AEA1");
    assert_eq!(v["profile"], 0);
    assert_eq!(v["geometry_ok"], true);
    assert_eq!(v["segments"], 5);
    assert_eq!(v["clusters"], 3);
    assert_eq!(v["root"]["segment_size"], 65536);
    assert_eq!(check(&v, "root_mac_ok"), true);
    assert_eq!(check(&v, "cluster_macs_ok"), true);
    assert_eq!(check(&v, "segment_macs_ok"), true);
    assert_eq!(check(&v, "checksums_ok"), 5);
    assert_eq!(check(&v, "checksums_failed").as_array().unwrap().len(), 0);
    assert_eq!(check(&v, "content_signature_ok"), true);
    assert_eq!(check(&v, "signature_padded_ok"), true);
    // Self-signed test leaf must NOT verify to an Apple root.
    assert_eq!(check(&v, "trusted_root"), false);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn synthetic_extract_fidelity() {
    let Some((dir, man)) = synthetic("fidelity") else {
        return;
    };
    let out = dir.join("out");
    let run = unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(&out)
        .arg("--json")
        .output()
        .expect("run extract");
    assert!(
        run.status.success(),
        "extract: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stats: Value = serde_json::from_slice(&run.stdout).unwrap();

    // Record counts the extractor reports.
    assert_eq!(stats["dirs"], man["stats"]["dirs"]);
    assert_eq!(stats["files"], man["stats"]["files"]);
    assert_eq!(stats["links"], man["stats"]["links"]);
    let blob_bytes: u64 = man["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["t"] == "F")
        .map(|e| e["size"].as_u64().unwrap())
        .sum();
    assert_eq!(stats["bytes"], blob_bytes);

    // Exact tree: path set, kinds, contents, modes, link targets.
    let mut actual = HashMap::new();
    walk(&out, "", &mut actual);
    let mut expected = HashMap::new();
    for e in man["entries"].as_array().unwrap() {
        expected.insert(
            e["path"].as_str().unwrap().to_string(),
            e["t"].as_str().unwrap().chars().next().unwrap(),
        );
    }
    assert_eq!(actual, expected, "tree path/kind set");

    for e in man["entries"].as_array().unwrap() {
        let p = out.join(e["path"].as_str().unwrap());
        match e["t"].as_str().unwrap() {
            "F" => {
                let want = unhex(e["hex"].as_str().unwrap());
                let got = fs::read(&p).unwrap();
                assert_eq!(got, want, "content of {}", e["path"]);
                let mut h = Sha256::new();
                h.update(&got);
                // sha2 0.11 output arrays no longer Display as hex
                let digest: [u8; 32] = h.finalize().into();
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(hex, e["sha256"].as_str().unwrap());
                assert_eq!(
                    mode_of(&p),
                    e["mode"].as_u64().unwrap() as u32,
                    "mode of {}",
                    e["path"]
                );
            }
            "L" => {
                let tgt = fs::read_link(&p).unwrap();
                assert_eq!(tgt.to_string_lossy(), e["target"].as_str().unwrap());
            }
            "D" => {
                assert!(p.is_dir());
                assert_eq!(
                    mode_of(&p),
                    e["mode"].as_u64().unwrap() as u32,
                    "dirmode of {}",
                    e["path"]
                );
            }
            _ => unreachable!(),
        }
    }
    // Escaped link target kept verbatim; nothing was created outside root.
    assert_eq!(
        fs::read_link(out.join("T/link-out"))
            .unwrap()
            .to_string_lossy(),
        "../../../SystemFrameworks"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn dry_run_matches_extract_counts() {
    let Some((dir, man)) = synthetic("dry") else {
        return;
    };
    let run = unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(dir.join("dry-out"))
        .arg("--dry-run")
        .arg("--json")
        .output()
        .expect("dry run");
    assert!(run.status.success());
    let stats: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(stats["dry_run"], true);
    assert_eq!(stats["dirs"], man["stats"]["dirs"]);
    assert_eq!(stats["files"], man["stats"]["files"]);
    assert_eq!(stats["links"], man["stats"]["links"]);
    assert!(
        !dir.join("dry-out").exists(),
        "dry run must not create the tree"
    );
    fs::remove_dir_all(&dir).ok();
}

fn flip_byte(path: &Path, off: usize) {
    let mut b = fs::read(path).unwrap();
    b[off] ^= 0x01;
    fs::write(path, &b).unwrap();
}

/// Run `inspect --verify` and return the JSON report if stdout carries one.
/// Since the fail-nonzero change, a failing check still prints the full
/// report and exits 1; only unparseable structure yields `None` — which is
/// itself a detection, so every caller asserts on the outcome either way.
fn verify_report(path: &Path, extra: &[&str]) -> Option<Value> {
    let out = unaea()
        .arg("inspect")
        .arg(path)
        .arg("--verify")
        .args(extra)
        .arg("--json")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).ok()
}

#[test]
fn tampering_is_detected() {
    let Some((dir, _)) = synthetic("tamper") else {
        return;
    };
    let aea = dir.join("archive.aea");
    let meta = inspect(&dir, &["--json"]);
    let auth_bytes = meta["auth"][0]["bytes"].as_u64().unwrap() as usize;
    let sig_off = 12 + auth_bytes;
    let rootmac_off = sig_off + 128 + 32 + 32;
    let c1 = dir.join("t1.aea");

    // Baseline sanity for the copy+flip path itself.
    let base = verify_report(&aea, &["--no-checksums"]).expect("clean copy verifies");
    assert_eq!(check(&base, "root_mac_ok"), true);

    // 1) Signature field corrupted -> refused outright (undecodable DER)
    //    or content_signature_ok false; either counts.
    fs::copy(&aea, &c1).unwrap();
    flip_byte(&c1, sig_off + 10);
    match verify_report(&c1, &["--no-checksums"]) {
        None => {}
        Some(v) => assert_eq!(check(&v, "content_signature_ok"), false, "sig byte flip"),
    }

    // 2) Root MAC field corrupted -> reported false (the MAC is compared,
    //    not parsed). Since review #3, failing checks must also exit
    //    non-zero for CI use.
    fs::copy(&aea, &c1).unwrap();
    flip_byte(&c1, rootmac_off + 5);
    let v = verify_report(&c1, &["--no-checksums"]).expect("root MAC flip still reportable");
    assert_eq!(check(&v, "root_mac_ok"), false, "root MAC flip detected");
    let st = unaea()
        .arg("inspect")
        .arg(&c1)
        .arg("--verify")
        .arg("--no-checksums")
        .output()
        .unwrap();
    assert!(!st.status.success(), "failing checks exit non-zero");
    // extract refuses the same archive; --no-verify is the override hatch.
    let refused = unaea()
        .arg("extract")
        .arg(&c1)
        .arg("-o")
        .arg(dir.join("refused"))
        .output()
        .unwrap();
    assert!(!refused.status.success(), "extract verifies by default");
    let forced = unaea()
        .arg("extract")
        .arg(&c1)
        .arg("-o")
        .arg(dir.join("forced"))
        .arg("--no-verify")
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "--no-verify extracts anyway: {}",
        String::from_utf8_lossy(&forced.stderr)
    );

    // 3) Last segment's payload byte flipped -> segment MAC and/or
    //    checksum must fail; a decode refusal counts too.
    fs::copy(&aea, &c1).unwrap();
    let len = fs::metadata(&c1).unwrap().len() as usize;
    flip_byte(&c1, len - 1);
    match verify_report(&c1, &[]) {
        None => {}
        Some(v) => {
            let mac_fail = check(&v, "segment_macs_ok") == &Value::Bool(false);
            let cks_total = meta["segments"].as_u64().unwrap();
            let cks_fail = check(&v, "checksums_ok").as_u64().unwrap_or(cks_total) < cks_total;
            assert!(mac_fail || cks_fail, "segment payload flip detected");
        }
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn extract_rejects_nonempty_out_but_dry_run_proceeds() {
    let Some((dir, _)) = synthetic("outpolicy") else {
        return;
    };
    let dirty = dir.join("dirty");
    fs::create_dir_all(&dirty).unwrap();
    fs::write(dirty.join("occupant"), b"x").unwrap();

    let blocked = unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(&dirty)
        .output()
        .unwrap();
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("not empty"),
        "clear error message"
    );

    let ok = unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(&dirty)
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(ok.status.success(), "dry-run is safe over existing dirs");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn evil_symlink_archives_are_refused_and_contained() {
    let Some((dir, _)) = synthetic("evil") else {
        return;
    };
    for name in ["evil1.aea", "evil2.aea"] {
        let out = dir.join(format!("out-{name}"));
        let run = unaea()
            .arg("extract")
            .arg(dir.join(name))
            .arg("-o")
            .arg(&out)
            .output()
            .unwrap();
        assert!(
            !run.status.success(),
            "{name}: planted symlink chain must fail extraction: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
    // Nothing escaped into the directory containing the output trees:
    // evil1's target would have put PWNED beside `out-*`, evil2's a link
    // named `tmp`.
    assert!(!dir.join("PWNED").exists(), "tar link attack contained");
    assert!(!dir.join("tmp").exists(), "symlink-through-symlink refused");
    // The evil1 payload landed *inside* the tree as an ordinary file.
    assert!(
        dir.join("out-evil1.aea/app/up/PWNED").exists(),
        "write stayed inside the output root"
    );
    fs::remove_dir_all(&dir).ok();
}

#[cfg(target_os = "macos")]
#[test]
fn quarantine_flag_tags_outputs() {
    let Some((dir, _)) = synthetic("quarantine") else {
        return;
    };
    let out = dir.join("q-out");
    let run = unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(&out)
        .arg("--quarantine")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let probe = Command::new("xattr")
        .args(["-p", "com.apple.quarantine"])
        .arg(out.join("T/plain.txt"))
        .output()
        .unwrap();
    assert!(probe.status.success(), "quarantine xattr present");
    assert!(String::from_utf8_lossy(&probe.stdout).contains("unaea"));

    // And absent without the flag.
    let out2 = dir.join("q-off");
    unaea()
        .arg("extract")
        .arg(dir.join("archive.aea"))
        .arg("-o")
        .arg(&out2)
        .output()
        .unwrap();
    let probe2 = Command::new("xattr")
        .args(["-p", "com.apple.quarantine"])
        .arg(out2.join("T/plain.txt"))
        .output()
        .unwrap();
    assert!(!probe2.status.success(), "no quarantine by default");
    fs::remove_dir_all(&dir).ok();
}
