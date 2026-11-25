//! Encrypted (profile 1) archives, as Apple ships restore images: `decrypt`,
//! key handling (`--key`, `--key-pem`), `inspect` with and without a key,
//! and the refusals and failure codes around them. Uses the synthetic
//! `p1.aea` from `scripts/make_test_aea.py --profile1`, which Apple's own
//! `aea decrypt` accepts (checked by hand at Apple's cluster geometry; see
//! doc/FORMAT-NOTES.md). Skips when python3/`cryptography` is missing.

mod common;

use common::{build_archive, check, tmpdir, xaea};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

struct P1 {
    dir: PathBuf,
    aea: String,
    pem: String,
    other_pem: String,
    key: String,
    meta: Value,
}

fn p1(tag: &str) -> Option<P1> {
    let dir = build_archive(tag, &["--profile1"])?;
    let s = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let meta: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("p1.json")).unwrap()).unwrap();
    Some(P1 {
        aea: s("p1.aea"),
        pem: s("p1-key.pem"),
        other_pem: s("p1-other.pem"),
        key: meta["key"].as_str().unwrap().to_owned(),
        meta,
        dir,
    })
}

fn run(args: &[&str]) -> Output {
    let out = xaea().args(args).output().expect("run xaea");
    assert!(
        out.status.code().is_some(),
        "xaea died from a signal on {args:?}"
    );
    out
}

fn code(args: &[&str]) -> i32 {
    run(args).status.code().unwrap()
}

/// Copy `src` to `dst` with one bit flipped at `off` (negative: from EOF).
fn flip_copy(src: &str, dst: &Path, off: isize) {
    let mut b = fs::read(src).unwrap();
    let at = if off < 0 {
        b.len() - off.unsigned_abs()
    } else {
        off as usize
    };
    b[at] ^= 0x01;
    fs::write(dst, &b).unwrap();
}

#[test]
fn decrypt_with_key_or_pem_reproduces_the_payload() {
    let Some(p) = p1("p1-decrypt") else { return };
    let want = fs::read(p.dir.join("p1.payload")).unwrap();
    for (name, flag, val) in [
        ("by-key.bin", "--key", format!("base64:{}", p.key)),
        ("by-pem.bin", "--key-pem", p.pem.clone()),
    ] {
        let out = p.dir.join(name);
        let o = run(&[
            "decrypt",
            &p.aea,
            out.to_str().unwrap(),
            flag,
            &val,
            "--json",
        ]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(fs::read(&out).unwrap(), want, "{name}");
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["verified"], true);
    }
    // --no-verify takes the same path minus the checks.
    let out = p.dir.join("noverify.bin");
    assert_eq!(
        code(&[
            "decrypt",
            &p.aea,
            out.to_str().unwrap(),
            "--key-pem",
            &p.pem,
            "--no-verify"
        ]),
        0
    );
    assert_eq!(fs::read(&out).unwrap(), want);
}

#[test]
fn decrypt_names_the_output_after_the_archive() {
    let Some(p) = p1("p1-name") else { return };
    let o = xaea()
        .current_dir(&p.dir)
        .args(["decrypt", "p1.aea", "--key-pem", "p1-key.pem"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        fs::read(p.dir.join("p1")).unwrap(),
        fs::read(p.dir.join("p1.payload")).unwrap()
    );
    // ...and never overwrites it.
    let again = xaea()
        .current_dir(&p.dir)
        .args(["decrypt", "p1.aea", "--key-pem", "p1-key.pem"])
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(6), "existing output is refused");
}

#[test]
fn inspect_without_a_key_describes_the_prelude() {
    let Some(p) = p1("p1-locked") else { return };
    let o = run(&["inspect", &p.aea, "--json"]);
    assert!(o.status.success());
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["profile"], 1);
    assert_eq!(v["encrypted"], true);
    assert!(
        v["root"].is_null(),
        "headers are unreadable without the key"
    );
    assert!(v["key_url"].as_str().unwrap().contains("/fcs-keys/"));
}

#[test]
fn inspect_verify_with_a_key_checks_everything() {
    let Some(p) = p1("p1-verify") else { return };
    let o = run(&["inspect", &p.aea, "--key-pem", &p.pem, "--verify", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["segments"], p.meta["segments"]);
    assert_eq!(v["padding"], p.meta["padding"]);
    assert_eq!(v["root"]["original_size"], p.meta["original_size"]);
    for k in [
        "root_mac_ok",
        "cluster_macs_ok",
        "padding_mac_ok",
        "segment_macs_ok",
    ] {
        assert_eq!(check(&v, k), true, "{k}");
    }
    assert_eq!(check(&v, "checksums_ok"), &p.meta["segments"]);
}

#[test]
fn key_problems_exit_7() {
    let Some(p) = p1("p1-keys") else { return };
    let out = p.dir.join("out.bin");
    let out = out.to_str().unwrap();
    let zero = format!("hex:{}", "00".repeat(32));
    assert_eq!(code(&["decrypt", &p.aea, out]), 7, "no key");
    assert_eq!(
        code(&["inspect", &p.aea, "--verify"]),
        7,
        "no key to verify with"
    );
    assert_eq!(
        code(&["decrypt", &p.aea, out, "--key", &zero]),
        7,
        "wrong key"
    );
    assert_eq!(
        code(&["decrypt", &p.aea, out, "--key", "base64:AAAA"]),
        7,
        "short key"
    );
    assert_eq!(
        code(&["decrypt", &p.aea, out, "--key-pem", &p.other_pem]),
        7,
        "foreign PEM"
    );
    let missing = p.dir.join("missing.pem");
    assert_eq!(
        code(&[
            "decrypt",
            &p.aea,
            out,
            "--key-pem",
            missing.to_str().unwrap()
        ]),
        7,
        "unreadable PEM"
    );
    assert!(!Path::new(out).exists(), "no output on key failures");
}

#[test]
fn file_tree_commands_refuse_disk_images() {
    let Some(p) = p1("p1-refuse") else { return };
    let dest = tmpdir("p1-refuse-out");
    assert_eq!(code(&["extract", &p.aea, dest.to_str().unwrap()]), 4);
    assert_eq!(code(&["cat", &p.aea, "x"]), 4);
    fs::remove_dir_all(dest).ok();
}

#[test]
fn tampering_fails_verification() {
    let Some(p) = p1("p1-tamper") else { return };
    // One bit in the last segment's data (just before the padding), and
    // one in the padding itself.
    let pad = p.meta["padding"].as_u64().unwrap() as isize;
    for (name, off, check_name) in [
        ("seg.aea", -pad - 5, "segment_macs_ok"),
        ("pad.aea", -7, "padding_mac_ok"),
    ] {
        let bad = p.dir.join(name);
        flip_copy(&p.aea, &bad, off);
        let bad = bad.to_str().unwrap();
        let o = run(&["inspect", bad, "--key-pem", &p.pem, "--verify", "--json"]);
        assert_eq!(o.status.code(), Some(5), "{name}: inspect --verify");
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(check(&v, check_name), false, "{name}");
        let out = p.dir.join(format!("{name}.bin"));
        assert_eq!(
            code(&["decrypt", bad, out.to_str().unwrap(), "--key-pem", &p.pem]),
            6,
            "{name}: decrypt"
        );
        assert!(!out.exists(), "{name}: a failed decrypt leaves no output");
    }
}

#[test]
fn decrypt_writes_a_signed_archives_raw_payload() {
    // Profile 0 needs no key: `decrypt` writes its AA01 stream verbatim.
    let Some(dir) = build_archive("p0-decrypt", &[]) else {
        return;
    };
    let out = dir.join("stream.aa");
    let aea = dir.join("archive.aea");
    let o = run(&["decrypt", aea.to_str().unwrap(), out.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let manifest = common::manifest(&dir);
    let stream = fs::read(&out).unwrap();
    assert_eq!(
        stream.len() as u64,
        manifest["original_size"].as_u64().unwrap()
    );
    assert_eq!(&stream[..4], b"AA01");
}
