//! Tests for the final symlink pass (`link_pass` in `src/extract.rs`).
//!
//! That pass is security-relevant: symlinks are deferred until every file
//! blob has landed precisely so a planted `x -> ..` cannot redirect a later
//! write out of the tree, and a link whose path traverses another archive
//! link is refused. It now creates links on several threads, so these tests
//! pin the two things concurrency must not move — the guard still fires, and
//! the resulting tree is the same one the sequential pass produced — plus
//! the pass's fallbacks (missing parent, occupied name).
//!
//! Drives the binary against archives built at test time by
//! `scripts/make_test_aea.py`; skipped with a notice when python3 or the
//! `cryptography` package is unavailable, like `tests/e2e.rs`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Link count for the many-links archive: comfortably past the extractor's
/// parallel-path threshold, small enough to build and extract fast.
const MANY_LINKS: usize = 1200;

fn xaea() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xaea"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "xaea-linkpass-{}-{}-{}",
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

/// Build the adversarial and many-links archives; `None` = skip the test.
fn build(tag: &str, links: usize) -> Option<PathBuf> {
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
        .arg("--links")
        .arg(links.to_string())
        .output()
        .expect("run builder");
    assert!(
        out.status.success(),
        "builder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(dir)
}

fn extract(archive: &Path, out: &Path, extra: &[&str]) -> std::process::Output {
    xaea()
        .arg("extract")
        .arg(archive)
        .arg(out)
        .args(extra)
        .output()
        .unwrap()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Sorted (relpath, kind, target-or-mode) lines, for comparing two trees.
fn snapshot(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let md = fs::symlink_metadata(&p).unwrap();
            let kind = if md.is_symlink() {
                format!("L {}", fs::read_link(&p).unwrap().display())
            } else if md.is_dir() {
                format!("D {:o}", md.permissions().mode())
            } else {
                format!("F {:o} {}", md.permissions().mode(), md.len())
            };
            out.push(format!("{rel}\t{kind}"));
            if md.is_dir() {
                walk(root, &p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// The classic tar link attack: symlink `app/up -> ..` plus a file record
/// whose path passes through it. The link must not exist while the file is
/// written, so `PWNED` lands *inside* the tree as an ordinary file, and the
/// link itself is then refused because a real directory is in the way.
#[test]
fn link_then_file_attack_stays_inside() {
    let Some(dir) = build("attack", 1) else {
        return;
    };
    let out = dir.join("out");
    let run = extract(&dir.join("evil1.aea"), &out, &[]);
    assert!(
        !run.status.success(),
        "planted symlink chain must fail extraction: {}",
        stderr(&run)
    );
    // `app/up -> ..` resolves one level above the output root, so an escape
    // would put PWNED next to `out`, not under it.
    assert!(!dir.join("PWNED").exists(), "write escaped the output root");
    assert!(
        out.join("app/up/PWNED").is_file(),
        "write should have stayed inside as an ordinary file"
    );
    assert!(
        out.join("app/up").is_dir(),
        "`app/up` must still be the real directory the file was written into"
    );
    fs::remove_dir_all(&dir).ok();
}

/// A link record whose path traverses a link created earlier in the same
/// pass is refused — and so is the same pair spelled with capitals, which a
/// case-sensitive guard comparison used to let through.
#[test]
fn nested_link_records_are_refused() {
    let Some(dir) = build("nested", 1) else {
        return;
    };
    for name in ["evil2.aea", "evil3.aea"] {
        let out = dir.join(format!("out-{name}"));
        let run = extract(&dir.join(name), &out, &[]);
        let err = stderr(&run);
        assert!(
            !run.status.success(),
            "{name}: link-through-link must fail extraction: {err}"
        );
        assert!(
            err.contains("traverses archive-created symlink"),
            "{name}: expected the traversal guard to fire, got: {err}"
        );
        // Both archives aim the second link at `tmp`, which would resolve
        // beside the output root if the traversal were allowed.
        assert!(!dir.join("tmp").exists(), "{name}: link escaped the root");
        fs::remove_dir_all(&out).ok();
    }
    fs::remove_dir_all(&dir).ok();
}

/// Every link of a tree far larger than the parallel-path threshold exists
/// with the recorded target, including the missing-parent and occupant cases.
#[test]
fn many_links_extract_with_recorded_targets() {
    let Some(dir) = build("many", MANY_LINKS) else {
        return;
    };
    let out = dir.join("out");
    let run = extract(&dir.join("links.aea"), &out, &[]);
    assert!(run.status.success(), "{}", stderr(&run));
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("links-manifest.json")).unwrap())
            .unwrap();
    let links = manifest["links"].as_array().unwrap();
    assert_eq!(links.len(), MANY_LINKS + 1);
    for e in links {
        let path = e["path"].as_str().unwrap();
        let target = e["target"].as_str().unwrap();
        let p = out.join(path);
        let got = fs::read_link(&p)
            .unwrap_or_else(|err| panic!("{path}: not a symlink: {err}"))
            .display()
            .to_string();
        assert_eq!(got, target, "{path} target");
    }
    fs::remove_dir_all(&dir).ok();
}

/// A link whose parent directory has no record at all: the pass creates the
/// parents on demand rather than failing.
#[test]
fn link_with_missing_parent_gets_its_dirs() {
    let Some(dir) = build("orphan", MANY_LINKS) else {
        return;
    };
    let out = dir.join("out");
    let run = extract(&dir.join("links.aea"), &out, &[]);
    assert!(run.status.success(), "{}", stderr(&run));
    // `orphan/NN/missing/parent/lK` for K % 7 == 2; no D record exists for
    // any component under `orphan`.
    let orphans: Vec<PathBuf> = (0..MANY_LINKS as u32)
        .filter(|i| i % 7 == 2)
        .map(|i| out.join(format!("orphan/{:02}/missing/parent/l{}", i % 20, i)))
        .collect();
    assert!(orphans.len() > 100);
    for p in &orphans {
        assert!(p.is_symlink(), "{} missing", p.display());
        assert!(
            p.parent().unwrap().is_dir(),
            "{} missing",
            p.parent().unwrap().display()
        );
    }
    fs::remove_dir_all(&dir).ok();
}

/// A regular file already occupying the link's name is replaced, not refused,
/// and the archive still extracts clean.
#[test]
fn link_over_existing_occupant_is_replaced() {
    let Some(dir) = build("occupant", MANY_LINKS) else {
        return;
    };
    let out = dir.join("out");
    let run = extract(&dir.join("links.aea"), &out, &[]);
    assert!(run.status.success(), "{}", stderr(&run));
    let p = out.join("P/F/0000/occupied");
    assert!(
        p.is_symlink(),
        "occupant should have been replaced by a link"
    );
    assert_eq!(
        fs::read_link(&p).unwrap().display().to_string(),
        "now-a-link"
    );
    fs::remove_dir_all(&dir).ok();
}

/// The concurrency regression test: `--writers 1` forces the sequential pass,
/// `--writers 6` the concurrent one, and the two trees must be identical down
/// to every link target and mode.
#[test]
fn concurrent_and_sequential_passes_agree() {
    let Some(dir) = build("agree", MANY_LINKS) else {
        return;
    };
    let mut snaps = Vec::new();
    for w in ["1", "6"] {
        let out = dir.join(format!("out-w{w}"));
        let run = extract(&dir.join("links.aea"), &out, &["--writers", w]);
        assert!(run.status.success(), "--writers {w}: {}", stderr(&run));
        snaps.push(snapshot(&out));
        fs::remove_dir_all(&out).ok();
    }
    let (seq, par) = (&snaps[0], &snaps[1]);
    assert_eq!(seq.len(), par.len(), "entry counts differ");
    let diff: Vec<_> = seq
        .iter()
        .zip(par)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| format!("{a}\t!=\t{b}"))
        .collect();
    assert!(diff.is_empty(), "trees differ:\n{}", diff.join("\n"));
    assert!(
        par.iter()
            .filter(|l| l.ends_with("now-a-link") || l.contains("\tL "))
            .count()
            >= MANY_LINKS
    );
    fs::remove_dir_all(&dir).ok();
}

/// A real directory sitting on a link's name is refused rather than removed,
/// even when the pass is otherwise large enough to run concurrently.
#[test]
fn directory_in_the_way_is_not_removed() {
    let Some(dir) = build("isdir", MANY_LINKS) else {
        return;
    };
    let out = dir.join("out");
    // Pre-create a directory on a name the archive wants for a link, so the
    // pass hits the EISDIR path instead of the replace path.
    fs::create_dir_all(out.join("P/F/0000/N.framework/Versions/l0")).unwrap();
    fs::write(
        out.join("P/F/0000/N.framework/Versions/l0/keep"),
        b"do not remove me",
    )
    .unwrap();
    let run = extract(&dir.join("links.aea"), &out, &[]);
    assert!(!run.status.success(), "extraction should have failed");
    assert!(
        out.join("P/F/0000/N.framework/Versions/l0/keep").is_file(),
        "occupant directory contents must survive: {}",
        stderr(&run)
    );
    fs::remove_dir_all(&dir).ok();
}
