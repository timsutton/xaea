//! The final symlink pass and its tar-attack guard.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// One deferred link record: its (clamped) path and its verbatim target.
pub(super) type Link = (Box<Path>, Box<str>);

/// Below this many links the final pass stays on one thread. A `symlink(2)`
/// on APFS costs tens of microseconds, so on a short pass thread spawn and
/// queue handoff cost more than they save.
const LINK_PAR_MIN: usize = 256;

/// Ceiling on final-pass workers. APFS serialises metadata updates well
/// before the core count: creating 12k links over a deep tree measured
/// 40.2 us/link on one thread, 12.6 us/link at 6 (3.2x), 18.5 at 8 (2.2x),
/// and back to ~serial at 12 and 16 — contention, not parallelism. The
/// default `--writers` is 6, which is where that curve peaks.
const LINK_PAR_MAX: usize = 8;

/// The lowercased component-boundary prefixes of a clamped record path,
/// shortest first; the last one is the whole path. Every guard comparison
/// goes through this one walk, so a link can never be recorded under one
/// spelling and matched under another. Case-insensitivity matters on
/// case-insensitive volumes, where a link at `Payload/up` and a record at
/// `payload/up/under` collide.
fn lowered_prefixes(path: &Path) -> Vec<Vec<u8>> {
    let mut acc: Vec<u8> = Vec::new();
    path.components()
        .map(|comp| {
            if !acc.is_empty() {
                acc.push(b'/');
            }
            acc.extend_from_slice(comp.as_os_str().to_string_lossy().to_lowercase().as_bytes());
            acc.clone()
        })
        .collect()
}

/// Final-pass symlink creation with the tar-attack guard: a symlink whose
/// path traverses a symlink created earlier in the same pass is refused —
/// during the stream phase no archive symlink exists at all, so this closes
/// the "link `x -> ..` then write `x/PWNED`" class entirely. Comparison is
/// case-insensitive to match case-insensitive volumes.
///
/// `workers` > 1 lets the *creations* run concurrently, but only for a link
/// list that is pairwise independent (see [`links_are_independent`]); any
/// other list — and any list shorter than [`LINK_PAR_MIN`] — runs the
/// sequential pass below, unchanged.
pub(super) fn link_pass(root: &Path, links: &[Link], workers: usize) -> Result<()> {
    if links.len() >= LINK_PAR_MIN && workers > 1 && links_are_independent(links) {
        link_pass_par(root, links, workers)
    } else {
        link_pass_seq(root, links)
    }
}

/// True when no link path is a strict component-boundary ancestor of another
/// and no two paths name the same link case-insensitively.
///
/// This is the guard, hoisted. The guard below only ever consults `created`,
/// which is built from the record list itself and never from the filesystem,
/// so whether a link traverses an archive symlink is a property of the list,
/// not of the tree — it can be decided for every link, single-threaded,
/// before a single link exists. Under independence no link can be created
/// *through* another one (the only way two `symlink(2)` calls in this pass
/// can interact), so the creations are free to race each other harmlessly.
///
/// The test is deliberately stronger than the guard it replaces (it rejects
/// an ancestor pair in either stream order, the guard only if the ancestor
/// comes first) and it is *not* a verdict on the archive: false means "run
/// the sequential pass", which still applies the guard exactly as written.
fn links_are_independent(links: &[Link]) -> bool {
    let prefixes: Vec<Vec<Vec<u8>>> = links.iter().map(|(p, _)| lowered_prefixes(p)).collect();
    let mut all: HashSet<&[u8]> = HashSet::with_capacity(links.len());
    for p in &prefixes {
        if let Some(whole) = p.last()
            && !all.insert(whole)
        {
            return false; // two records name the same link: last-writer-wins today
        }
    }
    // Strict ancestors of every path, matched against every link rather
    // than (as the guard does) only earlier ones.
    !prefixes.iter().any(|p| {
        p.split_last()
            .is_some_and(|(_, ancestors)| ancestors.iter().any(|a| all.contains(&a[..])))
    })
}

/// Create one link record. `symlink(2)` first: in the common case the parent
/// exists and the name is free, so this is the only syscall, and each extra
/// syscall here (it used to be mkdir + stat + unlink + symlink) is pure wall
/// time. Shared by both passes so their occupant and missing-parent
/// behaviour cannot drift apart.
fn create_link(root: &Path, path: &Path, target: &str) -> Result<()> {
    let full = root.join(path);
    let mut r = symlink(target, &full);
    if matches!(&r, Err(e) if e.kind() == ErrorKind::NotFound) {
        if let Some(p) = full.parent() {
            std::fs::create_dir_all(p).with_context(|| format!("mkdir -p {}", p.display()))?;
        }
        r = symlink(target, &full);
    }
    if matches!(&r, Err(e) if e.kind() == ErrorKind::AlreadyExists) {
        match std::fs::remove_file(&full) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            // EISDIR etc.: a real directory (or file) we cannot replace
            // lives here — in a well-formed archive this cannot happen;
            // bail loudly rather than silently keep the occupant (a
            // planted `x/` dir against a link record is itself
            // suspicious).
            Err(e) => Err(e).with_context(|| format!("replace {} with symlink", full.display()))?,
        }
        r = symlink(target, &full);
    }
    r.with_context(|| format!("symlink {} -> {}", full.display(), target))
}

/// The original pass: guard each link against the links created before it,
/// then create it, in stream order, on this thread.
fn link_pass_seq(root: &Path, links: &[Link]) -> Result<()> {
    let mut created: HashSet<Vec<u8>> = HashSet::new();
    for (path, target) in links {
        let mut prefixes = lowered_prefixes(path);
        let whole = prefixes.pop().unwrap_or_default();
        if let Some(hit) = prefixes.iter().find(|a| created.contains(*a)) {
            bail!(
                "refusing symlink {}: traverses archive-created symlink {}",
                path.display(),
                String::from_utf8_lossy(hit)
            );
        }
        create_link(root, path, target)?;
        created.insert(whole);
    }
    Ok(())
}

/// Concurrent variant, valid only for an independent link list (checked by
/// the caller, before anything was created, so there is no check-then-create
/// window between workers). Workers pull record indices off one shared
/// counter — a flat split would strand the tail on whichever thread drew the
/// deep subtrees.
///
/// On the error path this can create a handful of links that the sequential
/// pass would not have reached (the ones already in flight when the first
/// failure lands); the extraction aborts either way, and every link created
/// here is inside the tree and traverses no other link.
fn link_pass_par(root: &Path, links: &[Link], workers: usize) -> Result<()> {
    let workers = workers.min(LINK_PAR_MAX).min(links.len()).max(1);
    if workers == 1 {
        return link_pass_seq(root, links);
    }
    let next = AtomicUsize::new(0);
    // The first failure wins; the others stop at their next pull.
    let first_err: OnceLock<anyhow::Error> = OnceLock::new();
    // Scoped, not spawned: the pass must not outlive the message that
    // carried the link list, and `DirModes` may not start until it has.
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                while first_err.get().is_none() {
                    let Some((path, target)) = links.get(next.fetch_add(1, Relaxed)) else {
                        break;
                    };
                    if let Err(e) = create_link(root, path, target) {
                        let _ = first_err.set(e);
                    }
                }
            });
        }
    });
    first_err.into_inner().map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;

    #[test]
    fn link_pass_fallbacks() {
        let root = std::env::temp_dir().join(format!("xaea-linkpass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(root.join("d/occupied"), b"x").unwrap();
        std::fs::create_dir(root.join("d/isdir")).unwrap();
        let l = |p: &str, t: &str| (PathBuf::from(p).into_boxed_path(), Box::<str>::from(t));

        // Fast path, missing parent, and a file occupying the name.
        link_pass(
            &root,
            &[
                l("d/plain", "t1"),
                l("new/deeper/link", "t2"),
                l("d/occupied", "t3"),
            ],
            6,
        )
        .unwrap();
        for (p, t) in [
            ("d/plain", "t1"),
            ("new/deeper/link", "t2"),
            ("d/occupied", "t3"),
        ] {
            assert_eq!(std::fs::read_link(root.join(p)).unwrap(), Path::new(t));
        }

        // A real directory in the way is refused, not replaced.
        assert!(link_pass(&root, &[l("d/isdir", "t4")], 6).is_err());
        assert!(root.join("d/isdir").is_dir());

        // Traversing a symlink created earlier in the same pass is refused.
        assert!(link_pass(&root, &[l("x", "."), l("x/y", "t5")], 6).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Directory the parallel-path specs spread their links over.
    const SPEC_DIRS: usize = 400;

    /// A link list big enough for the parallel path, mixing every shape the
    /// pass has to handle: an existing parent (the common case, and what a
    /// real archive looks like), a missing parent (the `mkdir -p` fallback),
    /// a plain file occupying the link's name, unicode and space names.
    fn big_link_spec(n: usize) -> Vec<(PathBuf, String)> {
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let dir = format!(
                "Payload/F/{:04}/N.framework/Versions/Current",
                i % SPEC_DIRS
            );
            let path = match i % 7 {
                0 | 1 | 5 | 6 => format!("{dir}/l{i}"),
                // parent never created: exercises the mkdir -p fallback
                2 => format!("deep/{:03}/missing/parent/l{i}", i % 50),
                3 => format!("{dir}/ünïcode l{i}"),
                _ => format!("{dir}/sp ace/l{i}"),
            };
            v.push((PathBuf::from(path), format!("../../tgt/{i}")));
        }
        // A regular file already sitting on this name: replaced, not refused.
        v.push((PathBuf::from("Payload/F/0000/occupied"), "t".into()));
        v
    }

    /// Snapshot a tree as sorted (relpath, kind, link-target) triples.
    fn snapshot(root: &Path) -> Vec<(String, char, String)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, char, String)>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    out.push((rel.clone(), 'D', String::new()));
                    walk(root, &p, out);
                } else if md.is_symlink() {
                    let t = std::fs::read_link(&p).unwrap().display().to_string();
                    out.push((rel, 'L', t));
                } else {
                    out.push((rel, 'F', String::new()));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn fresh_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "xaea-linkpass-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn spec_to_records(spec: &[(PathBuf, String)]) -> Vec<Link> {
        spec.iter()
            .map(|(p, t)| (p.clone().into_boxed_path(), Box::<str>::from(t.as_str())))
            .collect()
    }

    /// Pre-populate a root the way the data phase would: the framework dirs
    /// the links live in already exist (as they do in a real archive, where
    /// the pass is pure `symlink(2)` work), and one plain file occupies a
    /// name a later link record wants.
    fn seed_data_phase(root: &Path) {
        for d in 0..SPEC_DIRS {
            std::fs::create_dir_all(root.join(format!("Payload/F/{d:04}/N.framework/Versions")))
                .unwrap();
        }
        std::fs::write(root.join("Payload/F/0000/occupied"), b"occupant").unwrap();
    }

    #[test]
    fn parallel_link_pass_matches_sequential() {
        let spec = big_link_spec(LINK_PAR_MIN * 4);
        let recs = spec_to_records(&spec);
        assert!(
            links_are_independent(&recs),
            "the synthetic spec must exercise the parallel path"
        );
        let a = fresh_root("seq");
        let b = fresh_root("par");
        seed_data_phase(&a);
        seed_data_phase(&b);
        link_pass_seq(&a, &recs).unwrap();
        link_pass(&b, &recs, 8).unwrap();
        let (sa, sb) = (snapshot(&a), snapshot(&b));
        assert_eq!(sa.len(), sb.len());
        let diff: Vec<_> = sa.iter().zip(&sb).filter(|(x, y)| x != y).collect();
        assert!(diff.is_empty(), "trees differ: {diff:?}");
        assert_eq!(sb.iter().filter(|(_, k, _)| *k == 'L').count(), spec.len());
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn nested_links_fall_back_and_still_bail() {
        // Well over the parallel threshold, but one link is nested under
        // another: the guard must still fire, with the same message.
        let mut spec = big_link_spec(LINK_PAR_MIN * 2);
        spec.push((PathBuf::from("Payload/up"), ".".into()));
        spec.push((PathBuf::from("Payload/up/under"), "t".into()));
        let recs = spec_to_records(&spec);
        assert!(!links_are_independent(&recs));
        let root = fresh_root("nested");
        seed_data_phase(&root);
        let err = link_pass(&root, &recs, 8).unwrap_err().to_string();
        assert!(
            err.contains("traverses archive-created symlink"),
            "unexpected error: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn independence_test_details() {
        let l = |p: &str| (PathBuf::from(p).into_boxed_path(), Box::<str>::from("t"));
        let recs = |v: &[&str]| -> Vec<Link> { v.iter().map(|p| l(p)).collect() };
        // `a` is an ancestor of `a/b2`, so this list is *not* independent.
        assert!(!links_are_independent(&recs(&["a", "b", "a/b2"])));
        assert!(links_are_independent(&recs(&["a", "b", "c/d"])));
        // Siblings sharing a prefix string are not ancestors.
        assert!(links_are_independent(&recs(&["ab", "a"])));
        // Ancestor in either stream order disqualifies.
        assert!(!links_are_independent(&recs(&["a", "a/b"])));
        assert!(!links_are_independent(&recs(&["a/b", "a"])));
        // Case-insensitive volumes: `A` and `a/b` are the same directory.
        assert!(!links_are_independent(&recs(&["A", "a/b"])));
        assert!(!links_are_independent(&recs(&[
            "Payload/up",
            "payload/up/under"
        ])));
        // Duplicate names (last-writer-wins today) stay sequential.
        assert!(!links_are_independent(&recs(&["a", "A"])));
    }

    /// Regression: the guard compared a lowercased ancestor against a set of
    /// paths inserted *un*-lowercased, so a nested pair spelled with capitals
    /// (`Payload/up`, `Payload/up/under`) slipped through and the second link
    /// was created straight through the first.
    #[test]
    fn guard_is_case_insensitive() {
        for (parent, child) in [
            ("Payload/up", "Payload/up/under"),
            ("Payload/up", "payload/up/under"),
            ("payload/up", "Payload/up/under"),
        ] {
            let root = fresh_root("caseguard");
            let recs: Vec<Link> = [parent, child]
                .iter()
                .map(|p| (PathBuf::from(p).into_boxed_path(), Box::<str>::from("..")))
                .collect();
            let err = link_pass_seq(&root, &recs).unwrap_err().to_string();
            assert!(
                err.contains("traverses archive-created symlink"),
                "{parent} + {child}: {err}"
            );
            assert!(
                std::fs::symlink_metadata(root.join(child)).is_err(),
                "{child} must not exist"
            );
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    /// Repeatable scaling signal for the final pass. Ignored by default
    /// because it is a benchmark, not an assertion:
    /// `cargo test --release -- --ignored --nocapture link_pass_scaling`
    #[test]
    #[ignore]
    fn link_pass_scaling() {
        let spec = big_link_spec(12_000);
        let recs = spec_to_records(&spec);
        for workers in [1usize, 2, 4, 6, 8, 12, 16] {
            let root = fresh_root("scale");
            seed_data_phase(&root);
            let t = Instant::now();
            if workers == 1 {
                link_pass_seq(&root, &recs).unwrap();
            } else {
                link_pass(&root, &recs, workers).unwrap();
            }
            let dt = t.elapsed().as_secs_f64();
            println!(
                "  workers={workers:2}  {:7.1} ms  {:6.2} us/link",
                dt * 1000.0,
                dt / recs.len() as f64 * 1e6
            );
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}
