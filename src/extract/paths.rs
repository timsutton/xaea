//! Path safety: mapping archive paths into the output root.

use anyhow::{Context, Result, bail, ensure};
use std::path::{Component, Path, PathBuf};

/// Map a record path to a path under the output root. Absolute paths are
/// rejected; `..` components are clamped to the root (Apple's archives
/// contain intentional top-level escapes such as
/// `Xcode-beta.app/…/SharedFrameworks -> ../../../SystemFrameworks`, whose
/// target never lands in the archive; symlinks keep the *original* target so
/// in-root links resolve exactly as Apple's tool produces).
fn clamp(rel: &str) -> Result<PathBuf> {
    ensure!(!rel.is_empty(), "empty path");
    ensure!(!rel.starts_with('/'), "absolute path");
    let mut out = PathBuf::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(_) => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop(); // clamps at root
            }
            Component::RootDir | Component::Prefix(_) => bail!("absolute path"),
        }
    }
    ensure!(
        !out.as_os_str().is_empty(),
        "path escapes to nothing: {rel:?}"
    );
    Ok(out)
}

pub(super) fn sanitize(p: &[u8]) -> Result<PathBuf> {
    let s = std::str::from_utf8(p).context("non-UTF8 path")?;
    clamp(s)
}

pub(super) fn link_target(s: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(s).context("non-UTF8 link target")?;
    ensure!(!s.starts_with('/'), "absolute link target");
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_policy() {
        assert_eq!(clamp("a/b/c").unwrap(), PathBuf::from("a/b/c"));
        assert_eq!(clamp("a/./b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(clamp("a/b/../c").unwrap(), PathBuf::from("a/c"));
        assert_eq!(clamp("../../x").unwrap(), PathBuf::from("x"));
        assert_eq!(clamp("a/../../x").unwrap(), PathBuf::from("x"));
        assert_eq!(clamp("./x").unwrap(), PathBuf::from("x"));
        assert!(clamp("/abs").is_err(), "absolute paths rejected");
        assert!(clamp("").is_err());
        assert!(clamp("..").is_err(), "pure escape clamps to nothing");
        // The exact synthetic-fixture case:
        assert_eq!(
            sanitize(b"T/../../esc/../escaped/inside.bin").unwrap(),
            PathBuf::from("escaped/inside.bin")
        );
        assert!(sanitize(&[b'x', 0xff, b'y']).is_err(), "non-UTF8 rejected");
        // Link targets stay verbatim, but absolute ones are rejected.
        assert_eq!(link_target(b"a/../../b").unwrap(), "a/../../b");
        assert!(link_target(b"/etc/passwd").is_err());
    }
}
