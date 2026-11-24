# Verification & fidelity

`extract` **verifies by default** and refuses an archive unless every check
passes; `inspect --verify` runs the same checks and prints an itemized
report (non-zero exit if anything fails, so it is CI-usable):

* root, cluster, and per-segment HMACs (the segment pass runs concurrently
  with extraction and is joined before the final pass);
* SHA-256 of every decompressed segment, checked inline on the decoder
  threads — no segment's bytes reach the filesystem before its own check;
* the ECDSA content signature over the signed prefix (SHA-1 suites are
  rejected outright);
* the certificate chain: every link verifies, every issuer has `CA:true`,
  and every certificate is inside its validity window;
* trust to the vendored Apple Root CA - G3 is reported (`trusted_root`)
  but only *warns*: a self-signed or privately-signed archive still gets
  full integrity verification — establish provenance yourself.

`--no-verify` skips all of it; it exists for recovering damaged archives,
not for speed. A tampered archive then extracts silently, but you can
still validate an extracted Xcode yourself with
`codesign --verify --deep --strict Xcode.app` (checks Apple's code
signature over the app's sealed contents, not the AEA container itself).

Extraction fidelity on the real fixture was proven by: 624/624 segment
checksums, exhaustive record walk, 100 % path-set match with `unxip`'s
output of the same-version `.xip`, `codesign --deep --strict` passing on
the extracted app, and byte-identical output between the single-threaded
and parallel pipelines (`scripts/verify.sh <tree-a> <tree-b>`). The only
content differences vs the `.xip` are ~2,000 Mach-O CMS signature blobs —
Apple re-signed the build for the AEA distribution.

Safety policy: absolute paths are rejected; `..` components clamp to the
output root; link targets are stored verbatim (Apple's archives contain
deliberate `../`-escape symlink records whose target never lands in the
tree) except absolute targets, which are rejected. Symlinks and directory
modes are created in a **final pass** after the whole stream has been
written (bsdtar/unxip practice), so no write can be redirected through an
archive-planted symlink; within that pass, a symlink whose path traverses
an earlier archive symlink is refused (the classic tar link attack), and
modes that would lock a directory against its own subtree are applied
*after* the subtree exists. Setuid/setgid/sticky bits are stripped from
every mode.

Two small permission details:

* `uid`/`gid` records are parsed but not applied — `chown` needs root, and
  Apple's own CLI declines to apply them unprivileged too.
* When a record's mode equals what `open(2)`/`mkdir(2)` already produce
  from the umask (e.g. 0644/0755 under the default umask), the redundant
  `fchmod`/`chmod` is skipped — a ~137k-syscount saving per Xcode tree
  with no observable difference. Non-default modes always get the call.
