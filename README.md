# unaea — a fast extractor for Apple Encrypted Archives (Xcode edition)

`unaea` unpacks `.aea` archives — Apple Encrypted Archive, the container
Apple has shipped for years inside IPSW/OTA restore images (where it is
encrypted) and now uses for Xcode distribution (Xcode 27 beta era,
replacing `.xip`), where it is signed but *not* encrypted (profile 0).
`unaea` targets that Xcode profile-0 use case, and extracts faster than
Apple's own `archiveutil extractXcodeAEA`, with full integrity verification
of the container, the signing chain, and every segment.

The format was reverse-engineered against a real Apple artifact and
documented (including four errata in the public spec) in
[FORMAT-NOTES.md](FORMAT-NOTES.md). The measured history behind the
benchmarks — architecture rationale, tuning data, rejected experiments —
is in [PERFORMANCE-NOTES.md](PERFORMANCE-NOTES.md).

## Benchmarks

Xcode 27.3 beta 2 archive (2.03 GiB compressed → 9.71 GiB payload,
30,082 dirs / 126,205 files / 11,254 links), M3 Max (16c / 128 GB), tools
run one at a time, warm cache:

| tool | time |
|---|---|
| **unaea** (verification on, the default) | **10.6 s** |
| **unaea** `--no-verify` | 9.0 s |
| unxip (same-version `.xip`, for scale) | 24.8 s |
| Apple `archiveutil extractXcodeAEA` | 40.0 s |

So full MAC + signature + checksum verification costs ~1.6 s of the run —
the expensive segment-MAC pass runs concurrently with the decode pipeline,
and per-segment SHA-256s are checked inline on the decoder threads, so
verification is on by default with no meaningful speed penalty.

Design: LZMA decoder threads read segments with `pread` and decode them
out of order; a reorder + parse thread runs the AA01 object-stream parser
with zero-copy blob pieces; a small pool of writer threads executes *all*
filesystem syscalls (mkdir/open/chmod/symlink/pwrite) fed by per-writer
ordered channels. Instrumentation (`UNAEA_STATS=1`) showed syscall
serialization, not write throughput, is the wall — so the parser thread
issues none.

## Usage

```sh
# Inspect + fully verify (MACs, checksums, signature chain)
unaea inspect Xcode_27.3_beta_2.aea --verify [--json] [--no-checksums]

# Extract
unaea extract Xcode_27.3_beta_2.aea -o ./Xcode-out
```

Progress: press **Ctrl-T** (`SIGINFO`) while extracting for a one-line
status report — segments, payload written, rate, file count. On Linux,
which has no `SIGINFO`, send `SIGUSR1` instead.

Options on `extract`:

| flag | meaning |
|---|---|
| `--no-verify` | skip signature/chain/MAC/checksum verification (trusted input only) |
| `-j/--jobs` | decoder threads (default: cores−1, min 2) |
| `-w/--writers` | writer threads (default: 6 — optimal on APFS/NVMe) |
| `--dry-run` | decode + parse everything, write nothing |
| `--prealloc` | pre-reserve file extents (`F_PREALLOCATE`/`posix_fallocate`); neutral-to-worse on APFS, off by default |
| `--quarantine` | tag outputs with `com.apple.quarantine` (macOS only, off by default like other CLI extractors) |
| `--json` | machine-readable summary |

## Verification & fidelity

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
not for speed.

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

## Platform support

* **macOS**: primary target; fully verified against Apple artifacts.
* **Linux**: builds and runs cleanly (`cargo build --release`); `SIGUSR1`
  replaces `SIGINFO`, `--quarantine` is rejected, `posix_fallocate`
  replaces `F_PREALLOCATE`. Perf tuning is macOS-first by design — pass
  `--jobs`/`--writers` to experiment elsewhere.
* Extraction supports **profile 0** (Xcode's: stored-compressed, signed)
  only; encrypted profiles (1–5) are parsed and verified envelope-only,
  and `extract` refuses them explicitly.

## Development

```sh
cargo build --release          # binary in target/release/unaea
cargo test                     # unit + synthetic end-to-end suite
AEA_FIXTURE=fixtures/Xcode_27.3_beta_2.aea cargo test -- --ignored   # real-artifact checks
UNAEA_STATS=1 ./target/release/unaea extract …   # pipeline timing breakdown
```

The test suite builds a synthetic, fully signed AEA (multi-cluster,
capacity padding, cross-segment blobs, stored segments, clamped paths,
symlinks, unicode) with `scripts/make_test_aea.py` and round-trips it
through verify + extract; the fixture-gated tests re-check every documented
fact in FORMAT-NOTES.md against the real Apple file.

## Acknowledgments

* [saagarjha/unxip](https://github.com/saagarjha/unxip) — the inspiration
  for this tool. unxip proved that extracting Xcode distributions could be
  several times faster than Apple's own tooling, and this project borrows
  its spirit (and some benchmark rivalry): parallel LZMA decode, a
  syscall-light pipeline, and APFS-friendly writes. The final-pass symlink
  policy follows bsdtar/unxip practice.
* [kinnay/AEA](https://github.com/kinnay/AEA) `FORMAT.md` — the starting
  point for the envelope layout; the errata found against Apple's real
  artifact are documented in FORMAT-NOTES.md.
