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
[FORMAT-NOTES.md](FORMAT-NOTES.md).

## Benchmarks

Xcode 27.3 beta 2 archive (2.03 GiB compressed → 9.71 GiB payload,
30,082 dirs / 126,205 files / 11,254 links), M3 Max (16c / 128 GB), tools
run one at a time, warm cache:

| tool | time |
|---|---|
| **unaea** | **~9 s** |
| unxip (same-version `.xip`, for scale) | 24.8 s |
| Apple `archiveutil extractXcodeAEA` | 40.0 s |

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
| `-j/--jobs` | decoder threads (default: cores−6) |
| `-w/--writers` | writer threads (default: 4 — optimal on APFS/NVMe) |
| `--dry-run` | decode + parse everything, write nothing (~7 s floor) |
| `--prealloc` | pre-reserve file extents (`F_PREALLOCATE`/`posix_fallocate`); neutral-to-worse on APFS, off by default |
| `--quarantine` | tag outputs with `com.apple.quarantine` (macOS only, off by default like other CLI extractors) |
| `--json` | machine-readable summary |

## Verification & fidelity

`inspect --verify` proves, against Apple's published spec (with our errata
corrections): root/cluster/segment HMACs, SHA-256 checksums of every
decompressed segment, the ECDSA content signature over the signed prefix,
and the cert chain up to the vendored Apple Root CA - G3.

Extraction fidelity on the real fixture was proven by: 624/624 segment
checksums, exhaustive record walk, 100 % path-set match with `unxip`'s
output of the same-version `.xip`, `codesign --deep --strict` passing on
the extracted app, and byte-identical output between the single-threaded
and parallel pipelines (`scripts/verify.sh <tree-a> <tree-b>`). The only
content differences vs the `.xip` are ~2,000 Mach-O CMS signature blobs —
Apple re-signed the build for the AEA distribution.

Safety policy (unxip-style): absolute paths are rejected, `..` components
clamp to the output root, symlink targets are stored verbatim (Apple's
archives contain deliberate `../`-escape symlink records whose target never
lands in the tree).

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
