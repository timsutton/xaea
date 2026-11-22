# xaea — a fast extractor for Apple Encrypted Archives (Xcode edition)

`xaea` unpacks `.aea` archives — Apple Encrypted Archive, the container
Apple has shipped for years inside IPSW/OTA restore images (where it is
encrypted) and now uses for Xcode distribution (Xcode 27 beta era,
replacing `.xip`), where it is signed but *not* encrypted (profile 0).
`xaea` targets that Xcode profile-0 use case, and extracts faster than
Apple's own `archiveutil extractXcodeAEA`, with full integrity verification
of the container, the signing chain, and every segment.

The format was reverse-engineered against a real Apple artifact and
documented (including four errata in the public spec) in
[FORMAT-NOTES.md](doc/FORMAT-NOTES.md). The measured history behind the
benchmarks — architecture rationale, tuning data, rejected experiments —
is in [PERFORMANCE-NOTES.md](doc/PERFORMANCE-NOTES.md). Exit codes are a
stability contract scripts can branch on; the full table is in
[ERROR-CODES.md](doc/ERROR-CODES.md).

## Installing

### Homebrew

On macOS, install a prebuilt binary:

```sh
brew install --cask timsutton/formulae/xaea
```

On Linux, you'll need to build from source, at least for now:
```sh
brew install --formula timsutton/formulae/xaea
```

### Manually

Prebuilt macOS and Linux binaries are available to download directly from [GitHub
releases](https://github.com/timsutton/xaea/releases/latest).

### Build from source

`cargo install --path .`.


## Benchmarks

Xcode 27.3 beta 2 archive (2.03 GiB compressed → 9.71 GiB payload,
30,082 dirs / 126,205 files / 11,254 links), M3 Max (16c / 128 GB), tools
run one at a time, warm cache:

| tool | time | on disk |
|---|---|---|
| **xaea** (defaults: verified, compressed) | **12.1–13.2 s** | 3.86 GiB |
| **xaea** `--no-verify` | 13.0–13.1 s | 3.86 GiB |
| **xaea** `--no-compress` | 7.8–10.0 s | 9.99 GiB |
| **xaea** `--no-compress --no-verify` | 8.2–8.4 s | 9.99 GiB |
| unxip (same-version `.xip`, for scale) | 24.8 s | |
| Apple `archiveutil extractXcodeAEA` | 38.8–40.0 s | 3.86 GiB |

Compression (the macOS default, matching what Apple's own extractor writes)
costs ~4 s and saves ~6 GiB. Full MAC + signature + checksum verification
costs at most ~1 s on the plain path and nothing measurable when
compressing: the expensive segment-MAC pass runs concurrently with the
decode pipeline, and per-segment SHA-256s are checked inline on the decoder
threads, so verification is on by default.

Design: LZMA decoder threads read segments with `pread` and decode them
out of order; a reorder + parse thread runs the AA01 object-stream parser
with zero-copy blob pieces; a small pool of writer threads executes *all*
filesystem syscalls (mkdir/open/chmod/symlink/pwrite) fed by per-writer
ordered channels. Instrumentation (`XAEA_STATS=1`) showed syscall
serialization, not write throughput, is the wall — so the parser thread
issues none.

## Usage

```sh
# Inspect + fully verify (MACs, checksums, signature chain)
xaea inspect Xcode_27.3_beta_2.aea --verify [--json] [--no-checksums]

# Extract into the current directory
xaea extract Xcode_27.3_beta_2.aea

# ...or into a given directory (created if missing)
xaea extract Xcode_27.3_beta_2.aea ~/Applications
```

The output directory may already exist and hold other files. `extract` aborts
before writing anything if the archive's top-level entry (e.g. `Xcode.app`)
already exists there, so it never merges into or overwrites an existing app.
`--dry-run` runs the same check.

Subcommands have one-letter shorthands: `xaea x …` is `xaea extract …`
and `xaea i …` is `xaea inspect …`.

Progress: press **Ctrl-T** (`SIGINFO`) while extracting for a one-line
status report — segments, payload written, rate, file count. On Linux,
which has no `SIGINFO`, send `SIGUSR1` instead.

Options on `extract`:

| flag | meaning |
|---|---|
| `--no-verify` | skip all integrity/authenticity checks (trusted or damaged input only; tampering goes unnoticed) |
| `-j/--jobs` | decoder threads (default: cores−1, min 2) |
| `-w/--writers` | writer threads (default: 10 when compressing, else 6 — measured optima on APFS/NVMe) |
| `--no-compress` | write plain files. By default on macOS, files are stored with transparent APFS compression (LZBITMAP decmpfs), as Apple's `archiveutil` does: an Xcode tree takes 3.86 GiB on disk instead of 9.99 GiB, for ~50% more extraction time (12.3 s vs 8.0 s on M3 Max). On a volume that can't hold compressed files (exFAT, most network shares) plain files are written automatically; pass `--compress` to get a warning when that happens. Linux always writes plain files. |
| `--readahead` | decoded segments (~16 MiB each) buffered ahead of the parser (default: 1/8 of RAM worth, between decoders+4 and 160 — 128 on 16 GB, 160 from 32 GB; lower it to cut peak memory, e.g. `--readahead 19` ≈ 3.2 GiB peak vs ≈ 5 GiB) |
| `--dry-run` | decode + parse everything, write nothing |
| `--prealloc` | pre-reserve file extents (`F_PREALLOCATE`/`posix_fallocate`); neutral-to-worse on APFS, off by default |
| `--decoder` | LZMA implementation: `liblzma` (vendored xz-utils, default) or `libcompression` (Apple's OS-provided library, macOS only). Also accepted by `inspect`. |
| `--json` | machine-readable summary |

## Shell completions

`xaea completions <shell>` prints a completion script to stdout — `bash`,
`zsh`, `fish`, `elvish`, or `powershell` — generated from the binary's own
argument parser, so it always matches the installed version:

```sh
# zsh — into any dir on $fpath (add `fpath+=~/.zfunc` before compinit)
mkdir -p ~/.zfunc && xaea completions zsh > ~/.zfunc/_xaea

# bash — Homebrew bash: $(brew --prefix)/etc/bash_completion.d; Linux: /etc/bash_completion.d
xaea completions bash > /usr/local/etc/bash_completion.d/xaea

# fish — no reload config needed
xaea completions fish > ~/.config/fish/completions/xaea.fish
```

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

## Platform support

* **macOS**: primary target; fully verified against Apple artifacts.
* **Linux**: builds and runs cleanly (`cargo build --release`); `SIGUSR1`
  replaces `SIGINFO`, `posix_fallocate` replaces `F_PREALLOCATE`. Perf tuning is macOS-first by design — pass
  `--jobs`/`--writers` to experiment elsewhere.
* Extraction supports **profile 0** (Xcode's: stored-compressed, signed)
  only; encrypted profiles (1–5) are parsed and verified envelope-only,
  and `extract` refuses them explicitly.

## Development

```sh
cargo build --release          # binary in target/release/xaea
cargo test                     # unit + synthetic end-to-end suite
AEA_FIXTURE=fixtures/Xcode_27.3_beta_2.aea cargo test -- --ignored   # real-artifact checks
XAEA_STATS=1 ./target/release/xaea extract …   # pipeline timing breakdown
```

The test suite builds a synthetic, fully signed AEA (multi-cluster,
capacity padding, cross-segment blobs, stored segments, clamped paths,
symlinks, unicode) with `scripts/make_test_aea.py` and round-trips it
through verify + extract; the fixture-gated tests re-check every documented
fact in doc/FORMAT-NOTES.md against the real Apple file.

### Releasing

Releases publish themselves from tags (GoReleaser, configured in
`.goreleaser.yaml`, driven by `.github/workflows/release.yml`):

1. Bump `version` in `Cargo.toml`, refresh `Cargo.lock` (one `cargo
   check`), write the CHANGELOG entry — landed on `main`.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.

The Release workflow builds every asset on one macOS runner — the darwin
targets natively, the Linux ones zig-cross-linked against glibc ≥ 2.30 —
and publishes the GitHub Release with generated notes and `checksums.txt`.
The workflow also accepts a manual `snapshot` dispatch that dry-runs the
whole pipeline without publishing.
To run the same build on your own machine, see
[RELEASING-LOCALLY.md](doc/RELEASING-LOCALLY.md).

The macOS binaries are signed with a Developer ID Application certificate
and notarized by GoReleaser (`notarize` in `.goreleaser.yaml`); the workflow
then checks the signatures of the shipped archive
(`scripts/verify-macos-signature.sh`). A real release needs
five repository secrets — `MACOS_SIGN_P12` (base64 `.p12`),
`MACOS_SIGN_PASSWORD`, `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID` and
`MACOS_NOTARY_KEY` (base64 App Store Connect `.p8`) — and fails without them.
Snapshot runs skip signing. A bare binary can't be stapled, so Gatekeeper
checks the notarization ticket online the first time a quarantined copy runs.

Before it runs, the workflow installs
[`cosign`](https://github.com/sigstore/cosign-installer), which makes
goreleaser-action verify the GoReleaser binary it downloads — both its
`checksums.txt` SHA-256 and that file's sigstore signature against
GoReleaser's release-workflow OIDC identity — instead of fetching it on trust.

## Acknowledgments

* [saagarjha/unxip](https://github.com/saagarjha/unxip) — the inspiration
  for this tool. unxip proved that extracting Xcode distributions could be
  several times faster than Apple's own tooling, and this project borrows
  its spirit (and some benchmark rivalry): parallel LZMA decode, a
  syscall-light pipeline, and APFS-friendly writes. The final-pass symlink
  policy follows bsdtar/unxip practice.
* [kinnay/AEA](https://github.com/kinnay/AEA) `FORMAT.md` — the starting
  point for the envelope layout; the errata found against Apple's real
  artifact are documented in doc/FORMAT-NOTES.md.
