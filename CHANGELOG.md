# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

* `xaea cat <archive> <member>`: write one regular file from an archive to
  stdout (e.g. `xaea cat Xcode.aea Xcode-beta.app/Contents/Info.plist | plutil -p -`),
  without extracting the tree. Directories and symlinks are refused with a
  clear error; verification is on by default and the output is streamed, so a
  non-zero exit means anything already written is untrustworthy.

## 0.2.0 - 2026-11-22

### Added

* Documented exit codes as a stability contract: 0 success, 2 usage, 3
  unreadable input, 4 rejected archive, 5 verification failure, 6 extraction
  failure, 1 generic (126–128 and ≥128 stay reserved for shell/signal
  conventions). Full table in [doc/ERROR-CODES.md](doc/ERROR-CODES.md).
* CI now proves the signature checks reject bad archives, instead of only
  that good ones pass: the test suite derives corrupt variants of its signed
  synthetic archive — wrong signature bytes, a malformed signature, dirty
  signature padding, a certificate chain that does not verify, a truncated
  envelope — and requires each to be refused with a named reason and no
  output written.
* One-letter subcommand shorthands: `xaea x` for `extract` and `xaea i` for
  `inspect`.
* `extract --readahead N`: how many decoded segments are buffered ahead of
  the writers. The default now scales with your RAM, which speeds up large
  extractions at the cost of some memory; lower it to use less.
* On macOS, `extract` now stores files with transparent APFS compression by
  default, as Apple's `archiveutil` does. An Xcode install takes about
  3.9 GiB on disk instead of about 10 GiB, and extraction takes about 50%
  longer (still ~3× faster than `archiveutil`). `--no-compress` writes plain
  files as before. Volumes that can't hold compressed files (exFAT, most
  network shares) get plain files automatically; `--compress` makes that
  fallback print a warning.
* `profile` cargo feature (`cargo build --features profile`): prints a
  per-stage timing breakdown (`XAEA_STATS=1`) or a live timeline
  (`XAEA_TL=1`) for performance investigations. No cost when not enabled.
* `xaea completions <shell>` prints a shell-completion script (bash, zsh,
  fish, elvish, powershell) generated from the binary's own argument parser.
* `-` as the archive path of `inspect` or `extract` reads the archive from
  standard input (`curl ... | xaea extract - outdir`). The bytes are
  spooled to a private temporary file first, so every integrity check —
  including the end-of-file geometry check — runs exactly as it does for a
  file.

### Changed

* Performance improvements yielding roughly 10% faster extraction:
  * Faster final symlink pass ([PR 55](https://github.com/timsutton/xaea/pull/55))
  * Fewer syscalls, a faster LZMA decoder, and a deeper read-ahead ([PR 38](https://github.com/timsutton/xaea/pull/38)). On Apple Silicon the decode-only gain is carried by the xz 5.8.4 crate swap (~4% on an M4 Max), not by the one-shot decode call or the removed per-segment copy

* `extract` now takes the output directory as an optional
  positional argument (`xaea extract FILE [OUT_DIR]`) instead of the
  required `-o/--out` flag. It defaults to the current directory, which may
  be non-empty, but it will abort if there exists already a matching payload
  path in the destination.

### Removed

* The `-o/--out` option of `extract` (see above).
* The `--quarantine` extract option (macOS `com.apple.quarantine` tagging).

## 0.1.3 - 2026-11-19

### Changed

* macOS release binaries are Developer ID-signed (hardened runtime) and
  notarized by the Release workflow.

## 0.1.2 - 2026-11-19

### Changed

* Universal binary release for macOS.

## 0.1.1 - 2026-11-19

### Changed

* CI Builds releases on macOS.

## 0.1.0 — 2026-11-19

First release.

### Added

* `unaea inspect` — parses the AEA1 envelope (root header, clusters,
  segments, auth pairs, signature) and reports geometry, key material
  offsets, and signing info; `--verify` folds in root/cluster/segment
  HMACs, per-segment SHA-256 checksums, the ECDSA content signature, and
  certificate-chain policy, exiting non-zero if any check fails so the
  command is usable in CI.
* `unaea extract` — full AA01 object-stream extraction with a parallel
  pipeline: out-of-order `pread` + LZMA decoder threads, a zero-syscall
  reorder/parse/dispatch thread, and writer threads that execute every
  filesystem syscall via per-writer FIFO channels.
* Verification **by default** on extract: upfront signature + chain
  policy (every link verifies, issuers are `CA:true`, validity enforced,
  SHA-1 suites rejected), header MACs, inline per-segment checksums gating
  each write, and a segment-MAC pass run concurrently with the pipeline
  and joined before the final pass. `--no-verify` opts out.
* Extraction safety policy: absolute paths rejected, `..` clamped to the
  output root, symlinks created in a final pass with a tar-link-attack
  guard, directory modes deferred until after the subtree exists,
  setuid/setgid/sticky stripped; optional `--quarantine` on macOS.
* Live progress report on Ctrl-T (`SIGINFO`; `SIGUSR1` on Linux).
* `--jobs` / `--writers` / `--dry-run` / `--prealloc` / `--json`.
* Test suite: unit tests for the key tree, format, and signature code;
  an end-to-end suite that builds a fully signed synthetic AEA at test
  time (`scripts/make_test_aea.py`) covering multi-cluster geometry,
  spec errata, tamper detection, and symlink-attack archives;
  fixture-gated tests re-checking every documented fact against a real
  Apple archive.
* Documentation: README, FORMAT-NOTES.md (format reverse-engineering
  notes including four errata in the public spec), CHANGELOG.md.
