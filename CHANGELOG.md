# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

* Documented exit codes as a stability contract: 0 success, 2 usage, 3
  unreadable input, 4 rejected archive, 5 verification failure, 6 extraction
  failure, 1 generic (126–128 and ≥128 stay reserved for shell/signal
  conventions). Full table in [doc/ERROR-CODES.md](doc/ERROR-CODES.md).
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

### Changed

* **Faster final symlink pass.** Links are still created only after every
  file has been written, but the creations now run over `--writers` threads
  instead of one, once the whole link list has been checked for the tar
  link-attack pattern. On Xcode 27.3 b2 that pass goes from 0.58 s to 0.20 s
  (~0.4 s, about 5% of a full extract). The same check is now genuinely
  case-insensitive, as it always intended to be: a nested pair spelled with
  capitals (`Payload/up` plus `Payload/up/under`) is now refused, where it
  used to be created through the first link and land outside the output
  directory the archive named.

* Faster extraction: a full Xcode extract is roughly 5–13% faster than
  0.1.3, from leaner segment decoding and fewer filesystem calls.
* **CLI:** `extract` now takes the output directory as an optional
  positional argument (`xaea extract FILE [OUT_DIR]`) instead of the
  required `-o/--out` flag. It defaults to the current directory, which may
  be non-empty.
* `extract` aborts up front, before writing anything, if one of the
  archive's top-level entries (e.g. `Xcode.app`) already exists in the
  output directory. This replaces the old "output dir must be empty" rule.

### Removed

* The `-o/--out` option of `extract` (see above).
* The `--quarantine` extract option (macOS `com.apple.quarantine` tagging).

### Fixed

* The `--decoder` help text claimed `libcompression` was "roughly 5%
  faster". That predates APFS compression becoming the macOS default and
  does not describe a full extract: re-measured, the two decoders are
  indistinguishable there. The ~5% is real, but only at the decode-bound
  `--dry-run` floor, where nothing is writing.

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
