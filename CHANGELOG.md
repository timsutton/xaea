# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

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
