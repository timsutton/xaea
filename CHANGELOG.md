# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

* One-letter subcommand shorthands: `xaea x` for `extract` and `xaea i` for
  `inspect`.
* `extract --readahead N`: decoded segments buffered ahead of the parser.
  The default rises from `decoders + 4` to 1/8 of RAM worth of segments,
  capped at 160 (128 on 16 GB, 160 from 32 GB), which lets decoders run
  ahead during the filesystem-bound first half of an Xcode archive: full
  extract −9% on M3 Max and −7% on M4 Max, at ~1.5–2 GiB more peak memory
  (`--readahead 19` restores the old footprint).
* `profile` cargo feature: per-stage timing probes (`XAEA_STATS` breakdown,
  `XAEA_TL` timeline). Compiles to nothing when off.

### Changed

* **Faster extraction.** On the Xcode 27.3 beta 2 fixture (2.03 GiB archive,
  9.71 GiB payload), a full extract is 5–6% faster than 0.1.3 before the
  read-ahead change below (M4 Max 6.99 → 6.61 s; M3 Max 9.66 → 9.10 s), and
  decode-only (`--dry-run`) is 4.4% faster on the M4 Max (4.63 → 4.43 s). With
  the new default `--readahead` the M4 Max full extract is 6.09 s (−13%
  vs 0.1.3). How:
  * **Newer xz-utils.** The vendored xz-utils goes from 5.2.5 (`xz2` /
    `lzma-sys`) to 5.8.4 (`liblzma-sys`). This is a decoder speedup on
    x86-64 only (−23% on a 16 MiB segment, from xz 5.6's assembly range
    decoder, so for the Intel slice and Linux builds); on Apple Silicon
    both versions run the same C decoder and decode at the same speed.
  * **One-shot decode, no redundant checksum.** Segments are decoded with a
    single `lzma_stream_buffer_decode` call into an exact-size buffer (no
    input copy through a `BufReader`, no zero-filled output). When the
    segment's SHA-256 is verified anyway (the default), liblzma's own check
    over the same bytes is skipped (`LZMA_IGNORE_CHECK`); `--no-verify`
    keeps it. Apple's segments declare no xz check, so on real archives
    this flag changes nothing (it saves ~9% only on CRC64 streams); it
    stays as future-proofing. Acceptance rules are unchanged (single
    stream, exact declared size).
  * **No second copy of every segment.** Decoders write straight into the
    `Arc<[u8]>` shared with the writers instead of building a `Vec` that
    `Arc::from` then copied into a fresh 16 MiB allocation: ~9.7 GiB less
    `memcpy`/page-faulting per Xcode extract and one live buffer instead of
    two per decoder at the handoff.
  * **Fewer filesystem syscalls.** Files are opened first and their parent
    directory is created only if the open fails with `ENOENT`, instead of
    `mkdir` (EEXIST) + `stat` before every file (~250k syscalls saved on an
    Xcode tree); `mkdir` likewise issues a single call. The serial final
    pass creates each symlink with one `symlink(2)` (falling back to
    `mkdir -p` / unlink only on `ENOENT` / `EEXIST`) instead of four calls,
    ~45k fewer on the single thread that gates the end of the run. The
    symlink traversal guard is unchanged.
  * **Deeper decoder read-ahead** (`--readahead`, see *Added*).
* **Dependencies:** `xz2` / `lzma-sys` are replaced by `liblzma-sys` (xz 5.8,
  still statically linked).
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
