# Performance notes — why `xaea` is as fast as it is

This is the measured history behind the numbers in the README: which
architecture decisions buy the speed, what the instrumentation showed,
which tempting optimizations were tried and **rejected**, and how to
re-measure. Read this before "optimizing" anything — several obvious
ideas are already in the code, and several others were proven useless or
harmful on APFS.

## Baseline numbers

Fixture: `fixtures/Xcode_27.3_beta_2.aea` — 2.03 GiB compressed →
9.71 GiB payload (624 segments / 3 clusters), 167,541 entries
(30,082 dirs / 126,205 files / 11,254 links).

Machine: M3 Max (16c / 128 GB), NVMe, APFS. Methodology: one tool at a
time, warm cache (this matters — all tuning below was done warm, and the
CI perf workflow primes the page cache with a warmup run to match).

| tool | time |
|---|---|
| **xaea**, verification on (default) | **10.6 s** |
| **xaea** `--no-verify` | 9.0 s |
| xaea `--dry-run` (decode+parse, no writes — the CPU floor) | 6.6 s |
| unxip (same-version `.xip`, for scale) | 24.8 s |
| Apple `archiveutil extractXcodeAEA` | 40.0 s |

≈1,000+ MiB/s of payload written. These are M3 Max numbers; the shape of
the result (writer-bound, verification cheap) should transfer, the
absolute seconds will not.

**The xaea rows above are the v0.1.0-era baseline and predate two
changes**, so don't quote them as current: transparent APFS compression
became the macOS default (#48), and decoding got faster since. Re-measured
2026-11-21 on this same machine and fixture at rev `931933a`, verification
on throughout: **12.30 s** with compression on (the default today; ~3.9 GiB
on disk), **8.23 s** with `--no-compress` (the plain-file output these rows
actually describe), **4.90 s** `--dry-run`. The `--no-verify` row and the
third-party rows were not re-run.

## The one fact that explains the architecture

**The wall is filesystem-syscall serialization, not CPU and not write
throughput.**

`XAEA_STATS=1` on the first M3 pipeline showed the parse+dispatch thread
taking **13.0 s while the writer pool drained in +0.0 s**: writers were
starved, and the parser's own `mkdir`/`open`/`pwrite` calls were the
serialization point. Moving *every* filesystem syscall off the parser
thread onto writers took 13.0 s → 9.8 s on its own (commit `3c79fbb`).
The parser thread now issues zero syscalls.

This matches the independent community finding (Jon Shier / saagarjha,
Slack, M3 Ultra): Apple's tool contends with APFS at 32 threads and
~4 writer threads is near-optimal disk throughput for this workload. Our
grid search landed in the same place (6 writers *after* syscall offload
concentrated the work).

## The pipeline and what each stage buys

```
 D decoders ──sync_channel(nd+4)──▶ reorder+parse ──per-writer ordered──▶ W writers
 pread, out-of-order LZMA          zero-copy AA01, no syscalls           all fs syscalls
 inline SHA-256 when verifying                                           queue depth 32
```

- **Segments are independently LZMA-compressed**, so out-of-order
  decoding is free — no back-references between segments. D decoder
  threads (default cores−1) each `pread` their segment and produce
  `Arc<[u8]>`. **pread, not mmap**: the payload is read through a single
  `Arc<File>` with `read_at` because `Mmap` is `Send` but not `Sync`;
  concurrent `pread` also avoids any mmap-region sharing questions.
  (envelope.rs gives each `Segment` a `data_off` to make this work.)
- **Zero-copy end to end.** The AA01 parser (`aa.rs`) slices the decoded
  segment buffers in place — `Piece { buf: Arc<[u8]>, start, end }` —
  and file blobs are handed to writers as `Piece`s. A blob's bytes are
  copied exactly once: into the page cache at `pwrite`. Decoders write
  straight into that `Arc<[u8]>` (`envelope::segbuf_filled`, via
  `Arc::new_uninit_slice`). Until that change every segment was decoded
  into a `Vec` first, and `Arc::from(Box<[u8]>)` silently allocated a
  second 16 MiB buffer and copied the segment into it, because `Arc`
  keeps its refcounts in front of the data and cannot adopt the `Box`'s
  allocation (~1.1 ms per segment on x86-64, and two live buffers per
  decoder for a moment).
- **Reorder + parse thread** reassembles segment order (HashMap keyed on
  sequence + `next_expected` cursor), runs the object-stream parser, and
  *only* dispatches work. No syscalls here — that's the whole point (see
  the one-fact section).
- **Writer threads (default 6)** execute every syscall
  (`mkdir`/`open`/`chmod`/`symlink`/`pwrite`) fed by
  **per-writer ordered `sync_channel(32)`s**. A file's records all route
  to one writer by object sequence, so each writer does contiguous
  appends to one open file at a time (`Cur` tracks the current file) —
  no seeks, no locks, no global queue contention.
- **Final pass (symlinks + directory modes) behind a Flush barrier**
  costs ~0.7 s of drain. It stays in: it is what closes the
  symlink-attack class (no archive-planted link exists while data is
  being written). Safety was traded for perf exactly once here, and it
  was worth it.

## Tuned defaults (do not change without re-running the grid)

| knob | default | measured rationale |
|---|---|---|
| decoders `--jobs` | cores−1 (min 2) | writers are I/O-blocked, so decoders may oversubscribe CPU: A/B 8.42/8.94 s vs 9.09/9.44 s for cores (commit `39fef48`) |
| writers `--writers` | 6 | >4 writers *hurt* before the syscall offload (contention); after offloading syscalls onto them, 6 won the grid (j12w6 = 8.80 s) |
| decoder channel `--readahead` | min(160, RAM/8 ÷ segment size), floor `nd + 4` | was `nd + 4` (19), which stopped decoders running ahead during the writer-bound first half of the archive; 160 gives −9% (M3 Max) / −7% (M4 Max) wall for +1.5–2 GiB peak RSS, so it is capped to 1/8 of physical RAM (64 on 8 GB, 128 on 16 GB, 160 from 32 GB). Not yet measured under real memory pressure. See "Profiling build" below |
| writer queue | 32 per writer | queue depth 12 cost **~1.5 s** of parser throughput via backpressure; 32 restored in the hardening batch. Worst case pinned memory: writers × 32 × segment size ≈ **3 GiB** — deliberate trade, documented in `extract.rs` |

The `--jobs` optimum is machine- *and mode*-dependent. The cores−1
rationale above is M3 Max and no-compress-shaped; on the M4 Pro mini
(10P+4E) it is wrong for the compression path. Interleaved,
rotating-order, paired: with compression on, j10 beats cores−1 by
**0.46 ± 0.04 s** (n=15, 0/15 rounds against) and j14 by the same
margin, while cores−1 and j14 are indistinguishable; with
`--no-compress` the sign flips — cores−1 beats j10 by **0.35 ± 0.01 s**
(n=7, 7/7). Fewer decoders help when writers burn encode CPU and hurt
when they are I/O-blocked — that is the row's own rationale, restated
on a smaller chip. No default change: one number has to serve both
modes and the spread is ~4%. Beware sequential A/B here — `bench.py`
runs its variants sequentially, and an earlier sequential sweep's
"j14 recovers" (−0.26 s vs cores−1) did not survive interleaving.

Raw grid/A-B logs lived in `/tmp/bench_{grid,ab,g2,jobs}.log`
(transient; regenerate with `XAEA_STATS=1` runs before touching these
constants).

## Syscall diet: the ~137k `chmod`s that were never legal

`open(2)`/`mkdir(2)` already create entries with `mode & ~umask`. When a
record's requested mode equals that default (0644/0755 under the usual
umask), the follow-up `fchmod`/`chmod` is a no-op — and the parser can
skip issuing it. **~137k syscalls saved per Xcode tree, −1.2 s**, zero
observable difference; non-default modes always still get the call.
(README documents the semantics; this is the perf rationale.)

## Things tried and rejected — don't re-litigate

- **Extent preallocation** (`F_PREALLOCATE` fstore_t /
  `posix_fallocate`): implemented, measured **neutral-to-worse** on
  APFS/NVMe. Kept as opt-in `--prealloc`; default off. APFS didn't need
  the hint.
- **More writers**: before the syscall offload this actively hurt
  (APFS contention — same failure mode as Apple's tool at 32 threads).
- **Bigger writer queue is not free either**: 12 was too small, 32 won;
  it's a backpressure-vs-memory trade, not "more is better".
- **mmap for the archive**: ruled out for `Sync` reasons above; nobody
  has since shown pread being the bottleneck at these rates.
- **Pinning decode to performance cores** (M4 Pro mini, 10P+4E): the
  testable premise — E-core stragglers stalling the ordered pipeline —
  fails at the source. Per-segment decode times reproduce across runs
  (Spearman ρ = 0.997 over 622 full segments, median per-segment CV
  1.4%) with no bimodality (max interior gap ×1.02): the 4× ns/B
  spread is LZMA content, not core placement, and per-thread rankings
  shuffle between runs. Sizing the pool to the P-core count is a
  measured decode loss too — dry-run is monotonic to j14, the 4
  E-cores worth 1.06 s (17%) over j10. QoS pinning itself was never
  measured: it was gated on the straggler test firing, and the headers
  don't promise P/E exclusion anyway (QoS classes are throughput/energy
  requests; `THREAD_AFFINITY_POLICY` is an experimental L2 hint).

## Alternate LZMA decoder: Apple's libcompression (`--decoder`)

`--decoder libcompression` decodes segments with the OS's
`compression_decode_buffer(COMPRESSION_LZMA)` (LZMA2 in the same .xz
container) instead of the vendored liblzma. Opt-in; liblzma stays the
default because it is portable and its behaviour is pinned by our build.
Re-measured 2026-11-21 on the same M3 Max (16c / 128 GiB), same fixture,
rev `931933a` with vendored liblzma 5.8.x — `scripts/bench.sh`, 1 warmup
+ 7 timed runs per cell, interleaved, warm cache, load 3–6, nothing else
running. Four cells, because APFS compression (the macOS default since
#48) turns out to be a far bigger effect than the decoder and had to be
controlled for:

| cell | liblzma | libcompression | Δ |
|---|---|---|---|
| full extract, **compression on (the default)** | 12.303 ± 0.066 s | 12.337 ± 0.071 s | +0.3% |
| full extract, `--no-compress` | 8.227 ± 0.175 s | 8.126 ± 0.163 s | −1.2% |
| `--dry-run` — decode+parse, no writes (the CPU floor) | 4.902 ± 0.020 s | 4.647 ± 0.012 s | **−5.2%** |

Peak RSS was 5.74 / 5.66 GiB compressed, 5.33 / 5.24 raw, 3.15 / 3.06
dry-run — libcompression marginally lighter in every cell.

Those are run-to-run σ, not confidence intervals. What decides each
comparison is the standard error of the *difference* (σ/√7, pooled):
≈0.037 s compressed, ≈0.090 s raw, ≈0.009 s dry-run.

- **On the default path the decoders are indistinguishable.** The gap is
  0.034 s against a standard error of 0.037 s — a 95% interval of ±0.07 s.
  The "roughly 5% faster" (≈0.6 s) this section used to claim is excluded
  outright, not merely unproven.
- **`--no-compress` as well, at this sample size:** −0.101 s ± 0.18 s, so
  at most ~3% faster and consistent with zero.
- **At the CPU floor the difference is real and unmistakable:** −0.255 s
  against σ ≈ 0.016 s, roughly 29 standard errors. libcompression also
  retires ~5% fewer instructions in every cell (1.02 vs 1.07 T compressed,
  0.58 vs 0.64 T raw).

So the old table was half right, and the halves are worth separating. Its
`--dry-run` row (−5%, against xz 5.2.5) reproduces almost exactly five
major liblzma versions later: Apple's decoder genuinely is ~5% cheaper per
byte, and the old `-j 2` isolation row (31.0 vs 28.7 s, −8%) was pointing
at the same real thing. What does not survive is reading that as a
full-extract win — the old −4.7% / −5.8% full-extract rows are gone. A
full extract is writer-bound ("The one fact that explains the
architecture"), so a 5% cut in decode effort lands entirely inside slack
the writers never asked the decoders to use. The advantage is real and
invisible at the same time, which is as clean a confirmation of the
architecture model as anyone could want: **CPU saved on a stage that is
not the bottleneck buys nothing.**

Practical reading: `--decoder` is not a speed lever. Choose it for
provenance — the OS library instead of the vendored one — not for time.
The lever on this machine is `--no-compress`, worth 4.1 s, a third of the
default run.

The earlier comparison also noted that vendored liblzma 5.8.x decoded a
16 MiB segment ~23% faster than 5.2.5 in a microbenchmark on x86-64 only,
with no difference on Apple Silicon — see "What the xz upgrade does (and
doesn't) buy" below. That asymmetry is consistent with the dry-run row
above barely moving (5.40–5.80 s then, 4.90 s now, across a period that
also included the syscall offload).

Two implementation details matter:

- **Exact-size output buffer.** A first cut reserved `orig + 1` bytes to
  detect over-long streams (`compression_decode_buffer` truncates
  silently). The capacity ≠ length mismatch made `into_boxed_slice`
  realloc+copy each 16 MiB segment and peak RSS went 0.2 → 1.1 GiB at
  `-j 2`. With an exact buffer it matches liblzma. (Both decoders now
  write directly into the exact-size shared segment buffer.) Over-long or
  corrupt streams are still caught by the per-segment SHA-256 when
  verifying (the default); with `--no-verify` only the size is checked.
- **Per-thread scratch buffer** (`compression_decode_scratch_buffer_size`)
  instead of letting libcompression allocate one per call.

## Alternate LZMA decoder: lzma-turbo (`--decoder lzma-turbo`)

[lzma-turbo](https://crates.io/crates/lzma-turbo) 0.12.1 is a pure-Rust port
of 7-Zip's `LzmaDec.c` / `Lzma2Dec.c` with 7-Zip's hand-written aarch64 /
x86-64 asm decode loop. It has no one-shot slice API, so each segment goes
through `XzReader` over the in-memory segment: LZMA2 decodes into a
block-sized dictionary window (the crate clamps it to the block's declared
size) and is copied into the segment buffer, which is zero-filled first
because `Read` needs initialised memory. Acceptance matches the liblzma
path: exactly `orig` bytes, xz check skipped when SHA-256 follows, bytes
after the stream ignored. Built with `default-features = false` (no encoder,
no AWS-LC C dependency).

Measured 2026-11-24, M3 Max (16c), Xcode 27.3 beta 2 fixture, liblzma 5.8.4
vs lzma-turbo 0.12.1. **The machine was not idle** (load average 7–26 from
other work, so absolute times are inflated); runs were interleaved and CPU
time is stable to ±0.5%, but treat wall times as indicative and re-measure
on an idle machine before relying on them.

| measure | liblzma | lzma-turbo | Δ |
|---|---|---|---|
| single thread, 23 real 16 MiB segments, best-of-7 | 178 MiB/s | 223 MiB/s | −20% time |
| `inspect --verify` checksum pass (decode + SHA-256, all cores), 4 interleaved rounds | 5.94–6.09 s | 4.81–4.86 s | −20% |
| same, user CPU | 69.1 s | 56.0 s | −19% |
| `bench.py -d` (`--dry-run`), 6 runs, not interleaved | 5.38 ± 0.73 s | 4.32 ± 0.12 s | −20% |

(`libcompression` measured 66.2 s CPU / 5.10 s dry-run in the same sessions.)
The zero-fill costs nothing measurable (71.6 vs 71.8 ms/segment). Decoded
output is byte-identical to liblzma's on all sampled segments, and all 624
segments (9.75 GiB) of the fixture pass their SHA-256 checks.

What is **not** measured: a full extract with writes. The attempt was
abandoned when the machine stalled. Per "The one fact that explains the
architecture", a full extract is writer-bound, so expect the CPU saving to
show up as lower CPU use rather than shorter wall time, as with
libcompression.

Costs of adoption: the crate declares `rust-version = 1.97.1` (xaea's MSRV
moved from 1.88), and it is Apache-2.0 where xaea is MIT.

## What verification costs (and how it hides)

Verify-by-default (batch `0820ee1`) initially regressed 8.4 s → 13.0 s.
Attribution: upfront serial segment-MAC pass ~1–1.5 s, queue-12
backpressure ~1.5 s, inline decode checksums ~0.5–1 s, final-pass drain
+0.7 s. The recovery was structural, not by cutting checks:

- Header MACs + signature + chain policy stay **synchronous upfront**
  (they're cheap, and must happen before the main key exists anyway);
- the expensive **per-segment MAC pass runs concurrently with the whole
  pipeline** via `std::thread::scope`, deliberately capped at **4
  threads** (`min(4)`) so it hides underneath the CPU-bound decode
  instead of competing with it; joined *before* the final pass, failures
  still abort extraction;
- **per-segment SHA-256 rides inline on the decoder threads** —
  essentially free next to LZMA, and it means no segment's bytes reach
  the filesystem before its own check.
- **…which makes xz's own check redundant**, so verified decodes pass
  `LZMA_IGNORE_CHECK` to liblzma (the .xz CRC64 covers the same decoded
  bytes the SHA-256 does). Microbenchmark, 16 MiB CRC64 segment, x86-64:
  110 ms → 93 ms together with the switch to one-shot
  `lzma_stream_buffer_decode` (no `BufReader` input copy, no zero-filled
  output). With `--no-verify` the xz check stays on if the stream has one.
  **Apple's segments don't:** every .xz stream header in the Xcode 27.3 b2
  fixture declares check type 0 (none) — checked by scanning for the xz
  magic and reading the low nibble of byte offset 7 (all 633 headers
  found, which includes a few `.xz` files stored inside segments; the 624
  real segments are among them). So this flag is a no-op on real archives
  (measured below); the "110 → 93 ms" above came from a synthetic CRC64
  stream and should not be read as an Apple-archive number. It stays in
  as harmless future-proofing should Apple start emitting a check.

Net: verification costs **1.6 s of a 10.6 s run** (10.6 vs 9.0), which
is why it's the default.

## Trajectory (how it got here)

M2 single-threaded → M3 first parallel pipeline **14.3 s** (byte-identical
output proven) → chmod-skip −1.2 s → stats instrumentation → syscall
offload **9.8 s** → jobs/writers grid **8.80 s** → cores−1 A/B **8.4 s**
→ hardening batch regressed to 13.0 s → queue-32 + concurrent segment
MACs → **10.6 s verified / 9.0 s unverified** at v0.1.0. Every step was
re-proven byte-identical (167,541 paths, zero diffs, permission modes
included) against the oracle tree with `scripts/verify.sh`.

## What the xz upgrade does (and doesn't) buy

The PR moves the vendored xz-utils from 5.2.5 (`xz2`/`lzma-sys`) to 5.8.4
(`liblzma-sys`). **On Apple Silicon this does not make the decoder faster**,
and neither does skipping the xz integrity check on Apple's archives.

Why, from the vendored sources' NEWS and `rangecoder/range_decoder.h`:

- The LZMA decoder speed work landed in the 5.5.x development series /
  5.6.0 (2024): "Speed optimizations to the C code and added GCC & Clang
  compatible inline assembly for x86-64." Three variants were built at
  first (basic C, branchless C, x86-64 inline assembly).
- Before 5.6.0 shipped, the branchless C variant was disabled again: in
  Lasse's benchmark feedback it "can be better than basic on x86-64 but
  often it's slightly worse on other archs. Since asm is much better on
  x86-64, branchless C is not used at all."
- The resulting default is `LZMA_RANGE_DECODER_CONFIG 0x1F0` (the asm
  range decoder) **only** for x86-64 with GCC/Clang, and `0` (basic C)
  everywhere else, including every `aarch64` build. So Apple Silicon runs
  the basic C decoder; 5.6+ only tweaked that path by "a few percent over
  5.4.x" per the NEWS, which does not show against 5.2.5 here.
- 5.8.0 added SSE2 intrinsics instead of `memcpy()` in the LZMA/LZMA2
  decoder on 32/64-bit x86 (0–5% typically, >15% on musl with highly
  compressed data). Also x86-only.

Measured, one real 16 MiB slice of an Xcode binary (`LLDB.framework`),
`lzma_stream_buffer_decode`, single thread, best of 15,
`scripts/xz_decoder_bench.sh`. The "no check" rows are what Apple's
segments actually look like (check type none); the CRC64 rows are a
stream made with `xz -6 --check=crc64`, for comparison:

| | 5.2.5 | 5.8.4 |
|---|---|---|
| M4 Max, no check | 124.7 / 124.8 / 124.8 ms | 125.0 ms |
| M4 Max, no check + `LZMA_IGNORE_CHECK` | — | 124.9 / 125.0 ms |
| M3 Max, no check | 167.7 / 155.8 / 162.8 ms | 161.6 / 155.6 / 162.1 ms |
| M4 Max, CRC64 checked | 136.5 ms | 136.8 ms |
| M4 Max, CRC64, `LZMA_IGNORE_CHECK` | 124.8 ms | 125.0 ms |
| M3 Max, CRC64 checked | 170.3 / 168.7 ms | 171.6 / 168.2 ms |
| M3 Max, CRC64, `LZMA_IGNORE_CHECK` | 153.9 / 158.9 ms | 157.1 / 154.2 ms |
| x86-64 Xeon, CRC64 checked (earlier session, not re-run) | 143 ms | 110 ms (−23%) |

- **aarch64:** the two versions are identical within noise, with or without
  a check. `LZMA_IGNORE_CHECK` is worth −8–9% *only* for streams that carry
  a CRC64 (it saves the CRC64 pass), which Apple's do not, so it changes
  nothing on real archives.
- **x86-64:** the −23% is the asm range decoder (plus the C tweaks). It
  applies to the Intel slice of the universal macOS binary and to Linux
  x86-64, not to the M-series numbers in this document.

So the xz bump is worth keeping for x86-64 and for being a maintained,
current library.

**Where the decode-only gain actually comes from** (measured 2026-11-24,
issue #43): the decode-only −4.4% on M4 Max is carried almost entirely by
the crate swap, not by the one-shot call or the removed copy. The method
was to build each of PR #38's decode-related commits (`ce88662` xz bump,
`4051cca` one-shot decode, `6017a12` direct-into-`Arc`) plus their parent
in clean worktrees, and time `extract --dry-run` on the fixture — 9 runs
per binary, interleaved in both orders, machine quiet (load ≈ 1.4), on an
M4 Max (not the M3 Max: that machine is too busy to benchmark reliably):

| bin | mean | σ | Δ vs base | Δ vs parent commit |
|---|---|---|---|---|
| base (`ce88662^`, xz2 0.1.7 / lzma-sys 0.1.20 / xz 5.2.5) | 4.608 s | 0.008 | — | — |
| base + `-DNDEBUG` (asserts compiled out; same source as base) | 4.588 s | 0.006 | −0.4% | — |
| xz (`ce88662`, liblzma 0.4.9 / xz 5.8.4) | 4.414 s | 0.007 | −4.2% | −4.2% |
| oneshot (`4051cca`) | 4.400 s | 0.009 | −4.5% | −0.3% |
| arc (`6017a12`) | 4.386 s | 0.008 | −4.8% | −0.3% |

Total: 4.608 → 4.386 s (−4.8%), consistent with the −4.4% the PR reported
(4.63 → 4.43 s). Per commit: the xz bump ~4.2%, the one-shot call ~0.3%,
the direct-into-`Arc` copy ~0.3%.

Two things this rules out: the C decoder itself is provably identical on
aarch64 (the single-segment microbenchmark above shows 124.7 vs 125.0 ms
best on M4 Max), and compiling the old decoder with `NDEBUG` (its live
`assert()`s compiled out) is worth only −0.4% — so neither the decoder's
speed nor the assert fix explains the −4.2%. The micro-cause of the crate-swap
gain (Rust wrapper, LTO/codegen, or both) was not isolated. What is
settled is the split between the decode commits: the PR's "gains come
from the one-shot call and the removed copy" framing is not supported by
the whole-extract measurement on M4 Max — the bulk of the decode-only
gain comes from the xz crate swap. The full-extract gain (~10%) is
still dominated by the syscall, symlink-pass and read-ahead changes,
which these decode-only numbers do not isolate.

### Skipping the xz check is safe here, and moot for Apple archives

liblzma's documentation says `LZMA_IGNORE_CHECK` should not be used
unless the data's integrity is verified externally. It is: with
verification on (the default), every decoded segment is SHA-256'd
against the segment checksum from the archive before any of its bytes
reach the filesystem, and every segment's MAC over the *compressed*
bytes is checked concurrently (joined before the final pass). Both are
stronger than any xz check and cover the same bytes. Since Apple's
segments carry no xz check at all, `--no-verify` extractions of Apple
archives have no integrity checking in the decode path (only the size
check); that matches what `--no-verify` documents.

## Profiling build (`--features profile`)

```sh
cargo build --release --features profile
XAEA_STATS=1 ./target/release/xaea extract FILE OUT   # per-stage breakdown
XAEA_TL=1    ./target/release/xaea extract FILE OUT   # 250 ms timeline
XAEA_WQ=64   ./target/release/xaea extract FILE OUT   # writer queue depth
```

Without the feature the probes (`src/prof.rs`) are empty inline shims.
`XAEA_STATS` then adds summed-over-threads seconds for: decoder
pread / lzma / sha256 / send-blocked; parser recv-wait / feed /
send-blocked; writer idle / mkdir / open / close / fchmod / pwrite and
the final passes. `XAEA_TL` prints, per 250 ms, segments decoded and
parsed, opens/s, MiB/s written, and thread-equivalents blocked/busy.
For kernel-side CPU, `xctrace record --template 'Time Profiler' --launch
-- xaea extract …` plus `scripts/prof_trace.py` (aggregates an exported
`time-profile` table per thread role). `scripts/fs_create_bench.rs` is
the raw `open(O_CREAT)`/`close` microbenchmark referenced below.

### What the profile showed (Xcode 27.3 b2, M3 Max, full extract ≈ 9 s)

- CPU: ~70 s user (LZMA 91%, ~8% of that `memmove` — but see "Decoder
  copy cost (#45)" below: it is LZ77 match expansion, not the
  dictionary→output flush; SHA-256 ≈ 5 s; segment MACs ≈ 1 s) + ~23 s sys,
  almost all writers. A dry run is the ~5 s decode floor (≈14 busy cores).
- Writer kernel time: `open` 51%, `pwrite` 22%, `mkdir` 12%, `close`
  9%, symlink 3%. A single writer needs ~14.8 s of sys; 8 writers burn
  ~26.8 s for no extra throughput past ~4 writers — contention, not work.
- The run has two phases. First ~5 s (≈110k files): filesystem-bound at
  ≈25k opens/s, writers saturated, parser blocked on writer queues ~97%
  of the time, decoders idle against a 19-segment window. Then ~3 s of
  large files: decode-bound, writers mostly idle. They ran back to back;
  deeper read-ahead overlaps them (hence `--readahead`).

Read-ahead sweep (full extract, 6 runs):

| `--readahead` | M3 Max wall | M3 peak RSS | M4 Max wall | M4 peak RSS |
|---|---|---|---|---|
| 19 (old) | 9.00 s | 3.2 GiB | 6.55 s | 3.2 GiB |
| 64 | 8.73 s | 3.9 GiB | 6.32 s | 3.9 GiB |
| 160 (default ≥ 32 GB) | 8.22 s | 5.3 GiB | 6.10 s | 4.8 GiB |
| 640 | 7.89 s | 6.3 GiB | 6.15 s | 4.8 GiB |

M4 Max vs 0.1.3 for the PR as a whole: `--dry-run` 4.63 → 4.43 s (−4.4%),
full extract 6.99 → 6.61 s (−5.4%), before the read-ahead change.

M4 Max reference (16c, same fixture, 5–8 runs): Apple's
`archiveutil extractXcodeAEA` 38.87 ± 0.19 s (it takes no output dir and
extracts into the cwd) against xaea 0.1.3 6.99 s, this PR 6.61 s, and
this PR with `--readahead 160` 6.09 s — ≈6.4× faster than Apple's tool.
Note archiveutil's output is smaller on disk (3.9 GiB `du` vs the 9.7 GiB
payload), i.e. it applies transparent APFS compression. xaea did not at
the time of that measurement, so the caveat then was that the two tools
were not doing identical work. They are now — xaea compresses by default
too (#48) — and still wins on the same M3 Max footing: 12.30 s against
archiveutil's 40.0 s, ≈3.3×. The probes cost nothing in default builds:
new build with
`--readahead 19` vs the pre-probe binary, A/B in both orders, 6.61–6.65 s
vs 6.65–6.67 s (σ ≈ 0.05–0.1 s).

### Tried and rejected in this round

- **Closing files on a dedicated thread** (1–2 closers): no gain (9.25 /
  9.24 / 9.40 s) — `close` serializes on the same filesystem locks.
- **Deeper writer queues** (128): no gain.
- **`openat` against a cached dir fd, or `O_EXCL` instead of `O_TRUNC`**:
  identical to full-path `open` in the microbenchmark (≈65k creates/s
  ceiling at 6 threads). Path walking is not the cost.
- **Routing files to writers by parent directory** (or in chunks of N
  consecutive files): `open` gets cheaper (16.5 → 10.1 s summed, sys
  23.6 → 18.3 s) — same-directory creates do contend — but big
  directories pin one writer and wall time gets worse (12.6 s pure;
  chunks of 2–32: 9.3–10.4 s vs 9.4 s round-robin, i.e. no gain). A
  least-loaded variant was not tried then; the spill-threshold retry of
  exactly that idea is measured under "Directory affinity measured
  (#46)".
- **More writers**: see above; 4–6 is the knee.

### Not yet tried

Parallelizing the final symlink pass (0.6–0.7 s serial tail; the
traversal check can run in the parser, creation could fan out).

### Decoder copy cost (#45)

Issue #45 read the ~8% `memmove` above as liblzma copying decoded bytes
from its internal dictionary into the caller's output buffer, and asked
whether a patch could alias the dictionary onto the output buffer to skip
that copy. Profiling a single segment refutes the attribution.

Method: a 16 MiB slice of the LLDB binary, `xz -6 --check=crc64` (4.67 MiB
in), decoded one-shot into an exact-size buffer by a `sample`-able harness
(`decode_prof`, release + debug symbols), 1 ms sampling, both decoders.
The call tree resolves entirely inside the statically-linked binary, so the
leaf addresses are unambiguous:

| leaf | samples | reached from | what it is |
|---|---|---|---|
| `_platform_memmove` @ `…f2c` | 565 | `lzma_decode` → `dict_repeat` | LZ77 match expansion (`SEQ_COPY`) |
| `DYLD-STUB$$memcpy` | 29 | `lzma_decode` → `dict_repeat` | same, small-match path |
| `_platform_memmove` @ `…db8` | 9 | `lz_decode` → `decode_buffer` | the dictionary→output flush |

Of 6065 samples, the dictionary→output flush — the exact copy #45 proposed
to remove — is **9 samples (≈ 0.15%)**, not 8%. The ~8% is `dict_repeat`
copying match bytes within the dictionary window, which is inherent to
LZ77: every decoder must materialise matches into the window. Aliasing
`dict.buf` onto the output buffer would eliminate only the 9-sample flush,
so the patch is not worth it.

Apple's `libcompression` shows **zero** `_platform_memmove` samples — its
`lzma1_chunk_decode` inlines and vectorises the match copies instead of
calling out to the platform routine — and is ~5% faster decode-only
(142.8 ms vs 150.2 ms best-of on the slice). That matches PR #60: the gain
is real but confined to the decode floor, and full extract is writer-bound,
so end-to-end wall time is indistinguishable. The decode-only win is
already available via `--decoder libcompression`; no liblzma patch is
warranted.

## Compressed extraction (the macOS default)

On macOS, `extract` stores files the way Apple's extractor does: decmpfs
with LZBITMAP (layout in FORMAT-NOTES); `--no-compress` turns it off. It
was made the default because saving ~6 GiB per Xcode install is worth ~4 s
per extraction. Xcode 27.3 b2, M3 Max, warm cache,
three runs each:

| | time | on disk | peak RSS |
|---|---|---|---|
| xaea (plain) | 7.8–8.2 s | 9.99 GiB | 5.7 GiB |
| xaea (compressed) | 12.1–12.5 s | **3.86 GiB** | 6.2 GiB |
| `archiveutil extractXcodeAEA` | 38.8 s | 3.86 GiB | — |

The output is byte-identical to the plain extraction when read back (`diff
-r`), modes and symlinks are identical, and `codesign --verify --deep
--strict` passes. It is ~0.1% smaller than Apple's (4,044,896 vs 4,049,568
KiB). It has exactly Apple's 88,006 inline files, but leaves ~970 more files
plain where a fork would not save a 4 KiB block.

Where the time goes. Encoding 9.7 GB at ~350 MB/s per core is ~28
core-seconds on top of ~76 s of LZMA, so the run is CPU-bound well before
the disk matters:

* **Writer routing was the first wall.** With round-robin file routing and
  6 writers it took 18.9 s. The parser was send-blocked 16.3 s while
  writers sat idle for 44 thread-seconds: a writer busy encoding a large
  file stalls its queue of small files while the others starve.
  Least-loaded routing (queued bytes + a 32 KiB-equivalent per open)
  brought 6 writers to 13.3–13.7 s. It is only enabled when compressing:
  on the plain path it measured neutral (7.9–8.1 s either way).
  `XAEA_BALANCE=1` turns it on there for experiments; re-measured
  paired on the M4 Pro mini it is a real +0.05 s (8/8 rounds) — below
  any bar for a default change (#46 below).
* **Then writer count.** Writers now do CPU work, so more help, up to a
  point: 6 → 13.7 s, 8 → 12.7 s, 10 → 12.6 s, 14 → 12.4 s, 20 → 16.5 s
  (sys time climbs). The default is 10 when compressing. Trimming decoders
  to 12 gained another ~0.4 s, which is within noise, so not adopted.
* Files that don't compress are detected early: after 2 MiB with < 2%
  saved, the encoded part is decoded back and the rest goes straight to
  `pwrite`. So the large `.pkg` payloads cost ~2 MiB of wasted encoding,
  not hundreds of MiB.

**A shared encode pool was measured and rejected.** The hypothesis: encoding
inside the owning writer serialises large files, so a pool that leaves writers
syscall-only would recover the stall. It does not pay, and not because encoding
is cheap. On an M4 Pro (10 performance + 4 efficiency cores, 64 GiB), 10
writers, encode is **55% of writer busy time** — 39.4 core-seconds of a 71.7 s
busy total across a 10.3 s run. Two other measurements close it:

* **Encode work is flat across files.** 126,204 files, 9.25 GiB encoded: the
  largest single file (182.9 MiB) is 1.9% of the total, the top 15 are 15.6%,
  and the six files ≥128 MiB together are 7.4%; the bulk sits in the <8 MiB
  bucket. Even perfectly parallelised, that largest file is ~0.75 s of
  single-core encode — too short for a writer to be pinned usefully.
* **The tail is already parallel.** Through the large-file tail, 4–10 writer
  threads encode at once, peaking at 9.9. A pool would relocate the same 39.4
  core-seconds onto the same cores and add no parallelism.

Least-loaded routing (above) had already removed the queue-level head-of-line
effect; this removes the within-file one as an explanation for the writer-count
plateau at 10–14. Taken with a temporary probe behind `--features profile`, not
upstreamed. The distribution is an archive property and so travels to other
machines; the saturation numbers do not — they were taken where decoder plus
writer demand exceeds the core count, and on a heterogeneous machine a
per-logical-core throughput figure is misleading anyway, since a quarter of the
threads land on efficiency cores.

The same probe puts **`finish()`/xattr store at 19.25 s across ~125k compressed
files (~154 µs each)** — bigger than `open`, and a better lever than encode
parallelism if writer time is attacked again. The 39.4 core-seconds of encode
also exceed the ~28 estimated from throughput above; different machine and
different method (directly accounted vs derived), and the gap is unexplained.

Not yet measured on M4 Max. Not tried: LZFSE for a better ratio at half the
speed.

### The per-file store path measured (#67): real wall, half CPU, nothing removable

Issue #67 asked whether the ~19.25 core-seconds the #61 probe attributed to
`WStore` (the decmpfs store in `finish()`, ~125k compressed files, ~154 µs
each — bigger than `open`) was real, and whether any of it was removable.
The wall is real, it is not core-seconds, and none of it is removable.
Measured on the M4 Pro mini (10P + 4E cores, 64 GiB) at `88cc811`,
hash-verified fixture, warm cache, `caffeinate -i`; temporary probe behind
`--features profile` (wall + `CLOCK_THREAD_CPUTIME_ID` per span, `finish`
split from `spill`, per-syscall wall), three warm runs, spread ≤ 7% on
every store metric (full-run wall σ ≈ 0.2 s). The CPU clock was validated
against a non-reducible busy loop (44 ms wall read as 44 ms CPU).
Quiescence: the series began at load 0.94 with all `md*` at 0.0%; the
resident GUI processes (Activity Monitor, sysmond, oMLX) were sampled
instantaneously (`top`, second sample) before and after every run and never
exceeded 12% each. Runs taken back-to-back carry the previous run's 1-min
load (4.4, 6.0 — self-inflicted, 15-min mean stayed ~2.1); `finish` wall
showed no trend with it (21.35 / 20.55 / 22.09). `xctrace` failed to record
on that machine without sudo, so the independent check is the standalone
microbench below rather than a sampling profile.

- **The wall is real.** `finish()` sums to **21.4 s across 10 writers**
  (20.6–22.1) on an idle machine — slightly *above* the 19.25 s taken
  under saturation. Descheduling did not inflate the headline number.
- **It is not core-seconds.** Thread-CPU inside `finish()` is **10.7 s**;
  the other ~half is kernel block time (APFS journal/lock waits inside
  the syscalls). Wall-in-closure accounting overstates CPU ~1.8× here —
  the same effect that left #66's encode figure above its throughput
  estimate, now measured directly.
- **`spill` is not the confounder**: decode-back + pwrite for give-up and
  not-worth-it files totals 0.09 s across 1,286 calls.
- **Per-syscall wall, µs/call** (126,198 finishes: 88,007 inline, 36,913
  fork): inline `com.apple.decmpfs` xattr 97 µs (8.6 s — this write
  *carries the file's compressed bytes*, ~1.2 KiB each);
  `com.apple.ResourceFork` 139 µs (5.1 s, ~83 KiB each — the compressed
  data itself); `fchflags` 39 µs (4.8 s); the 16-byte fork-path header
  xattr 57 µs (2.1 s); `fstat` 4.3 µs (0.55 s).
- **A 100-line microbench reproduces it without xaea.** Create + the same
  xattr/flag sequence, 10 threads, same volume: 99 / 160 / 26 / 4 µs —
  within 15% for the two xattr writes; `fchflags` reads lower in isolation
  (26 vs 39 µs; the microbench's files carry lighter forks). Single-thread
  floors: a 1 KB decmpfs xattr costs 17.5 µs where 16 B costs 6.8 and
  3.5 KB costs 17.4 — mostly a fixed decmpfs-xattr cost, not per-byte; a
  90 KiB fork 30 µs; `fchflags` 13 µs on a decmpfs file vs 7 µs on a plain
  one (the kernel's compression-state transition); `fstat` 1 µs. This is
  APFS behaviour under concurrent file creation, not our code shape.
- **Nothing removable.** The two xattr writes *are* the data path; the
  flag is required and must stay last (crash-safety ordering). The
  defensive `fstat` is provably redundant — `check_top_level` blocks every
  path by which `finish()` could see a pre-existing file, hardlinks exist
  only in the deferred pass, and `UF_COMPRESSED` is the only flag this
  program sets, so `fchflags(UF_COMPRESSED)` and
  `fchflags(st_flags | UF_COMPRESSED)` are the same call — but at
  4.3 µs × 125k ≈ 0.5 core-seconds ≈ 0.05 s of wall it sits below the
  noise floor: technically droppable, provably worthless.

The intuition that failed is "three or four syscalls can't cost 154 µs".
Under 10-way concurrent creation on APFS they demonstrably can, and the
dominant one is not metadata overhead at all — it is the compressed
payload going through the xattr interface because that is what decmpfs is.

### Directory affinity measured (#46): the contention is real, the savings are not on the wall

Issue #46 asked whether PR #38's directory-routing `open` win (16.5 →
10.1 s summed, sys 23.6 → 18.3 s, M3 Max, pre-least-loaded) could be
salvaged by preferring the directory's writer and spilling to the
least-loaded one once that queue runs deep. Prototyped on
`exp/dir-affinity-46-proto`, kept out of main — a knob that measures
zero does not earn its ~230 lines: a directory's mkdir binds it to a
writer, its files prefer that writer while its
queued work (the same byte counter the balancer uses) stays under a
spill threshold N, and the binding survives a spill — sticky, so the
directory returns to its writer when the queue drains. Every routed
tree measured was byte-identical to the unrouted one (both modes, full
fixture, `diff -r` plus codesign-clean).

Measured on the M4 Pro mini (10P + 4E, 64 GiB) — single-machine data;
the M3 Max the issue named was unmeasurable this round. Hash-verified
fixture, warm cache, `caffeinate -i`, advisory lock, series start gated
at 1-min load ≤ 2.1 with all `md*` at 0.0%; the runs themselves carry
self-inflicted 1-min load 5.5–14.5, as in #67. Interleaved with
rotating variant order per round, paired per-round differences,
n = 8 rounds per series. Decision rule fixed before measuring: a win
is a paired mean ≥ 0.15 s at ≥ 3 SE with ≥ 6/8 sign agreement.
Δ = base − variant; positive means affinity faster.

Compress mode (the macOS default; base 10.998 s):

| variant | Δ mean ± SE | t | rounds favoring |
|---|---|---|---|
| `dir:256k` | +0.000 ± 0.044 s | 0.0 | 4/8 |
| `dir:1m` | −2.721 ± 0.036 s | −75 | 0/8 |
| `dir:4m` | −4.016 ± 0.080 s | −50 | 0/8 |

Plain mode (base 7.257 s; `bal` = `XAEA_BALANCE=1`, the load counters
with no affinity):

| variant | Δ mean ± SE | t | rounds favoring |
|---|---|---|---|
| `bal` | +0.025 ± 0.019 s | 1.3 | 6/8 |
| `dir:1m` | −1.011 ± 0.043 s | −23 | 0/8 |
| `dir:4m` | −1.437 ± 0.047 s | −30 | 0/8 |

A second plain series (8 rounds, base 7.253 s) filled the grid:
`bal` +0.053 ± 0.008 s (8/8), `dir:256k` +0.055 ± 0.011 s (8/8). The
load counters are a real +50 ms on the plain path — consistent across
both series — but an order of magnitude below the bar, and 256k
affinity adds nothing on top of them.

The threshold ladder reproduces #38's chunking result, and the queue
arithmetic says why. A writer queue holds 32 messages; a file is two of
them (Open + Slice) and the average file is ~81 KiB, so a full queue is
~1.8 MiB of counted work. `dir:4m` can never spill — pure directory
routing with the escape hatch welded shut — and loses 4.0 s, the same
failure as #38's 12.6 s pure run. `dir:1m` spills only past half a full
queue, so a hot directory ping-pongs between its writer and one other
while the rest of the pool idles: −2.7 s. `dir:256k` spills after ~2
queued files, restoring the full spread — and measures zero. The
threshold that preserves parallelism is the threshold at which affinity
barely exists.

The profile build confirms the contention is real and that the wall
does not care (plain, one profile-feature run each, summed over writer
threads; wall there is not a timing measurement):

| variant | summed `open` | `mkdir -p` fallback | writer idle | wall |
|---|---|---|---|---|
| base | 8.85 s | 0.98 s | 21.0 s | 7.0 s |
| `dir:256k` | 9.05 s | 0.86 s | 21.4 s | 7.0 s |
| `dir:1m` | 6.77 s | 0.25 s | 31.2 s | 7.9 s |
| `dir:4m` | 6.52 s | 0.10 s | 34.8 s | 8.3 s |

So the second prize is real — affinity removes ~90% of the `mkdir -p`
fallback and a quarter of summed `open` time, reproducing #38's
contention finding on this machine — and it is worth nothing, because
the removed time lands in writer idle, which was already 21
thread-seconds. Same shape as the encode-pool rejection above: time
saved on a stage that has slack buys no wall.

The intuition that failed is "contention costs a fifth of the
filesystem-bound phase, so removing it wins a fifth." Contention costs
summed thread-seconds, not wall: with 6–10 writers there is more than a
fifth of slack, and the only routings that capture the savings spend
more than they are worth in lost parallelism.

## Re-measuring

```sh
cargo build --release
XAEA_STATS=1 ./target/release/xaea extract fixtures/Xcode_27.3_beta_2.aea -o /tmp/out
# prints: parse+dispatch time, writer drain time — the two numbers that
# tell you which side of the pipeline is the bottleneck.
./scripts/verify.sh <new-tree> <oracle-tree>   # correctness gate, always
```

For A/B timing use `scripts/bench.py`: hyperfine over a real
`extract` (wiping the output dir before each run), any number of named
variants, plus machine/rev header and a mean/σ/min/CPU/peak-RSS/MiB/s
table. `-d` for dry-run, `-r`/`-w` for runs/warmups, `-h` for the rest:

```sh
scripts/bench.py fixtures/Xcode_27.3_beta_2.aea 'liblzma=--decoder liblzma' 'libcompression=--decoder libcompression'
scripts/bench.py -d -r 10 fixtures/Xcode_27.3_beta_2.aea 'w4=-w 4' 'w6=-w 6'
```

Warm the cache first (extract once to /dev/null-ish, or just discard the
first run). The CI `perf` workflow (hyperfine, warmup run, throughput =
payload bytes / mean wall) tracks the same numbers on every PR; a budget
gate (fail the run above N seconds) is planned there.

Platform caveat: all of the above was tuned on macOS/APFS by design. On
Linux the code builds and runs cleanly, but treat the defaults as
starting points — re-run the grid via `--jobs`/`--writers` before
trusting them.
