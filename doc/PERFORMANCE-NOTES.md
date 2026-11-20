# Performance notes — why `xaea` is as fast as it is

This is the measured history behind the numbers in the README: which
architecture decisions buy the speed, what the instrumentation showed,
which tempting optimizations were tried and **rejected**, and how to
re-measure. Read this before "optimizing" anything — several obvious
ideas are already in the code, and several others were proven useless or
harmful on APFS.

## Baseline numbers

Fixture: `fixtures/Xcode_27.3_beta_2.aea` — 2.03 GiB compressed →
9.71 GiB payload (624 segments / 3 clusters), 137,459 entries
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

## Alternate LZMA decoder: Apple's libcompression (`--decoder`)

`--decoder libcompression` decodes segments with the OS's
`compression_decode_buffer(COMPRESSION_LZMA)` (LZMA2 in the same .xz
container) instead of the vendored liblzma. Opt-in; liblzma stays the
default because it is portable and its behaviour is pinned by our build.
Measured on M3 Max, Xcode 27.3 b2 fixture, `scripts/bench.sh` — **against
xz 5.2.5** (the old `xz2`/`lzma-sys` crates). The vendored liblzma is now
xz 5.8.x via the `liblzma` crate, which decoded a 16 MiB segment ~23%
faster in a microbenchmark (x86-64), so this comparison needs re-running:

| run | liblzma | libcompression |
|---|---|---|
| **full extract, defaults, verify on** — the real-world number, run A (5 runs) | 9.42 ± 0.33 s | 8.97 ± 0.46 s (−4.7%) |
| same, run B (8 runs) | 9.88 ± 0.54 s | 9.31 ± 0.30 s (−5.8%) |
| `--dry-run`, default jobs (CPU floor) | 5.40–5.80 s, ~74 s CPU | 5.12–5.54 s, ~69 s CPU (−5%) |
| `--dry-run --no-verify -j 2` — isolation microbenchmark, not a usage scenario | 31.0 s | 28.7 s (−8%) |

The `-j 2` row exists only to isolate per-core decoder throughput: with
two decoders and nothing else running, wall time is pure LZMA (CPU ≈
2 × wall), free of writer/MAC-pass contention and clock-boost effects.

Read the full-extract result as "roughly 5%": the gap (0.4–0.6 s) is
about the size of run-to-run σ, and absolute times drifted ~0.5 s
between sessions. More runs (`scripts/bench.sh -r 20`) would tighten it.

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
  output). With `--no-verify` the xz check stays on: it is then the only
  integrity check. The saving assumes Apple's segments carry CRC64 (check
  type: low nibble of byte offset 7 of each segment's stream header = 0x4).

Net: verification costs **1.6 s of a 10.6 s run** (10.6 vs 9.0), which
is why it's the default.

## Trajectory (how it got here)

M2 single-threaded → M3 first parallel pipeline **14.3 s** (byte-identical
output proven) → chmod-skip −1.2 s → stats instrumentation → syscall
offload **9.8 s** → jobs/writers grid **8.80 s** → cores−1 A/B **8.4 s**
→ hardening batch regressed to 13.0 s → queue-32 + concurrent segment
MACs → **10.6 s verified / 9.0 s unverified** at v0.1.0. Every step was
re-proven byte-identical (137,459 paths, zero diffs, permission modes
included) against the oracle tree with `scripts/verify.sh`.

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

- CPU: ~70 s user (LZMA 91%, ~8% of that `memmove` out of liblzma's
  dictionary; SHA-256 ≈ 5 s; segment MACs ≈ 1 s) + ~23 s sys, almost all
  writers. A dry run is the ~5 s decode floor (≈14 busy cores).
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
payload), i.e. it appears to apply transparent APFS compression, which
xaea does not; the comparison is wall time to a complete tree, not
identical work. The probes cost nothing in default builds: new build with
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
  least-loaded variant was not tried.
- **More writers**: see above; 4–6 is the knee.

### Not yet tried

Parallelizing the final symlink pass (0.6–0.7 s serial tail; the
traversal check can run in the parser, creation could fan out), and
avoiding liblzma's dictionary→output copy (~8% of decode CPU).

## Re-measuring

```sh
cargo build --release
XAEA_STATS=1 ./target/release/xaea extract fixtures/Xcode_27.3_beta_2.aea -o /tmp/out
# prints: parse+dispatch time, writer drain time — the two numbers that
# tell you which side of the pipeline is the bottleneck.
./scripts/verify.sh <new-tree> <oracle-tree>   # correctness gate, always
```

For A/B timing use `scripts/bench.sh`: hyperfine over a real
`extract` (wiping the output dir before each run), any number of named
variants, plus machine/rev header and a mean/σ/min/CPU/peak-RSS/MiB/s
table. `-d` for dry-run, `-r`/`-w` for runs/warmups, `-h` for the rest:

```sh
scripts/bench.sh 'liblzma=--decoder liblzma' 'libcompression=--decoder libcompression'
scripts/bench.sh -d -r 10 'w4=-w 4' 'w6=-w 6'
```

Warm the cache first (extract once to /dev/null-ish, or just discard the
first run). The CI `perf` workflow (hyperfine, warmup run, throughput =
payload bytes / mean wall) tracks the same numbers on every PR; a budget
gate (fail the run above N seconds) is planned there.

Platform caveat: all of the above was tuned on macOS/APFS by design. On
Linux the code builds and runs cleanly, but treat the defaults as
starting points — re-run the grid via `--jobs`/`--writers` before
trusting them.
