# Performance notes — why `unaea` is as fast as it is

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
| **unaea**, verification on (default) | **10.6 s** |
| **unaea** `--no-verify` | 9.0 s |
| unaea `--dry-run` (decode+parse, no writes — the CPU floor) | 6.6 s |
| unxip (same-version `.xip`, for scale) | 24.8 s |
| Apple `archiveutil extractXcodeAEA` | 40.0 s |

≈1,000+ MiB/s of payload written. These are M3 Max numbers; the shape of
the result (writer-bound, verification cheap) should transfer, the
absolute seconds will not.

## The one fact that explains the architecture

**The wall is filesystem-syscall serialization, not CPU and not write
throughput.**

`UNAEA_STATS=1` on the first M3 pipeline showed the parse+dispatch thread
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
  copied exactly once: into the page cache at `pwrite`.
- **Reorder + parse thread** reassembles segment order (HashMap keyed on
  sequence + `next_expected` cursor), runs the object-stream parser, and
  *only* dispatches work. No syscalls here — that's the whole point (see
  the one-fact section).
- **Writer threads (default 6)** execute every syscall
  (`mkdir`/`open`/`chmod`/`symlink`/`pwrite`/quarantine) fed by
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
| decoder channel | `nd + 4` | small bound keeps memory pinned without starving reorder |
| writer queue | 32 per writer | queue depth 12 cost **~1.5 s** of parser throughput via backpressure; 32 restored in the hardening batch. Worst case pinned memory: writers × 32 × segment size ≈ **3 GiB** — deliberate trade, documented in `extract.rs` |

Raw grid/A-B logs lived in `/tmp/bench_{grid,ab,g2,jobs}.log`
(transient; regenerate with `UNAEA_STATS=1` runs before touching these
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

## Re-measuring

```sh
cargo build --release
UNAEA_STATS=1 ./target/release/unaea extract fixtures/Xcode_27.3_beta_2.aea -o /tmp/out
# prints: parse+dispatch time, writer drain time — the two numbers that
# tell you which side of the pipeline is the bottleneck.
./scripts/verify.sh <new-tree> <oracle-tree>   # correctness gate, always
```

Warm the cache first (extract once to /dev/null-ish, or just discard the
first run). The CI `perf` workflow (hyperfine, warmup run, throughput =
payload bytes / mean wall) tracks the same numbers on every PR; a budget
gate (fail the run above N seconds) is planned there.

Platform caveat: all of the above was tuned on macOS/APFS by design. On
Linux the code builds and runs cleanly, but treat the defaults as
starting points — re-run the grid via `--jobs`/`--writers` before
trusting them.
