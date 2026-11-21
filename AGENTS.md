# AGENTS.md

Instructions for AI agents working on this repo. Both Claude Code and Codex
review and author changes here, and this file loads into every session — so
it stays short and holds only what the docs don't frame for you. The deep
docs are the source of truth; read them before touching what they cover.

## Orientation

`xaea` extracts Apple Encrypted Archives (`.aea`) — the Xcode distribution
container (profile 0: stored-compressed, signed, not encrypted) — faster
than Apple's `archiveutil`, with full verification (`README.md`). Edition
2024, `rust-version = 1.87` (`Cargo.toml:4-7`); CI pins the compiler at
`RUST_VERSION: 1.100.0` (`.github/workflows/ci.yml:19`) — use it locally
when a gate result has to mean what CI will say.

- `doc/FORMAT-NOTES.md` — the container and AA01 payload layout, verified
  against a real Apple artifact, incl. four spec errata. Read before
  touching `envelope.rs`, `aa.rs`, `kdf.rs`, `sigverify.rs`, or decmpfs layout.
- `doc/PERFORMANCE-NOTES.md` — the measured history behind the speed: tuned
  defaults, instrumentation, rejected optimizations. Read before any change
  that could move a number.
- `doc/RELEASING-LOCALLY.md` — GoReleaser as a local snapshot build. Only
  when working on release tooling.

## Verification gate

A branch is done only when all three pass — the exact CI commands
(`ci.yml:31,47,65`; clippy and test run on both ubuntu and macos, and
macOS-only code like `decmpfs.rs` compiles nowhere else):

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Tests needing the real 2 GB Xcode fixture are `#[ignore]`d and skipped by
default (`ci.yml:62-64`): `real_fixture_verifies_green`
(`tests/fixture.rs:26`) and the `link_pass_scaling` benchmark
(`src/extract.rs:1583`). Point `AEA_FIXTURE` at the archive to run them:
`AEA_FIXTURE=fixtures/Xcode_27.3_beta_2.aea cargo test --release --locked
-- --ignored --nocapture fixture` (README "Development"; CI's `fixture` job
does the same, `ci.yml:112`). The fixture test self-skips with `SKIP:` when
the path is absent (`tests/fixture.rs:32-35`) — a silent pass is not a run.

## When the branch is green, open a pull request — don't wait to be asked

Once `fmt`, `clippy`, and `test` pass locally, push a descriptively-named
branch and open a PR with `gh pr create --base main`, with `Fixes #N` in the
body when the work maps to an issue. Do not wait to be asked.

Opening the PR is the end of your authority:

- Never merge, and never enable auto-merge.
- Never add reviewers, assignees, or labels.
- Never comment on or close issues.
- Never touch repository settings, secrets, or variables.

Updating your own PR branch: `git push --force-with-lease`. Never bare
`git stash` — the stash stack is shared with the main checkout and every
other worktree, and other sessions use it concurrently; prefer a WIP commit.

## Precedence: measured decisions outrank style

`doc/PERFORMANCE-NOTES.md` is substantially a record of tempting
optimizations that were measured and rejected — "Read this before
'optimizing' anything" (line 6), "Things tried and rejected — don't
re-litigate" (line 123), tuned defaults "do not change without re-running
the grid" (line 101). Those measured decisions, and the security invariants
below, outrank any general Rust style guide, linter suggestion, or skill.
Generic tooling will confidently "simplify" load-bearing code (the
zero-copy `segbuf_filled` path, the umask chmod-skip, the exact-size decode
buffer); doing so requires saying explicitly why the documented measurement
no longer applies.

## Security invariants — do not refactor away

All in `src/extract.rs`; each is pinned by a test.

- **Symlinks and directory modes run in a deferred final pass**, after a
  per-writer `Flush` barrier drains every stream-phase write
  (`Work::LinkPass`/`Work::DirModes`, 314-320; barrier at 1263-1271).
  While records stream, no archive-created symlink exists, so no file write
  can be redirected through one (module doc, 19-22). Within the pass a link
  traversing an earlier archive link is refused (`link_pass_seq`, 440-466),
  and directory modes apply last so a hostile 0555 dir can't lock its own
  subtree. End-to-end coverage: `tests/link_pass.rs`.
- **Guard path comparisons are genuinely case-folded.** `lower_path`
  (339-348) and the `created` set in `link_pass_seq` (457-463) lowercase
  component-by-component using the same walk. A guard that compared
  non-lowercased paths silently bypassed containment on case-insensitive
  volumes — a real bug, pinned by `guard_is_case_insensitive` (1551-1578).
- **Privilege bits are stripped from every mode**: `rec.mode & 0o0777`
  (834) — an unprivileged extraction must never plant setuid/setgid/sticky.
- **Verification happens before bytes reach the filesystem.** Per-segment
  SHA-256 runs inline on the decoder threads (`decode_segment`, 1032-1039),
  so no segment's bytes reach a writer before its own check; signature,
  chain policy, and header MACs are enforced before any filesystem touch
  (`verify_upfront`, 1052-1057); the concurrent segment-MAC pass is joined
  before the final pass (1245-1258).
- Path policy: absolute paths rejected, `..` clamped to the root (`clamp`,
  924-943); absolute link targets rejected (`link_target`, 950-954); an
  existing top-level name aborts before the first byte is written
  (`check_top_level`, 793-815).

## Rust conventions (as actually used)

- **Errors are `anyhow` end to end.** No typed error enums exist in `src/`;
  raise with `bail!`/`ensure!`, add `.with_context(|| format!(…))` at each
  call site, and let `fn main() -> Result<()>` (`src/main.rs:103`) print
  the chain and exit 1. There is no exit-code classification beyond that;
  `inspect --verify` signals failure by erroring.
- `.unwrap()` appears in tests and in provably-total conversions
  (bounds-checked `try_into`, e.g. `src/envelope.rs:298`); elsewhere return
  `Result`.
- **Parallelism uses `std::thread::scope`** when work must not outlive its
  caller — the concurrent segment-MAC pass (`src/extract.rs:1110`) and the
  parallel link pass (488); plain `thread::spawn` only for pipeline stages
  the driver joins explicitly.
- **Unsafe is confined to FFI**: the statically-linked vendored liblzma
  (`liblzma-sys`, `Cargo.toml:25`; one-shot decode at `src/envelope.rs:106`)
  and Apple's libcompression (`#[link(name = "compression")]`,
  `src/envelope.rs:149-160`, `src/decmpfs.rs:59-80`), plus decmpfs
  xattr/flag syscalls (`src/decmpfs.rs`). The one non-FFI primitive is
  `segbuf_filled` (`src/envelope.rs:54-66`), whose `# Safety` contract —
  `fill` initializes every byte — is what makes zero-copy decoding sound.
  Every `unsafe` block carries a `// SAFETY:` comment; keep it that way.

## Benchmarking discipline

- Never run two benchmarks concurrently; every published number was taken
  one tool at a time with nothing else running
  (`doc/PERFORMANCE-NOTES.md:16-18,143-144`).
- Warm cache matters: all tuning was done warm, and CI primes the page
  cache with a warmup run (`perf.yml:95-97`).
- Absolute seconds only compare within one machine
  (`scripts/bench.sh:23-24`; `PERFORMANCE-NOTES.md:28-30`). The perf
  workflow's budget is a single repo variable (`PERF_MAX_SECONDS`, default
  120 s on `extract --dry-run`, `perf.yml:51,151-162`) and its header says
  to compare runs only when the runner CPU matches.
- Report run-to-run spread and sample size, not a single number — judge a
  comparison by the standard error of the difference, not by σ alone
  (`PERFORMANCE-NOTES.md:158-160`). `scripts/bench.sh` prints
  mean/σ/min/CPU/RSS per variant.

## Git attribution

Commits and PRs use the maintainer's git identity with no AI attribution:
no `Co-Authored-By` trailers naming an assistant or vendor, no "Generated
with" lines, no `--author` or committer overrides. PR review is automated
separately (`.github/workflows/claude-code-review.yml`).

## Skills (informational)

Interactive sessions on the maintainer's machine may have
`rust-best-practices` and `rust-review` skills available. They are personal
installs, not present in CI — nothing in this repo may depend on them.
