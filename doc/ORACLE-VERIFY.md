# Oracle-tree verification — extraction fidelity as a routine check

Container-level verification (`inspect --verify`, on by default in
`extract`) proves the bytes are Apple's: MACs, segment checksums, the
signature chain. It does **not** prove the *filesystem* we build from those
bytes is the filesystem Apple's own tooling builds. That is the oracle
check: extract the same archive with Apple's `archiveutil
extractXcodeAEA` (historically `unxip` for `.xip`s) and diff the two trees.
This document is the cold-start procedure, how to read the diff, and the
CI policy decision.

## Prerequisites

- macOS with `/usr/bin/archiveutil extractXcodeAEA` (macOS 26+; measured on
  27.3).
- The fixture `fixtures/Xcode_27.3_beta_2.aea` — not in the repo; the
  download URL is the `AEA_FIXTURE_URL` repo secret. Pin:
  SHA-256 `1d685d5c6b843a8ca46d34cf38134b72118af8caf28d9b5cfc0f91df4f2bfe64`
  (same pin CI uses). Check it before trusting anything downstream.
- ~10 GiB free per tree (the payload is 9.71 GiB), and `cargo build
  --release`.

## Procedure

```sh
shasum -a 256 fixtures/Xcode_27.3_beta_2.aea   # must match the pin above
FIXTURE=$PWD/fixtures/Xcode_27.3_beta_2.aea

oracle=$(mktemp -d /tmp/oracle-XXXXXX)         # never extract into the repo
mine=$(mktemp -d /tmp/mine-XXXXXX)

(cd "$oracle" && archiveutil extractXcodeAEA "$FIXTURE")   # ~40 s
target/release/xaea extract "$FIXTURE" "$mine"             # ~10 s

scripts/verify.sh "$mine" "$oracle"            # ~2 min; exit 0 = identical
```

Measured on the fixture above: full compare 1:52, `--fast` 1:17,
`--manifest` ~1 min, `--golden` ~1 min. Use
`scripts/verify.sh --fast "$mine" "$oracle"` for a quick structural pass
(modes, symlinks, empty dirs, path set — no content hashes) before
committing to the full hash. If the two tools ever name the top-level
directory differently, point the script at the inner roots
(`"$mine/Xcode-beta.app" "$oracle/Xcode-beta.app"`).

`verify.sh` compares, for every path in either tree: presence (including
empty directories), entry type, permission bits, symlink targets (the
literal target string), and file content hashes. Exit status: **0**
identical, **1** differences found, **2** usage/environment error — a
missing or empty oracle root is always an error, never a silent pass.

## Reading the output

One summary line, then up to 20 example paths per category:

| category | meaning | likely culprit |
|---|---|---|
| `only-mine` / `only-oracle` | path-set bug — includes an empty dir present in only one tree | record walk, path clamping, dir creation |
| `type-differs` | file vs dir vs link at the same path | record-type dispatch |
| `mode-differs` | permission bits differ | mode application (umask-skip logic, final-pass ordering) |
| `target-differs` | symlink target strings differ | link target storage/clamping |
| `hash-differs` | file contents differ | decode pipeline or write path |

Any non-zero count is a real finding: investigate before merging. A
`hash-differs` on a Mach-O is a correctness bug, full stop — both tools read
the same signed bytes.

## Measured baseline (Xcode 27.3 beta 2, macOS 27.3, 2026-11-20)

`archiveutil extractXcodeAEA` tree vs `xaea extract` tree:

```
mine=167542 oracle=167542 common=167542 only-mine=0 only-oracle=0
type-differs=0 mode-differs=0 target-differs=0 hash-differs=0
```

**Zero differences** across all 167,542 entries — paths, types, modes,
symlink targets and content hashes. (The ~2,000 Mach-O CMS blobs that differ
between the `.aea` and the old `.xip` builds are an artifact-vs-artifact
difference — Apple re-signed for the AEA distribution — not an
xaea-vs-archiveutil one.) So on this fixture there is no "expected to
differ" list; the categories below are what the check deliberately ignores.

## Not compared, by design

- **uid/gid** — `chown` needs root; Apple's own CLI declines to apply them
  unprivileged too (see README).
- **timestamps** — every extraction re-stamps; not part of fidelity.
- **xattrs and APFS compression attributes** (`com.apple.provenance`,
  decmpfs) — Apple's tooling may attach metadata or store files compressed;
  xaea writes plain bytes. Content hashes cover the *logical* bytes either
  way, so this can never masquerade as a `hash-differs`.
- **setuid/setgid/sticky bits** — xaea strips them by policy. Note a
  tooling limit: BSD `stat %Lp` (macOS) reports only the 9 low permission
  bits, GNU `stat %a` reports all 12. Xcode's tree contains no special-bit
  files, so nothing real is hidden on macOS.
- Paths containing tabs or newlines are unsupported (Apple archives contain
  none); `verify.sh` detects and reports them as exit 2 rather than
  silently skipping entries.

## The golden manifest (and the CI decision)

**Can oracle verification run in CI?** Not as a required gate, for two hard
reasons: the fixture lives behind a repo secret, so fork PRs cannot run it
at all (the same constraint `ci.yml` already documents for its fixture job);
and the trees are ~10 GiB each, which does not fit a hosted macOS runner's
free disk — `perf.yml` already treats a *single* full extract as opt-in.

- **(a) macOS CI job invoking `archiveutil` live.** Self-maintaining (no
  golden to regenerate), but needs fixture + two trees ≈ 22 GiB (over
  budget), is the slowest possible check (Apple's tool + double-hashing
  ~20 GiB), and couples CI green to Apple's tooling behavior on whatever
  macOS build the runner happens to run. Rejected.
- **(b) Committed golden manifest keyed on the fixture SHA-256.** A
  manifest of the oracle tree, committed as
  `fixtures/oracle-<sha12>.tsv.xz` (measured: 35.8 MB of text, 2.8 MB xz);
  CI extracts with xaea only (one tree) and diffs with `--golden`.
  Deterministic, reviewable — the expected output is itself version
  controlled — and needs no Apple tooling in CI. Cost: it goes stale when
  the fixture changes and must be regenerated by a human who has the
  fixture and Apple tooling.

**Decision: (b).** It is the only option that fits the runner's disk budget,
and freezing the expected output in a reviewed file is a feature.

**What a human must enable** (one-time, then on each fixture change):

```sh
# on a Mac with the fixture, after producing the oracle tree as above:
scripts/verify.sh --manifest "$oracle" | xz -9e \
  > fixtures/oracle-1d685d5c6b84.tsv.xz     # key = fixture SHA-256, first 12
# commit it. No new secrets: the workflow reuses the existing AEA_FIXTURE_URL.
```

A golden whose key doesn't match the fixture pin is a hard error, never a
silent skip. Until one is committed, the oracle check stays a manual gate —
which is exactly what the PR template's checkbox enforces on every PR that
can change what lands on disk.

**What CI runs today** (`.github/workflows/oracle-verify.yml`):

- `self-test` — every PR, `ubuntu-latest`, no fixture or secrets:
  `scripts/verify-selftest.sh` builds synthetic trees and asserts
  `verify.sh` catches each diff category and exits 2 on empty/missing
  roots. The golden is only as trustworthy as the tool that reads it, so
  the tool is the part that can be a real gate.
- `manifest` — `workflow_dispatch` only, `macos-latest`: builds xaea,
  fetches the fixture (ci.yml's cache pattern), extracts, uploads xaea's
  manifest as an artifact, and diffs against the committed golden if one
  exists. Dispatch-only because of the disk budget; it is the
  regenerate-and-debug button, not a gate.

## Regenerating / extending

`scripts/verify.sh --manifest <root>` prints the canonical manifest
(tab-separated `path/type/mode/digest-or-target`, path-sorted). The
manifest is a pure function of the tree, so two runs on the same tree are
byte-identical — diff two manifests directly if you want to see exactly what
moved between two extractions.
