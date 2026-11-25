# Exit codes

`xaea` follows Unix convention: `0` on success, non-zero on failure, with
distinct codes for the failure classes a script is likely to branch on.

## Stability contract

**These codes are part of `xaea`'s CLI interface.** Scripts may and should
branch on them, so:

* Existing codes are never renumbered, repurposed, or reused. A class that
  today maps to a code keeps that code forever.
* `0` (success), `1` (generic failure) and `2` (usage error) keep their
  conventional meanings.
* Adding a code requires all of: allocating the next free number in the
  8–125 range, adding a row to the table below, adding a test asserting
  that code in `tests/exit_codes.rs`, and announcing it as an `Added`
  entry in the CHANGELOG. Codes are allocated append-only; gaps are never
  backfilled.
* 126–128 and every code ≥128 are **reserved forever** (see below) and
  must never be assigned, no matter how far the table grows.

## Table

| Code | Meaning | Typical cause | Retryable? |
|-----:|---------|---------------|------------|
| 0 | Success | Extract/inspect completed; also `--help` and `--version` | — |
| 1 | Generic failure | Environment or internal failure not tied to the archive: thread spawn or panic, `available_parallelism`, JSON serialization | Depends on cause |
| 2 | Usage error | Unknown subcommand or flag, missing argument (rejected by clap before any work); `--decoder libcompression` on a non-macOS machine; an IPSW given to `decrypt` without a disk image, or with one it does not have; a URL with `--offline` | No — fix the command line |
| 3 | Input archive unreadable | Path does not exist, no read permission, input is a directory, mmap/IO error while reading the input; a URL that cannot be downloaded (network failure, HTTP error, a server without range requests), also mid-`decrypt` | Sometimes — fix permissions or retry after a transient storage or network failure |
| 4 | Archive rejected | The bytes were read but are not a processable archive: bad magic, truncated or malformed envelope, bad geometry, or a valid archive this command cannot handle (an unsupported profile; an encrypted disk-image archive with `extract` or `cat`) | No — re-download the archive |
| 5 | Verification failure | `inspect --verify` found the archive untrustworthy or damaged: content signature, certificate chain, root/cluster/segment MACs, or segment checksums | No — re-download; `--no-verify` is the deliberate override hatch |
| 6 | Extraction failure | The extract, cat or decrypt pipeline failed: output I/O (disk full, unwritable path), top-level entry collision or an existing `decrypt` output file, decode error mid-stream — **and** verification failures detected during `extract` or `decrypt` (see note) | Sometimes — free space, move the colliding entry, retry |
| 7 | Key failure | An encrypted (profile 1) archive was given no key (`decrypt`, `inspect --verify`), a malformed `--key`, a key that fails the root header MAC, a `--key-pem` that cannot be read, is not the key the archive names, or does not unwrap its key, or a key PEM that cannot be fetched from the archive's key URL (or a key URL off Apple's hosts, which is never fetched) | No — supply the right key or PEM |
| 8–125 | Unallocated | Future codes are allocated here, append-only | — |
| 126–128 | Reserved — never used by `xaea` | Shell convention: 126 = found but not executable, 127 = command not found, 128 = the base shells use for signal deaths. Returning these would make a real failure indistinguishable from a shell-level one | — |
| ≥128 | Reserved — never used by `xaea` | 128 + *n* means "killed by signal *n*". `xaea` installs no signal handlers, so Ctrl-C and Ctrl-\ kill it the Unix way and the shell reports 130 and 131 | — |

## Note on the 5/6 split

`inspect --verify` runs verification as a distinct stage, so its failures
get code 5. `extract` folds verification into the streaming decode
pipeline: by the time an error reaches the process boundary it is
indistinguishable (by type, without restructuring the pipeline) from an
output I/O failure, so mid-extract verification failures exit 6 like any
other extract failure. A script that needs to tell "the archive is
tampered/corrupt" from "extraction hit an I/O problem" should run
`inspect --verify` first (5 vs everything else), then `extract`.

## Where codes are assigned

All codes are assigned at the `main` boundary in `src/main.rs`: modules
keep returning `anyhow::Error`, and each call site tags its errors with an
`Exit` class via a wrapper that downcasts the error chain — classification
never inspects message text. `tests/exit_codes.rs` pins every reachable
class to its code.
