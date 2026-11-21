<!--
Extraction fidelity is checked against an oracle tree produced by Apple's
own tooling. If this PR can change what lands on disk, run the oracle check
before asking for review — doc/ORACLE-VERIFY.md has the cold-start
procedure (~15 min on a Mac that has the fixture).
-->

## Summary

<!-- What changed and why. Link the issue. -->

## Test plan

- [ ] `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test`
- [ ] **Oracle verification** — `scripts/verify.sh <mine> <oracle>` exits 0 against an
      `archiveutil extractXcodeAEA` tree. **Required** for any change touching
      extraction, decoding, path handling/normalization, permissions/modes, or
      symlink policy — i.e. anything that can change what lands on disk.
- [ ] N/A — this change cannot affect extracted output, because: <!-- e.g. docs,
      CI-only, inspect/reporting-only, a flag that only affects timing -->

<!--
Legitimate N/A: the code path never reaches the writer threads (parser-only
refactors that are covered by --dry-run, docs, benchmarks, release plumbing).
"Not required" is not a legitimate N/A for writer, mode, symlink, or path
clamping changes — those are exactly what the oracle catches and unit tests
don't.
-->

## Notes for review

<!-- Measurements, tradeoffs, follow-ups. Delete if empty. -->
