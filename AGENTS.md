# AGENTS.md

`xaea` is a Rust CLI to inspect and extract Apple AEA archives as fast as possible, specifically those by which Xcode is distributed.

## Building and testing

It is a standard Rust project:

- `cargo build` to build
- local verifications:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets --locked -- -D warnings`
  - `cargo test --locked`

There's a convention of using a `fixtures` directory to contain .aea files from actual Xcode distributed archives. You can look there if you need to exercise them in your work. Set the `AEA_FIXTURE` env var to a `.aea` file if you need to use it during `cargo test` as well (but they make tests take much longer), adding `--ignored` to the `cargo test` invocation.

## Branching

- Do all work in a dedicated branch. Start new work from the upstream `main` unless the work is explicitly being derived from another work-in-progress branch.
- Isolate work in a git worktree — unless you are already running inside one. If the environment you are running in already provides a worktree (for example, an Orca-managed workspace), treat the current checkout as the isolated worktree: do not create an additional worktree nested inside it.
- Never merge `main` into your work branch. If you need to fix merge conflicts, do it by rebasing on top of the upstream `main`.

## Opening pull requests

Once `fmt`, `clippy`, and `test` pass locally, push a descriptively-named branch and open a PR with `gh pr create --base main`, with `Fixes #N` in the body when the work maps to an issue. Do not wait to be asked.

Opening the PR is the end of your authority:

- Never merge, and never enable auto-merge.
- Never add reviewers, assignees, or labels.
- Never comment on or close issues.
- Never touch repository settings, secrets, or variables.

Other AI agents may add comments on PRs, feel free to address them autonomously.

## Details

- If you need more documentation, find it in the `doc` folder. This will have details about the AEA format as well as past investigations in attempting to improve the performance.

## Benchmarking discipline

- Since the tool is performance-sensitive, if you're going to run any benchmark to compare code, make sure to do it when there isn't other work being done on the machine.

## Documentation

- Don't add additional info to the README, although feel free to correct anything there if relevant to your changes.
- Add a short, 1-2 sentence line to the CHANGELOG.md file if the changes are user-facing. It's ok for the changelog info to be technical in nature, but low-level implementation details needn't be included.
