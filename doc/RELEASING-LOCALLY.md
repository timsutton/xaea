# Running the release build locally

The Release workflow (`.github/workflows/release.yml`) is a thin wrapper
around GoReleaser (`.goreleaser.yaml`), so the same build runs on a Mac.
A local run is a *snapshot*: it builds every binary and archive into
`dist/` and publishes nothing.

## Prerequisites

```sh
brew install goreleaser zig
cargo install --locked cargo-zigbuild
rustup target add x86_64-apple-darwin aarch64-apple-darwin \
  x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
```

The darwin targets build with plain `cargo build`; the Linux targets are
cross-linked with zig through `cargo-zigbuild`.

## Run it

```sh
goreleaser release --snapshot --clean --skip=publish
ls dist/*.tar.gz   # darwin (universal) + linux amd64 + arm64, and checksums.txt
```

`--snapshot` versions the archives `<version>-SNAPSHOT-<sha>` and skips the
tag requirement; `dist/` is git-ignored.

To build just one platform: `goreleaser build --snapshot --clean --single-target`.

CI pins the compiler (`RUST_VERSION` in the workflows); a local run uses
whatever rustup's active toolchain is, so it's for checking the pipeline,
not for reproducing a published binary.

Local snapshots are unsigned: signing only runs when `MACOS_SIGN_P12` is set.

## Dry-running in CI instead

Actions → Release → Run workflow, with **snapshot** ticked, does the same
thing on a GitHub macOS runner and publishes nothing.

## What a real release adds

Pushing a `vX.Y.Z` tag runs the same config without `--snapshot`, signed and
notarized, and uploads the assets to a draft GitHub Release. A second job then
attests their build provenance, attaches it as
`xaea_<version>_provenance.intoto.jsonl` and publishes the release. If that job
fails, re-run it; the release stays a draft until it succeeds. If the build job
fails after uploading assets, delete the draft before re-running it.

Don't do any of that locally; the header of
`.github/workflows/release.yml` describes how to cut a release.

## Verifying provenance

Any release archive, the checksums file, or an extracted `xaea` binary:

```sh
gh attestation verify xaea_<version>_linux_amd64.tar.gz --repo timsutton/xaea
```

Add `--bundle xaea_<version>_provenance.intoto.jsonl` to check against the
attached bundle instead of fetching the attestation from GitHub.
