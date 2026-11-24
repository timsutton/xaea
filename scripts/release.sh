#!/usr/bin/env bash
# Release driver, run by .github/workflows/release.yml: install the toolchain
# pieces, verify the tag, extract the release notes, run GoReleaser, then
# verify the macOS signatures on the shipped archives.
#
# Environment:
#   RELEASE_SNAPSHOT   "true" for a dry run (skip the tag check, the signature
#                      check and signing/notarization, and pass --snapshot to
#                      GoReleaser)
#   GITHUB_REF_TYPE    must be "tag" for a real release (workflow-provided)
#   GITHUB_REF_NAME    tag name, e.g. vX.Y.Z (real releases only)
#   RUNNER_TEMP        scratch dir for the release notes (defaults to a temp dir)
#   GITHUB_TOKEN       needed by GoReleaser to create the release
#   MACOS_SIGN_P12     base64 Developer ID .p12 (required for real releases)
#   MACOS_SIGN_PASSWORD, MACOS_NOTARY_ISSUER_ID, MACOS_NOTARY_KEY_ID,
#   MACOS_NOTARY_KEY   notarization secrets (required for real releases)
set -euo pipefail

snapshot="${RELEASE_SNAPSHOT:-false}"

# Toolchain: Homebrew for the binaries, cargo for the crate. GoReleaser,
# cosign and zig are brew formulae; cargo-zigbuild has no tap.
brew install goreleaser cosign zig
cargo install --locked cargo-zigbuild

if [ "$snapshot" != "true" ]; then
  # A real release must be cut from a vX.Y.Z tag that matches the crate
  # version in both Cargo.toml and Cargo.lock; otherwise the binaries would
  # report a different version than the release they're attached to.
  if [ "${GITHUB_REF_TYPE:-}" != "tag" ]; then
    echo "::error::Non-dry-run releases must run from a tag, not '${GITHUB_REF_NAME:-}'"
    exit 1
  fi
  tag_version="${GITHUB_REF_NAME#v}"
  toml_version=$(awk -F'"' '/^version *=/ {print $2; exit}' Cargo.toml)
  lock_version=$(awk -F'"' '/^name = "xaea"$/ {getline; print $2; exit}' Cargo.lock)
  echo "tag=$tag_version Cargo.toml=$toml_version Cargo.lock=$lock_version"
  if [ "$tag_version" != "$toml_version" ] || [ "$tag_version" != "$lock_version" ]; then
    echo "::error::Tag '$GITHUB_REF_NAME' does not match Cargo.toml ($toml_version) / Cargo.lock ($lock_version)"
    exit 1
  fi
fi

version=$(awk -F'"' '/^version *=/ {print $2; exit}' Cargo.toml)
notes_dir="${RUNNER_TEMP:-$(mktemp -d)}"
notes="$notes_dir/release-notes.md"
scripts/release-notes.sh "$version" > "$notes"

args=(release --clean --release-notes="$notes")
if [ "$snapshot" = "true" ]; then
  args+=(--snapshot)
fi
goreleaser "${args[@]}"

# Check what actually shipped in the darwin archives: Developer ID-signed with
# the hardened runtime. Notarization can't be checked offline; GoReleaser waits
# for Apple's verdict and fails the step on rejection. Snapshots ship unsigned
# binaries, so there is nothing to check — skipping avoids a false failure.
if [ "$snapshot" != "true" ]; then
  scripts/verify-macos-signature.sh dist
fi
