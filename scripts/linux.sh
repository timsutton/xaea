#!/usr/bin/env bash
# Work on this checkout inside a Linux container.
#
#   scripts/linux.sh                       # interactive shell
#   scripts/linux.sh cargo test --locked   # run one command
#   AEA_FIXTURE=path/to/x.aea scripts/linux.sh \
#     cargo test --release --locked -- --ignored
#
# Inside the container:
#   /src      this checkout, mounted live
#   /target   cargo's target dir, kept between runs; `xaea` is on PATH after
#             `cargo build --release`
#   /scratch  empty Linux filesystem for extraction output, removed on exit
#   /fixture  the AEA_FIXTURE file, read-only, if set
#
# Set DOCKER_DEFAULT_PLATFORM=linux/amd64 to run x86_64 (emulated, so slower,
# on Apple Silicon).
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
platform=${DOCKER_DEFAULT_PLATFORM:-native}
suffix=${platform##*/}
image=xaea-linux:$suffix
# Per checkout: worktrees sharing a target dir could reuse each other's builds.
target_volume=xaea-target-$suffix-$(printf %s "$repo" | cksum | cut -d' ' -f1)

# The Dockerfile copies nothing in, so it's built without a context. Cached
# after the first run.
docker build --quiet --tag "$image" - <"$repo/scripts/linux.Dockerfile" >/dev/null

args=(--rm --interactive
    --volume "$repo:/src"
    --volume "$target_volume:/target"
    --volume "xaea-cargo-registry:/usr/local/cargo/registry"
    --volume /scratch)
if [[ -t 0 && -t 1 ]]; then
    args+=(--tty)
fi
if [[ -n ${AEA_FIXTURE:-} ]]; then
    [[ -f $AEA_FIXTURE ]] || {
        echo "AEA_FIXTURE is not a file: $AEA_FIXTURE" >&2
        exit 1
    }
    fixture=$(cd "$(dirname "$AEA_FIXTURE")" && pwd)/$(basename "$AEA_FIXTURE")
    inside=/fixture/$(basename "$fixture")
    args+=(--volume "$fixture:$inside:ro" --env "AEA_FIXTURE=$inside")
fi

if (($# == 0)); then
    set -- bash
fi
exec docker run "${args[@]}" "$image" "$@"
