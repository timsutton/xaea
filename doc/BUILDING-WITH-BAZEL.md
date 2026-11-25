# Building with Bazel

Install Bazelisk and a native C toolchain (Xcode Command Line Tools on macOS,
or a C compiler and development headers on Linux). Bazelisk uses the version
from `.bazelversion`. Bazel downloads the pinned Rust toolchain and builds
the vendored liblzma with the native C toolchain.

```sh
bazelisk build //:xaea
bazel-bin/xaea --version
```

Use `bazelisk build -c opt //:xaea` for an optimized build. To build and run
in one command, use `bazelisk run //:xaea -- --help`.

Make dependency changes in `Cargo.toml` and update `Cargo.lock` with Cargo.
Bazel's Crate Universe regenerates the dependency targets from those files and
uses the locked versions and manifest features. The build reads package
metadata such as the version from `Cargo.toml` as well. If you change the
Rust edition, update `BUILD.bazel` to match.

`MODULE.bazel.lock` records Bazel module resolution and the generated crate
targets. After changing dependencies or updating Bazel or its rules, run
`bazelisk build //:xaea` and commit any changes to this file.

## Remote cache

If a gRPC cache is listening on port 8980 on your machine, enable it with
the `remote-cache` configuration in `.bazelrc`.

```sh
bazelisk build --config=remote-cache //:xaea
```

This configuration reads cached outputs and uploads results of local builds.

## Remote execution

The `remote-exec` configuration uses the Buildbarn `homelab` instance and
routes actions to the `ubuntu24-04-v2` Linux Arm64 worker pool. Run it from a
Linux Arm64 Bazel client with the worker's C toolchain environment. This builds
a Linux Arm64 binary.

```sh
bazelisk build --config=remote-exec //:xaea
```

On macOS, run the client in a Linux Arm64 Docker container with the same
toolchain as the workers. If Buildbarn listens on the Docker Desktop host,
point both endpoints at the host from the container.

```sh
bazelisk build --config=remote-exec \
  --remote_cache=grpc://host.docker.internal:8980 \
  --remote_executor=grpc://host.docker.internal:8980 //:xaea
```
