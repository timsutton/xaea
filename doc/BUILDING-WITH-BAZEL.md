# Building with Bazel

Install Bazelisk as `bazel` and a native C toolchain (Xcode Command Line Tools
on macOS, or a C compiler and development headers on Linux). Bazelisk selects
the version from `.bazelversion` and invokes it through `tools/bazel`. Bazel
downloads the pinned Rust toolchain and builds the vendored liblzma with the
native C toolchain.

```sh
bazel build //:xaea
bazel-bin/xaea --version
```

Use `bazel build -c opt //:xaea` for an optimized build. To build and run
in one command, use `bazel run //:xaea -- --help`.

Make dependency changes in `Cargo.toml` and update `Cargo.lock` with Cargo.
Bazel's Crate Universe regenerates the dependency targets from those files and
uses the locked versions and manifest features. The build reads package
metadata such as the version from `Cargo.toml` as well. If you change the
Rust edition, update `BUILD.bazel` to match.

`MODULE.bazel.lock` records Bazel module resolution and the generated crate
targets. After changing dependencies or updating Bazel or its rules, run
`bazel build //:xaea` and commit any changes to this file.

## Tests

```sh
bazel test //:tests
```

This runs the unit and CLI integration suites. Bazel supplies Python and
`cryptography` for the synthetic archives. For the multi-gigabyte Xcode
fixture, use the existing Cargo fixture test with `AEA_FIXTURE` and
`--ignored`.

## Remote cache

If a gRPC cache is listening on port 8980 on your machine, enable it with
the `remote_cache` configuration in `.bazelrc`.

```sh
bazel build --config=remote_cache //:xaea
```

This configuration reads cached outputs and uploads results of local builds.

## Remote execution

The `remote_exec` configuration uses the Buildbarn `homelab` instance and
routes actions to the `ubuntu24-04-v2` Linux Arm64 worker pool. Run it from a
Linux Arm64 Bazel client with the worker's C toolchain environment. This builds
a Linux Arm64 binary.

```sh
bazel build --config=remote_exec //:xaea
bazel test --config=remote_exec //:tests
```

On macOS, run the client in a Linux Arm64 Docker container with the same
toolchain as the workers. If Buildbarn listens on the Docker Desktop host,
point both endpoints at the host from the container.

```sh
bazel build --config=remote_exec \
  --remote_cache=grpc://host.docker.internal:8980 \
  --remote_executor=grpc://host.docker.internal:8980 //:xaea
```
