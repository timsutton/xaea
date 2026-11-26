# Building with Bazel

Install Bazelisk as `bazel` and a native C toolchain (Xcode Command Line Tools
on macOS, or a C compiler and development headers on Linux). Bazelisk selects
the version from `.bazelversion`. Bazel downloads the pinned Rust toolchain
and builds the vendored liblzma with the native C toolchain.

```sh
bazel build //:xaea
bazel-bin/xaea --version
```

Use `bazel build --config=release //:xaea` for an optimized build with the
same fat link-time optimization (LTO) mode as `cargo build --release`. To build
and run in one command, use `bazel run //:xaea -- --help`.

Make dependency changes in `Cargo.toml` and update `Cargo.lock` with Cargo.
Bazel's Crate Universe regenerates the dependency targets from those files and
uses the locked versions and manifest features. A genrule reads the package
version from `Cargo.toml` for `xaea --version`. If you change the Rust edition,
update `BUILD.bazel` to match.

`MODULE.bazel.lock` records Bazel module resolution and the generated crate
targets. CI rejects a stale lockfile. After changing dependencies or updating
Bazel or its rules, run `bazel build //:xaea` and `bazel test //:tests`, then
commit any changes to this file.

## Tests

```sh
bazel test //:tests
```

This runs the unit and CLI integration suites using the checked-in
[synthetic fixtures](../tests/fixtures/README.md). For the multi-gigabyte
Xcode fixture, use the existing Cargo fixture test with `AEA_FIXTURE` and
`--ignored`.

## Remote cache

If a gRPC cache is listening on port 8980 on your machine, enable it with
the `remote_cache` configuration in `.bazelrc`.

```sh
bazel build --config=remote_cache //:xaea
```

This configuration reads cached outputs and uploads results of local builds.

## Remote execution

The `remote_exec` configuration routes actions to the `ubuntu24-04-v2` pool
in Buildbarn's `homelab` instance. Bazel selects Linux Arm64 as both the
execution and target platform, including when the client runs on macOS.
The profile uses the `llvm` module's hermetic toolchain for C compilation
and linking.

```sh
bazel build --config=remote_exec //:xaea
bazel test --config=remote_exec //:tests
```

This profile puts the Linux binary in `bazel-linux-bin` and test logs in
`bazel-linux-testlogs`. To use a different server with the same worker
configuration, override `--remote_cache`, `--remote_executor`, and
`--remote_instance_name` on the command line.
