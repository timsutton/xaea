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
