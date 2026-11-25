# xaea

xaea is a CLI that can extract the Xcode app from an [AEA archive](https://theapplewiki.com/wiki/Apple_Encrypted_Archive) several times faster than the built-in tools on macOS. It's written in Rust and runs on both macOS and Linux.

Apple will distribute Xcode on [developer.apple.com](https://developer.apple.com/download/more/) exclusively as an AEA archive [after the release of Xcode 27.3](https://developer.apple.com/documentation/xcode-release-notes/xcode-27_3-release-notes#Xcode-AEA).

This project is inspired by Saagar Jha's [unxip](https://github.com/saagarjha/unxip), and aims to make its LZMA decoding and file-writing tasks as performant as possible, while keeping the space-saving benefits of APFS compression (on macOS) and file integrity features of the AEA format.

**Note:** This tool is very new and not widely tested, its code is written nearly entirely by LLMs, and its command-line interface / behavior may change prior to its 1.0 release.

## Installation

### Homebrew

On macOS, install a prebuilt binary:

```sh
brew install --cask timsutton/formulae/xaea
```

On Linux, you'll need to build from source, at least for now:
```sh
brew install --formula timsutton/formulae/xaea
```

### Manually

Prebuilt macOS and Linux binaries can be downloaded directly from [GitHub
releases](https://github.com/timsutton/xaea/releases/latest).

### Build from source

`xaea` is a standard Rust build: `cargo install --path .` will install the release-optimized binary into your `~/.cargo/bin` directory.

## Usage

Run `xaea -h` for full usage instructions, but here are some examples:

```sh
# Extract into the current directory
xaea extract Xcode_27.3_beta_2.aea

# ...or into a given directory
xaea extract Xcode_27.3_beta_2.aea /Applications

# Inspect + fully verify (MACs, checksums, signature chain)
xaea inspect Xcode_27.3_beta_2.aea --verify

# Dump a single file from the archive to stdout
xaea cat Xcode_27.3_beta_2.aea Xcode-beta.app/Contents/Info.plist | plutil -p -
```

## Benchmarks

Xcode 27.3 beta 2 archive (2.03 GiB compressed → 9.71 GiB payload,
30,082 dirs / 126,205 files / 11,254 links), Macbook Pro M4 Max (16 cores / 128 GB RAM), benchmarks performed 5 times after warmup:

| tool | mean duration | usage on disk |
|---|---|---|
| xaea (defaults: use APFS compression, lzma-turbo decoder) | 9.1 s | 3.86 GiB |
| xaea `--no-compress` | 5.3 s | 9.99 GiB |
| Apple's `archiveutil extractXcodeAEA` | 37.5 s | 3.86 GiB |

**TL;DR**, on this particular M4 Max system, `xaea` gives the same result in roughly 1/4 of the time.

The `--no-compress` option is by far the fastest extraction method, but at the cost of more disk space usage as it will skip the system's file compression support during extraction.

## More details

On macOS, [Apple's `libcompression` framework](https://developer.apple.com/documentation/compression/compression_lzma) can be used instead of the default [`lzma-turbo`](https://crates.io/crates/lzma-turbo/) by passing `--decoder=libcompression`.

AEA is also used by Apple to distribute other material, such as restore images. Extracting these is outside of the scope of the tool for now. See the [ipsw](https://github.com/blacktop/ipsw) tool. The format used for the Xcode image distribution uses AEA for its signing/integrity features, not for encryption.

## Documentation

The format was reverse-engineered against a real Apple artifact and documented (including four errata in the public spec) in [FORMAT-NOTES.md](doc/FORMAT-NOTES.md). The measured history behind the benchmarks — architecture rationale, tuning data, rejected experiments — is in [PERFORMANCE-NOTES.md](doc/PERFORMANCE-NOTES.md). Exit codes are a stability contract scripts can branch on; the full table is in [ERROR-CODES.md](doc/ERROR-CODES.md). More details on file verification/fidelity features in [VERIFICATION.md](doc/VERIFICATION.md).

## Acknowledgments

* [saagarjha/unxip](https://github.com/saagarjha/unxip) — the inspiration for this tool, it proved that extracting Xcode distributions could be several times faster than Apple's own tooling and in attempting to push the limits against APFS.
* [kinnay/AEA repo's FORMAT.md](https://github.com/kinnay/AEA/blob/main/FORMAT.md) — the starting
  point for the envelope layout; the errata found against Apple's real artifact are documented in doc/FORMAT-NOTES.md.
* [Apple Encrypted Archive on The Apple Wiki](https://theapplewiki.com/wiki/Apple_Encrypted_Archive) - Another detailed description of the AEA format.
