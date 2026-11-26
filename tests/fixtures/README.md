# Synthetic AEA fixtures

Regenerate the archives and their JSON manifests together from the repository
root. The generator needs Python 3 and `cryptography`. You can use an existing
environment with `cryptography` installed or create a temporary virtual environment.

```sh
venv_dir=$(mktemp -d)
python3 -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install cryptography
"$venv_dir/bin/python" -I scripts/make_test_aea.py tests/fixtures \
  --seed 1 --evil --links 1200 --tamper
cargo test --locked
```

Commit the generated `.aea` and `.json` files together. The seed fixes the
payload and signing keys, while ECDSA signatures can change on each run.
The certificates have a fixed validity window from January 1, 2000 to
December 31, 2099 UTC because extraction checks them against the current time.

| Cargo integration test | Files in this directory |
| --- | --- |
| `tests/cat.rs`, `tests/stdin.rs` | `archive.aea`, `manifest.json` |
| `tests/e2e.rs` | `archive.aea`, `manifest.json`, `evil1.aea`, `evil2.aea`, `evil3.aea` |
| `tests/exit_codes.rs` | `archive.aea` |
| `tests/link_pass.rs` | `evil1.aea`, `evil2.aea`, `evil3.aea`, `links.aea`, `links-manifest.json` |
| `tests/sig_rejection.rs` | `archive.aea`, `tamper.json`, and its six listed archives |

Cargo tests and CI read these files directly. Real Xcode archives for the
ignored tests in `tests/fixture.rs` live in the repository's top-level
`fixtures/` directory or at the path provided via `AEA_FIXTURE`.
