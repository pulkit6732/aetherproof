[Back to the AetherProof README](../README.md)

# 0.5.1

**Pulkit Kr Srivastava | Apache-2.0**

0.5.0 shipped to PyPI with three defects. This release corrects them and adds the
tests that would have caught each one. Nothing about the receipt format, the
signing preimage, or the verifier changed, so **every receipt issued by any earlier
version still verifies unchanged**.

## Fixed

**`__version__` reported the wrong number.** 0.5.0 went out with `pyproject.toml`
at 0.5.0 and `aetherproof/__init__.py` still at 0.4.0, so anyone asking the package
its own version got 0.4.0. PyPI versions are immutable, so that artifact cannot be
corrected in place; 0.5.1 is the fix. `tests/test_version_consistency.py` now holds
the two in agreement.

**Three tests only worked on Windows.** `tests/test_auto.py` used
`"Z:/definitely/not/a/real/path"` as a directory that could not be created. On
Windows `Z:` is an unmapped drive, so creation failed and the assertions held. On
Linux and macOS `Z:` is a legal relative directory name: `mkdir` created it, signing
succeeded, and three tests asserting failure were simply wrong.

That single assumption is why continuous integration was green on Windows and red
on Linux and macOS across 3.9, 3.11 and 3.13 alike. It was never a Python version
problem and never an environment problem.

The replacement is a path underneath a regular file, which cannot be created on any
operating system: POSIX raises `NotADirectoryError`, Windows raises
`FileExistsError`. Nothing can exist beneath a file.

**Markdown tables were collapsed onto single lines** in ten documents, including
the README, `SECURITY.md` and `docs/ROADMAP.md`. A cleanup pass that replaced
typographic characters with ASCII used a pattern that also matched newlines, so
every table row after a bold marker was joined to the one before it. The affected
files are restored and the offending rule is gone.

## Removed

**The wheel workflow.** It was written, committed, and never produced a single
green run: `maturin` exited 1 on the Windows targets and the aarch64 cross-build
failed inside Docker. A workflow that has never worked should not sit in the tree
looking like infrastructure, so it is gone until it can be developed against real
runs. The Windows wheel still builds correctly by hand:

```bash
cd rust/py && python -m maturin build --release
pip install ../target/wheels/aetherproof_native-*.whl
```

**A `continue-on-error` marker on the Linux and macOS jobs.** That was added while
the cause of the failures was unknown, and it was a workaround rather than a fix.
With the actual cause found, every platform is required again.

**Three zero-byte files** committed by accident: `$(grep`, `$(wc` and `cannot`,
all shell redirect artifacts.

## Verified

| | |
|---|---|
| Python | 645 passed, 1 skipped |
| Rust | 59 passed |
| clippy `-D warnings` | 0 errors |
| `cargo fmt --check` | clean |
| Adversarial probe | 0 panics, 0 fail-open paths |
| Fuzz campaign | 0 panics, 0 forgeries across 350,000 inputs |
| Security audit | pass |

## What 0.5.0 brought, for anyone arriving here first

The Rust core was restored to the tree and is no longer a dead branch. It carries
the 128-byte fixed-width receipt format, wire-compatible with the AetherOS kernel,
along with an RFC 6962 Merkle session tree proven byte-identical to the Python
implementation by pinned vectors.

A security layer keeps signing keys inside Rust, wiped in place on release. A
Python `bytes` object holding a key cannot be wiped by its owner, and garbage
collection does not overwrite the allocation, so a key handled that way stays
readable in the heap and in any core dump afterwards.

ML-DSA-65 (FIPS 204) is available as a second signature slot alongside Ed25519,
opt-in and Rust-only. A hybrid receipt is 3,453 bytes against 128, and signing
costs 42 times as much, so it is not a default.

PyO3 bindings expose the primitives and the security layer to Python. The package
does not import the extension and behaves identically without it, which continuous
integration checks rather than assumes.

Full detail in [docs/ROADMAP.md](ROADMAP.md); the honest assessment, including what
remains unverified, in [docs/ANALYSIS.md](ANALYSIS.md).

## Install

```bash
pip install --upgrade aetherproof
```
