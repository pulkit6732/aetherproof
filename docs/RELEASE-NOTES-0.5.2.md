# AetherProof 0.5.2 - stability release

[Back to README](../README.md)

Found by testing 0.5.1 under production load and by re-checking every public claim. Measured on Windows 11, Python 3.14.7 and 3.11.9, rustc 1.98.1.

## Fixed
- **Concurrent writers could fail to get a receipt.** With 10 processes signing at once, `issue_receipt` exhausted its 16 retries ("could not reserve a log sequence") because colliding writers retried immediately and collided again. In strict mode this raised; in the default mode `auto.sign` returned `None` and the receipt was silently missing. Writers now back off with capped random jitter, up to 64 attempts. After the fix: 10 x 100 and 16 x 60 concurrent strict signs all succeed with an intact chain; 291 integrity checks during writes, 0 false tamper flags.
- **Rust secure-signer test failed on rustc 1.98.** It read through a pointer taken from a shared borrow after a mutable borrow (undefined behaviour) and saw a stale value. `SecureSigner` now keeps its seed in place (`[u8; 32]` plus a live flag), so the wipe is tested by reading the storage directly; the crate now forbids `unsafe` everywhere, tests included. The test fails if `destroy()` stops zeroizing (checked).
- **Python bindings did not build on Python 3.14** (PyO3 0.24). Upgraded to PyO3 0.26.
- **Native extension version was 0.5.0 inside the 0.5.1 release.** Now equal to the package version, enforced by a test.

## Changed (breaking for the Rust CLI)
- The Rust CLI no longer signs or verifies with the public `DEV_SIGNING_SEED` by default. `generate` needs `--key <32-byte seed file>` and writes `<out>.pub`; `verify` needs `--pubkey <file>`. The demo key is available only with `--demo`, and its output says "DEMO KEY - PROVES NOTHING".

## Claims corrected
- Removed "EU AI Act §13(3)(c) compliant" from the Rust crate, CLI output and metadata (never verified).
- The 128-byte Rust receipt is documented as a legacy format: its hash fields are 64-bit FNV-1a checksums, not cryptographic hashes.
- `CLAIMS.md` no longer says "there is no ML-DSA in this codebase"; it describes the Rust core's experimental, unreviewed ML-DSA-65 slot.
- Package keyword "tamper-proof" -> "tamper-evident".
- README test counts replaced with measured numbers; the Rust/Python benchmark figures are marked as not re-run.
- Removed three empty files committed by accident (`rust/8.0}`, `rust/cannot`, `rust/f64`).

## Unchanged, still true (see CLAIMS.md)
- Deleting the newest log entries is not detectable without an external log head (`full_audit` b4, a known gap).
- `aetherproof.auto` fails open by default: if the receipt cannot be written, it returns `None`. Set `AETHERPROOF_STRICT=1` where a missing receipt must stop the work.

## Test results
- Python: 646 passed, 1 skipped, 93% coverage (native extension built); 573 passed, 3 skipped without it; same on Python 3.11.
- Rust: 59 passed; `cargo fmt --check` and `cargo clippy --workspace --all-targets -D warnings` clean.
- Stress suites: `industrial_stress` 7/7, `isolation_audit` 18/18, `full_audit` 30/31 (the known gap above).
