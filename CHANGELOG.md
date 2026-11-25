# Changelog

## 0.6.0 (unreleased)

### Added
* `core/limits.py`: per payout, daily, per destination and count caps per account, checked and
  spent in one SQLite IMMEDIATE transaction (safe across processes and threads); revocation of
  an approval before use; `verify_with_limits`.
* `core/destinations.py`: destination approval by k of n policy keys that are not the payout
  approver's. Versioned records (an old add cannot undo a revoke), signatures re-checked on
  every lookup, hash chained history. Domain rules for bank (hashed account), crypto (network +
  asset + address) and stock (instrument + allowed sides).
* `core/gate.py`: one `decide()` for the library, the CLI and the API. With `gate_policy.json`
  it adds destination approval and caps; without it behaviour is unchanged.
* CLI: `instruction verify --gate-policy PATH`. API: `/api/v1/verify` applies the gate policy;
  new error code `gate_policy` (503) when the policy exists but is unusable.
* `bench/financial_benchmark.py` and `docs/BENCHMARK.md`: six systems, three simulated domains,
  900 legitimate transactions, 16 attack families, attack matrix, latency p50 / p95 / p99.
* `marketlab/`: simulated exchange used to test the permission gate on orders (research, not in
  the package), with matching engine tests.
* `docs/INTEGRATIONS.md`: what real sandbox, testnet and paper trading tests need.

### Fixed
* SQLite setup could fail with "database is locked" when several processes opened a new
  replay, limits or destination database at the same moment (the WAL switch does not always
  wait for the busy timeout). Setup now retries for up to 30 s (`core/dbutil.py`). Found by the
  8 process race test; affects the 0.5.2 replay store too.
* Local API: a POST refused before its body was read (wrong role, bad token, no route) now
  reads the body first, so Windows clients get the error reply instead of a connection reset.

### Tests
* Python: 948 passed, 0 skipped (`python -m pytest tests/`, Windows, Python 3.14, 26 Nov 2026).
* Rust: 62 passed (`cargo test --release --workspace` in `rust/`).
* MarketLab matching engine: 5 passed.

## 0.5.2 (PyPI, built from 44bd7fa)

Signed payout instructions, fail closed gate, replay store, payout and bank statement
reconciliation, evidence packages, local API and desktop app. See
`docs/RELEASE-NOTES-0.5.2.md`.

Earlier versions: `docs/RELEASE-NOTES-0.5.1.md`, `docs/RELEASE-NOTES-0.4.0.md`.
