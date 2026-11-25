# AetherProof 0.6.0 release notes

Prototype release. Synthetic data only; no live provider, bank, exchange or wallet connection;
no independent security audit.

## What is new

**Destination approval, separate from the payout approver.** A valid payout signature proves
the approver's key signed; it does not prove the key was not stolen or the approver not
deceived. 0.6.0 adds a destination registry (`core/destinations.py`): a destination is usable
only if k of n policy keys, held apart from the approver and the loan system, signed it.
Records are versioned, signatures are re-checked on every lookup, history is hash chained.
Crypto destinations bind network and asset; stock destinations bind instrument and side.

**Aggregate caps and cancellation.** Per payout, daily, per destination and count caps per
account, atomic across processes (`core/limits.py`). An approval can be revoked before use.

**One gate for library, CLI and API.** `core/gate.decide` applies the same rules everywhere.
Put `gate_policy.json` in the AetherProof home or pass `--gate-policy`. Without it, behaviour
is exactly 0.5.x. A broken policy is a refusal (CLI error, API `503 gate_policy`).

**Benchmark and MarketLab.** `bench/financial_benchmark.py` compares six systems on 900
legitimate transactions and 16 attack families across simulated bank payouts, crypto
withdrawals and stock orders (`docs/BENCHMARK.md`). `marketlab/` is a simulated exchange for
testing the gate on orders; research only, not in the package.

## Fixed

* Opening a new replay, limits or destination database from several processes at once could
  fail with "database is locked". Affects the 0.5.2 replay store. Setup now retries.
* The local API now reads the body of a refused POST before replying (Windows clients got a
  connection reset instead of the error).

## Measured (25 and 26 Nov 2026, Windows laptop, synthetic data)

* Legitimate transactions wrongly blocked: 0 of 900, every system in the benchmark.
* Full gate (S5): refused all 14 attack families that act before payout; the strongest
  conventional model (locked allowlist with caps) let 6 through.
* Not detected by any system: one insider forging both provider export and bank statement.
* Decision latency, full gate: 3.2 ms median, 4.0 ms p95, 5.1 ms p99.
* Tests: 948 Python, 62 Rust, 5 MarketLab matching engine tests, all passing.

## Not in this release

Live provider clients, the gate holding the only provider keys, shadow mode alerts, a CLI for
managing destinations and revocations, crypto testnet and paper trading adapters, KMS / HSM
keys. See `docs/INTEGRATIONS.md` and `docs/ROADMAP.md`.

## Upgrading

`pip install --upgrade aetherproof`. No change is needed for 0.5.x users; the new checks only
apply when a gate policy file exists. Instruction format and API contract version are unchanged
(one new error code, `gate_policy`).
