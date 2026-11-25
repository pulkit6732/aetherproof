# AetherProof

**Transaction assurance prototype: bind an approval to the exact payout, enforce policy before
money moves, and produce evidence anyone can verify offline.**

Status: **0.6.0, prototype.** Tested on synthetic data only. No production deployment, no live
provider, bank, exchange or wallet connection, no independent security audit, no regulatory
certification. Website and early access: https://aetherproof.vercel.app/

## The problem

An API key proves who is calling, not that this exact transaction was approved. In 2026,
lenders in India lost crores through their own payout integrations: attackers inside a lending
server called the payout API with the real keys, from allowed addresses, and swapped borrowers'
accounts for mule accounts. Typical gaps:

* approved ₹50,000, executed ₹5,00,000;
* approved beneficiary, substituted beneficiary;
* an approval replayed, used after expiry, or used after the loan was cancelled;
* a payout made around the gate, at the provider dashboard.

## How it works

```
loan system ──signs──▶ approval (amount, currency, destination, validity window)
                              │
policy authority (k of n keys, not the approver) ──approves──▶ destination registry
                              │
executor ──▶ gate: signature ▸ fields match ▸ destination approved ▸ caps ▸ single use ──▶ provider
                                                                                       │
provider export + bank statement ──▶ reconciliation ──▶ signed evidence package ◀──────┘
```

## Feature status

| Feature | Status | Where |
|---|---|---|
| Ed25519 signed approval: amount, currency, destination, validity window | Implemented and tested | `core/instruction.py` |
| Fail closed gate; refuses changed amount, destination, unknown reference | Implemented and tested | `core/instruction.py` |
| Single use (durable SQLite replay store) | Implemented and tested | `ReplayStore` |
| Caps: per payout, per day, per destination per day, count per day; atomic across processes | Implemented and tested; CLI and API via gate policy | `core/limits.py`, `core/gate.py` |
| Cancelling an approval before use | Implemented and tested (library; no CLI command yet) | `LimitStore.revoke` |
| Destination approval by k of n policy keys, versioned, hash chained history | Implemented and tested; enforced in CLI and API; managed through the library (no CLI command yet) | `core/destinations.py` |
| Domain rules: bank account (hashed), crypto network + asset + address, stock instrument + side | Implemented and tested | `core/destinations.py` |
| Payout reconciliation: RazorpayX shaped and generic CSV / JSON exports | Implemented and tested, from files | `core/payouts.py` |
| Bank statement check: "processed" but never debited; unexplained debits | Implemented and tested, from files | `core/settlement.py` |
| Signed evidence packages, offline verification | Implemented and tested | `core/evidence.py` |
| Hash chained log, signed checkpoints, RFC 3161 time stamps | Implemented and tested | `core/log.py`, `core/anchor.py` |
| Local API `/api/v1` with roles, lockout, rate limit, audit log | Implemented and tested, local only | `server.py` |
| Desktop app | Experimental: needs a separate Rune checkout | `app/` |
| MarketLab simulated exchange | Simulated, research only, not in the package | `marketlab/` |
| Live RazorpayX / Cashfree client; gate holding the only keys | Planned | [INTEGRATIONS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/INTEGRATIONS.md) |
| Shadow mode (watch provider webhooks, alert in minutes), freeze request | Planned | |
| Crypto testnet and broker paper trading adapters | Planned | [INTEGRATIONS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/INTEGRATIONS.md) |
| Cloud KMS / HSM keys, multi instance deployment | Planned | |

## Install

```bash
git clone https://github.com/pulkit6732/aetherproof
cd aetherproof
pip install -e ".[timestamp]"
```

`pip install aetherproof==0.5.2` from PyPI has the gate and reconciliation but not caps,
destinations or the gate policy; those arrive with 0.6.0.

## Quick start

```bash
# approver: sign what was approved
aetherproof instruction sign --amount 48500.00 --currency INR --beneficiary-token fa_123 \
    --reference LN-1041 --approval-ref SAN-7701 --approved-by credit-ops

# executor: check before paying (exit 0 = allow, 1 = reject)
aetherproof instruction verify ~/.aetherproof/instructions/<id>.json \
    --amount 48500.00 --currency INR --beneficiary-token fa_123 --reference <id>

# afterwards: provider export and bank statement against the approvals
aetherproof payouts reconcile payouts.json --instructions ~/.aetherproof/instructions \
    --source razorpayx --statement statement.csv

# auditor: offline tamper check of a signed evidence package
aetherproof evidence verify run.evidence.json --pubkey signing_key.pub

# local API
aetherproof serve
```

## Gate policy: caps and destination approval in the CLI and API

Put `gate_policy.json` in `~/.aetherproof/` (or pass `--gate-policy PATH` to
`instruction verify`). The CLI, the API (`POST /api/v1/verify`) and the library
(`aetherproof.core.gate.decide`) then apply the same rules. Without the file, behaviour is
exactly 0.5.x.

```json
{
  "account": "nbfc-main",
  "limits": {"per_payout_max": "200000.00", "daily_max": "8000000.00", "daily_count_max": 500,
             "per_destination_daily_max": "200000.00", "utc_offset_minutes": 330},
  "destinations": {"policy_pubkeys": ["policy_a.pub", "policy_b.pub"], "required_signers": 2}
}
```

An unusable policy is a refusal, never a quiet fall back: the CLI exits with an error and the
API answers `503 gate_policy`. Destinations are approved with the library:

```python
from aetherproof.core.destinations import DestinationRegistry, make_record, sign_record
rec = make_record(account="nbfc-main", destination="fa_borrower_1041", domain="bank", action="add",
                  version=1, evidence="eNACH UMRN ...")
reg = DestinationRegistry("~/.aetherproof/destinations.db", [policy_a.get_public_key(), policy_b.get_public_key()], 2)
reg.apply(rec, [sign_record(rec, policy_a), sign_record(rec, policy_b)])
```

The policy keys must be held apart from the payout approver and the loan system. That is the
point: a stolen approver key or a tricked approver cannot add a destination.

## Benchmark

Six systems, three simulated domains (bank payouts, crypto withdrawals, stock orders), 900
legitimate transactions and 16 attack families modelled on real incidents. Full method, attack
matrix and caveats: [BENCHMARK.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/BENCHMARK.md). Run of 25 Nov 2026:

* Legitimate transactions wrongly blocked: 0 of 900, every system.
* The full gate (S5) refused every one of the 14 pre-execution attack families; the strongest
  conventional baseline modelled (a locked allowlist with caps) let 6 of them through (amount
  inflated, two replays, expired, revoked, attacker inside the loan system).
* After the fact: payouts that skipped the gate and forged provider status were detected; one
  insider forging both the provider export and the bank statement was **not** detected.
* Decision latency, legitimate payouts: 3.2 ms median, 5.1 ms p99 for the full gate (signature
  checks and two durable writes; laptop).

The conventional systems are models of publicly documented controls, not vendor products.

## MarketLab

A simulated exchange (price time priority, 265 agents, liquidity shock, rogue bot) used to test
the permission gate on trading orders. Reproduced 26 Nov 2026: same seed gives the same event
log fingerprint; the gate blocked all 713 rule breaking orders with 0 legitimate orders wrongly
blocked; in a liquidity shock one side of the book was empty in 97% of steps. Its price dynamics are only
partly realistic. Details and the two failed attempts to improve them:
[marketlab/README.md](https://github.com/pulkit6732/aetherproof/blob/main/marketlab/README.md). Simulation only; never connected to an exchange.

## Security model and limits

Read [CLAIMS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/CLAIMS.md) before quoting anything.

| Not covered | Why |
|---|---|
| Payouts that skip the gate | Until the gate holds the only provider keys, a call from elsewhere is not checked; reconciliation detects it afterwards |
| Stolen policy keys | Whoever holds k policy keys can approve a destination |
| Stolen approver key alone | Covered only with destination approval enabled; otherwise caps limit the damage |
| A fully fake borrower | If the attacker creates the borrower and gets the destination approved, the gate cannot tell |
| One insider forging both provider export and bank statement | Two consistent forged files stay consistent; needs an independent evidence source |
| Authentic bank data | Statements are imported files, not authenticated feeds |
| That every event was logged | The log proves integrity, not completeness |

Report vulnerabilities as described in [SECURITY.md](https://github.com/pulkit6732/aetherproof/blob/main/SECURITY.md).

## Python and Rust

The Python package is self contained. The optional Rust core (`rust/`) adds ML-DSA-65 (FIPS
204), secret wiping and constant time compares; the package does not import it, which CI
enforces. Its 128 byte receipt is a legacy format with 64 bit FNV-1a fields; see CLAIMS.md.

## Tests and reproducibility

Run on 26 Nov 2026, Windows, Python 3.14: `python -m pytest tests/` and the Rust suite in
`rust/` (`cargo test --release --workspace`). Counts for this release are in
[CHANGELOG.md](https://github.com/pulkit6732/aetherproof/blob/main/CHANGELOG.md). CI runs the Python suite on Linux, macOS and Windows with
Python 3.9, 3.11 and 3.13. Benchmark: `python bench/financial_benchmark.py`. MarketLab:
`python marketlab/run_tests.py`.

## Also in this repository

* **Receipts**, the original SDK: signed records of a prompt and output pair, verified offline
  ([GETTING-STARTED.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/GETTING-STARTED.md)).
* **Action reconciliation** against AWS CloudTrail ([RECONCILIATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/RECONCILIATION.md)).

## Documentation

[USER_GUIDE](https://github.com/pulkit6732/aetherproof/blob/main/docs/USER_GUIDE.md) · [SIGNED-INSTRUCTION-SPEC](https://github.com/pulkit6732/aetherproof/blob/main/docs/SIGNED-INSTRUCTION-SPEC.md) ·
[API_CONTRACT](https://github.com/pulkit6732/aetherproof/blob/main/docs/API_CONTRACT.md) · [BENCHMARK](https://github.com/pulkit6732/aetherproof/blob/main/docs/BENCHMARK.md) ·
[INTEGRATIONS](https://github.com/pulkit6732/aetherproof/blob/main/docs/INTEGRATIONS.md) · [CLAIMS](https://github.com/pulkit6732/aetherproof/blob/main/docs/CLAIMS.md) · [ROADMAP](https://github.com/pulkit6732/aetherproof/blob/main/docs/ROADMAP.md) ·
[CHANGELOG](https://github.com/pulkit6732/aetherproof/blob/main/CHANGELOG.md) · [SECURITY](https://github.com/pulkit6732/aetherproof/blob/main/SECURITY.md) · [CONTRIBUTING](https://github.com/pulkit6732/aetherproof/blob/main/CONTRIBUTING.md)

## License

Apache-2.0. Versions up to 0.2.2 were AGPL-3.0-or-later.
