# Financial adversarial benchmark

`python bench/financial_benchmark.py` · results in `bench/financial_benchmark_result.txt`
and `.json` · synthetic data only · run 25 Nov 2026 on one Windows laptop.

## What is compared

| System | What it is |
|---|---|
| S1 | Authenticated API: valid key from an allowed IP. What the stolen-credential attacks had |
| S2 | Conventional policy engine, modelled on publicly documented provider controls: per payout and daily caps (atomic), beneficiary allowlist the API credential can extend, 24 hour idempotency keys |
| S2b | Same engine, allowlist locked: it changes only through a separate, uncompromised approval path. The strongest fair version of a conventional engine |
| S3 | AetherProof 0.5.2 gate, real code (`verify_instruction` + `ReplayStore`) |
| S4 | AetherProof gate plus limits and revocation (`core/limits.py`, real code) plus after the fact reconciliation of provider records and the bank statement (`reconcile_payouts`, real code) |

S2 and S2b are **models**, not any vendor's product. No competitor product was run.

Three transaction types: bank payouts (INR), crypto withdrawals (address, network and asset
bound), stock orders (account, symbol and side bound). 300 approved legitimate transactions
per type, including one exactly at the per payout cap and one executed one second before its
approval expires.

## Results

Legitimate transactions wrongly blocked: **0 of 900 for every system.**

Unauthorized actions executed, summed over the three transaction types (count / amount).
Amounts add INR and USD units together, so compare the counts; L = lakh, Cr = crore:

| Attack (real pattern it models) | S1 | S2 | S2b | S3 | S4 |
|---|---|---|---|---|---|
| 01 Stolen API key, new mule account (NBFC API heists, 2026) | 60 / 11.4 L | 60 / 11.4 L | **0** | **0** | **0** |
| 02 Account swapped on an approved loan (Delhi NBFC cases, 2026) | 30 | 30 | **0** | **0** | **0** |
| 03 Amount inflated on an approved payout | 30 | 30 | 30 | **0** | **0** |
| 04 Replay, same idempotency key | 3 | **0** | **0** | **0** | **0** |
| 05 Replay, new request id | 60 | 60 | 60 | **0** | **0** |
| 06 Replay after 48 hours | 60 | 60 | 60 | **0** | **0** |
| 07 Structuring into small payouts (317 transaction case) | 600 | 600 | **0** | **0** | **0** |
| 08 Expired approval | 30 | 30 | 30 | **0** | **0** |
| 09 Revoked approval (loan cancelled) | 30 | 30 | 30 | 30 | **0** |
| 10 Crypto: same address, other network or token | 10 | 10 | **0** | **0** | **0** |
| 11 Stock: side or symbol flipped | 10 | 10 | **0** | **0** | **0** |
| 12 Stolen signing key, burst (Ronin 2022, Knight Capital 2012) | 180 / 3.6 Cr | 32 / 64 L | **0** | 180 / 3.6 Cr | 32 / 64 L |
| 13 Approver tricked into signing (Bybit 2025) | 9 | 9 | **0** | 9 | 5 |

Concurrency: 16 threads sent 160 stolen-key payouts of 2 lakh against an 80 lakh daily cap.
S4 allowed exactly 40 (80 lakh). The cap held. A separate unit test races 8 processes.

After the fact (provider records and bank statement):

| Scenario | S1, S2, S2b, S3 | S4 |
|---|---|---|
| 14 Payout made at the provider dashboard, skipping the gate | not detected | **detected**: paid with no valid signed instruction |
| 15 Provider status forged; hidden bank debit (Bangladesh Bank 2016 pattern) | not detected | **detected**: processed but no bank debit; unexplained debit |
| 16 One insider forges both provider export and statement | not detected | **not detected** |

Latency on legitimate payouts: S3 1.28 ms median (1.74 ms p99); S4 2.69 ms median
(3.62 ms p99), two durable SQLite writes per payout.

## What the results mean

* **Where AetherProof wins against the strongest conventional engine (S2b):** attacks 03, 05,
  06, 08, 09 and after the fact 14, 15. These are all the same kind: the payout differs from
  the exact approval (amount, single use, time, cancellation) or the records disagree with
  what was approved. A caps and allowlist engine does not know the approval, so it cannot
  see them.
* **Where the locked allowlist wins:** 12 and 13. A stolen signing key or a tricked approver
  produces valid signatures; S4 only caps the damage, the locked allowlist stops new
  destinations outright. AetherProof needs a destination rule of its own: the borrower's
  mandate account for lending, a separately signed counterparty list for treasury and
  crypto. Both are on the roadmap, not built.
* **Caveat that favours S2b:** every legitimate destination was pre-allowlisted. In lending
  each loan pays a new account, added by the loan system itself; if that system is the one
  compromised, S2b behaves like S2. For crypto treasuries and trading, with stable
  counterparties, S2b is realistic. Also, real trading allowlists cover instruments, not
  side, so S2b would not stop a side flip in practice.
* **Nobody** detects one insider forging both files consistently (16).

## What would make this independent

* Provider sandboxes: RazorpayX and Cashfree payout sandboxes, gate holding the only keys.
* Crypto testnet: real withdrawals on a test network against a wallet policy engine.
* Paper trading: a broker paper account with its own pre-trade limits as S2b.
* An outside red team writing attacks without seeing the gate code.
* Real lender data under NDA for false block rates.
