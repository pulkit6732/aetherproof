# Financial adversarial benchmark

Run: `python bench/financial_benchmark.py` (needs numpy). Raw output:
`bench/financial_benchmark_result.txt` and `.json`. Every number below is copied from the
run of 25 Nov 2026 18:05 UTC on commit `d118c26` plus the p95 change, one Windows laptop,
Python 3.14, fixed seed `20261125`, fixed clock. **Synthetic data only. No real provider,
bank, exchange, broker or wallet was involved.**

## Systems

| | What it is | Real code or model |
|---|---|---|
| S1 | API key from an allowed IP. What the stolen-credential attacks had | model |
| S2 | Caps (per payout, daily, count; atomic) + beneficiary allowlist the API credential can extend + 24 h idempotency keys | model of publicly documented provider controls |
| S2b | S2 with the allowlist locked: changed only through a separate path. The strongest fair conventional baseline | model |
| S3 | AetherProof 0.5.2 gate: `verify_instruction` + `ReplayStore` | real code |
| S4 | S3 + caps and revocation (`core/limits.py`) + reconciliation of provider records and bank statement (`reconcile_payouts`) | real code |
| S5 | S4 + destination approval by 2 of 2 policy keys that are not the approver's (`core/destinations.py`), through `core/gate.decide`, the function the CLI and API call | real code |

S2 and S2b are not Fireblocks, BitGo, Copper, Razorpay, Cashfree, a bank or a broker. No
vendor product was run. Every system sees the same requests, the same legitimate day first,
and the same caps (`POLICIES` in the script).

## Domains

| | Bank payout | Crypto withdrawal | Stock order |
|---|---|---|---|
| Destination | IFSC + account | network + asset + address | account + instrument + side |
| Bound by the signature (S3 to S5) | amount, currency, destination token, validity window | same; network and asset are inside the destination | same; instrument and side inside the destination |
| Destination policy (S5) | exact account (stored as hash) | exact network + asset + address | account + instrument, allowed sides listed |
| Replay state | durable SQLite, single use per approval | same | same |
| Caps | 2 lakh per payout, 80 lakh and 500 per day, 2 lakh per destination per day | same units | per destination cap = account cap (symbols repeat) |
| Reconciliation | provider export + bank statement (real code) | not modelled (no chain data) | not modelled (no execution reports) |
| Status | simulated | simulated | simulated |

Legitimate traffic: 300 approved transactions per domain (900 total), loan sized amounts,
one exactly at the per payout cap, one executed one second before its approval expires.

## Results

Legitimate transactions wrongly blocked: **0 of 900 for every system.**

Unauthorized actions executed, all three domains together (count). Amounts are in the raw
output; they add INR and USD units, so compare counts.

| # | Attack | S1 | S2 | S2b | S3 | S4 | S5 |
|---|---|---|---|---|---|---|---|
| 01 | Stolen API key, new mule account | 60 | 60 | 0 | 0 | 0 | 0 |
| 02 | Account swapped on an approved loan | 30 | 30 | 0 | 0 | 0 | 0 |
| 02b | Attacker inside the loan system, which feeds the allowlist | 30 | 30 | **30** | 30 | 30 | **0** |
| 03 | Amount inflated on an approved payout | 30 | 30 | **30** | 0 | 0 | 0 |
| 04 | Replay, same idempotency key | 3 | 0 | 0 | 0 | 0 | 0 |
| 05 | Replay, new request id | 60 | 60 | **60** | 0 | 0 | 0 |
| 06 | Replay after 48 hours | 60 | 60 | **60** | 0 | 0 | 0 |
| 07 | Structuring into small payouts | 600 | 600 | 0 | 0 | 0 | 0 |
| 08 | Expired approval | 30 | 30 | **30** | 0 | 0 | 0 |
| 09 | Revoked approval | 30 | 30 | **30** | 30 | 0 | 0 |
| 10 | Crypto: other network or token, same address | 10 | 10 | 0 | 0 | 0 | 0 |
| 11 | Stock: side or symbol flipped | 10 | 10 | 0 | 0 | 0 | 0 |
| 12 | Stolen approver signing key, burst | 180 | 32 | 0 | 180 | **32** | **0** |
| 13 | Approver tricked into signing | 9 | 9 | 0 | 9 | **5** | **0** |

After the fact, from provider records and the bank statement (S4 and S5; the others have no
reconciliation):

| # | Scenario | S4 / S5 |
|---|---|---|
| 14 | Payout made at the provider dashboard, skipping the gate | detected: paid with no valid signed instruction |
| 15 | Provider status forged; a hidden bank debit | detected: processed but no bank debit; unexplained debit |
| 16 | One insider forges provider export and statement consistently | **not detected** |

Concurrency: 16 threads sent 160 stolen-key payouts of 2 lakh against an 80 lakh daily cap
(S4 stores). 40 were allowed, exactly 80 lakh. The cap held. Unit tests also race 8
processes on the caps and 16 threads on destination changes.

## Attack matrix

| # | Pattern it is modelled on | Objective | Attacker has | Expected of a sound gate | Result | Limitation |
|---|---|---|---|---|---|---|
| 01 | NBFC payout API thefts, India 2026 (press; CERT-In advisory as summarised) | pay mules | provider API key, allowed IP | refuse: no approval | S2b to S5 refuse | S2 refuses only if the key cannot add beneficiaries |
| 02 | Delhi NCR cases 2026: account swapped on approved loans | redirect approved loans | API key | refuse: destination differs from approval | S2b to S5 refuse | S2b only because the mule is not on its list |
| 02b | Same cases: attacker inside the loan system | get the mule approved | loan system and approver key | refuse: destination not approved by policy keys | only S5 refuses | S5 fails if the policy keys are also stolen |
| 03 | Altered payment instructions (BEC, insider) | pay more than approved | API key, real approval | refuse: amount differs | S3 to S5 refuse | |
| 04 | Retried call | pay twice | the same request | refuse | S2 to S5 refuse | |
| 05 | Replayed approval with a new request id | pay twice | old approval | refuse: approval used | S3 to S5 refuse | |
| 06 | Approval reused days later | pay again | old approval | refuse | S3 to S5 refuse | |
| 07 | Delhi case: 317 transactions, Rs 12.84 crore (ThePrint) | stay under per payout limits | API key | refuse unapproved | S2b to S5 refuse | |
| 08 | Approval used after its window | pay late | expired approval | refuse | S3 to S5 refuse | |
| 09 | Loan cancelled after approval | pay a cancelled loan | unused approval | refuse: revoked | S4, S5 refuse | revocation must be recorded in time |
| 10 | Wrong network or token for the same address | redirect a withdrawal | approval | refuse | S2b to S5 refuse | |
| 11 | Compromised trading agent | flip side or symbol | approval | refuse | S2b to S5 refuse | S2b only because side is in its list key; real allowlists usually list instruments, not side |
| 12 | Ronin 2022 (stolen keys), Knight Capital 2012 (runaway orders) | drain with valid signatures | approver signing key | refuse new destinations | S2b, S5 refuse; S4 caps at 32 | S5 fails if policy keys are stolen too |
| 13 | Bybit 2025: signers approved a misrepresented payload | get a signer to sign a mule payout | approver's signature | refuse: destination not approved | S2b, S5 refuse; S4 caps | S5 fails if the mule was approved as a destination earlier |
| 14 | Payout at the provider dashboard | skip the gate | dashboard access | detect afterwards | S4, S5 detect | detection, not prevention |
| 15 | Bangladesh Bank 2016: records altered to hide transfers | hide a transfer | provider record access | detect afterwards | S4, S5 detect | needs the bank statement |
| 16 | Insider controls both files | hide a transfer | provider export and statement | detect | **nobody detects** | needs an independent evidence source |

## What it shows, and what it does not

* Against the strongest conventional baseline (S2b), AetherProof's advantage is everything
  tied to the exact approval: amount (03), single use (05, 06), time (08), revocation (09),
  approval of destinations by keys the loan system does not hold (02b), and after the fact
  detection (14, 15).
* S2b matches S5 on 01, 02, 07, 10, 11, 12, 13 only because every legitimate destination was
  on its list in advance. In lending each loan pays a new account added by the loan system;
  02b is that case, and there S2b lets all 30 through.
* S5 needs the policy keys to be held apart from the approver and the loan system. If an
  attacker holds k policy keys, S5 is no better than S4.
* 16 is not solved. Integrity of records is proven; their authenticity and completeness are
  not, without an independent source (for example a bank feed the insider cannot edit).

## Latency on the 900 legitimate transactions

| | median | p95 | p99 | What one decision includes |
|---|---|---|---|---|
| S1, S2, S2b | under 0.002 ms | | | a dictionary lookup and arithmetic; no signature, no disk |
| S3 | 1.285 ms | 1.592 | 1.791 | Ed25519 verify, canonical JSON, one durable SQLite write |
| S4 | 2.617 ms | 3.49 | 3.9 | S3 + an IMMEDIATE SQLite transaction for the caps |
| S5 | 3.197 ms | 3.972 | 5.096 | S4 + registry lookup and 2 Ed25519 verifies of the destination record |

These are not equivalent work: S1 and S2 do no cryptography and no durable writes. The
numbers say the full gate adds about 3 ms per payout on a laptop; they do not compare the
systems' efficiency.

## What would make this independent

* RazorpayX and Cashfree payout sandboxes, with the gate holding the only keys.
* A crypto testnet withdrawal against a real wallet policy engine.
* A broker paper account, using its own pre-trade limits as the baseline.
* An outside red team writing attacks without the gate code.
* Real lender data under NDA, for false block rates.
