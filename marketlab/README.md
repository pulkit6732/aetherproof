# MarketLab prototype (research, not part of the AetherProof package)

One event driven limit order book (price time priority), 265 agents of four kinds
(200 noise traders, 5 market makers, 30 momentum, 30 fundamental), a liquidity shock, a
rogue trading agent, an authorization gate built on AetherProof's Ed25519 signer and
SQLite replay store, and a hash chained event log. Synthetic market. Not calibrated to any
real instrument.

Run from the repository root: `python marketlab/fetch_data.py` (optional, downloads SPY prices; not
stored in the repository), then `python marketlab/run_tests.py` (needs numpy and the aetherproof
package). Matching engine tests: `python -m pytest marketlab/test_marketlab.py`. MarketLab is a
research environment for AetherProof's permission gate, not part of the PyPI package.

## Results, 25 Nov 2026, one Windows laptop

| Test | Result |
|---|---|
| T1 reproducibility | Same seed: identical event chain digest. Different seed: different. 32,852 trades, 1.4 s per 20,000 steps |
| T2 realism (stylized facts) | Simulated, 5 seeds, sampled every 10 steps: excess kurtosis 4.38, lag 1 return autocorrelation -0.152, mean autocorrelation of absolute returns (lags 1 to 10) 0.166. SPY 1 minute within session (7 days): 3.74, 0.025, 0.188. SPY daily (10 years): 14.58, -0.130, 0.334. Gaussian walk: 0.00, 0.00, 0.00 |
| T3 liquidity shock | Market makers withdraw and 8 sellers dump for 600 steps: one side of the book empty in 97% of shock steps (where both sides existed, spread averaged 4.41 ticks against 1.75 before), top 5 depth 267 to 43, drop 62 ticks (1 without the shock), half of the drop recovered 14 steps after the low |
| T4 rogue agent | 600 oversized dumps, 60 wrong account, 24 forged mandate, 29 replayed order ids: all blocked. 91 legitimate orders: 0 wrongly blocked inside the permission window (45 correctly blocked after it expired). Price drop 1 tick with the gate, 1,464 without |
| T5 evidence | 32,652 events; recomputed digest matches; editing one trade is detected |

## What these results do not show

* T2 is a sanity check, not calibration. Fat tails and volatility clustering are present
  and close to SPY's 1 minute values, but the lag 1 autocorrelation is far too negative
  (bid ask bounce), and simulation steps are not mapped to real time.
* T3 recovery is fast because fundamental traders anchor to a fixed value. Real recoveries
  depend on things this model does not have.
* T4 is circular: the attacker breaks exactly the limits the gate checks. In real markets
  these pre-trade checks already exist by law (SEC Rule 15c3-5 in the US, SEBI algo ID
  and broker controls in India). The new part is only the signed mandate and the offline
  verifiable log.
* Not tested: calibration to real order book data (needs paid L2 data), a head to head
  benchmark against ABIDES (not on PyPI; needs a source install), options, FX, crypto,
  cross market contagion, scale beyond a few hundred agents.

## Reproduced 26 Nov 2026

All T1 to T5 numbers above reproduced exactly from this folder (same seeds), 1.0 s per
20,000 steps. Matching engine tests: price priority, time priority, cancels, partial fills,
position and cash conservation, deterministic event log: 5 passed.

## Two attempts to fix the known flaws, both rejected

| Change | Lag 1 autocorrelation | Excess kurtosis | Volatility clustering | Shock recovery |
|---|---|---|---|---|
| Model 1 (kept) | -0.152 | 4.38 | 0.166 | half in 14 steps |
| Market makers quote a smoothed fair price; value traders learn (0.01) | -0.337 | 0.71 | 0.046 | never in the run |
| Value traders learn slowly (0.002), wider band | -0.300 | 1.78 | 0.087 | half in 11 steps |

Both made the market less like SPY's within session minutes (0.025, 3.74, 0.188), so the
model stayed as it was. Fixing bid ask bounce and recovery speed needs a better order
placement model (for example calibrated to real order book data), not parameter tweaks.

## Throughput is not latency

1.0 s per 20,000 steps is simulation throughput on one laptop: about 33,000 simulated trades
per second including agent logic. It says nothing about real exchange latency. The gate's
own decision latency is measured separately in `docs/BENCHMARK.md`. MarketLab has never been
connected to a real exchange or broker.

## Not run

ABIDES was not compared: it is not on PyPI and needs a source install and its own
configuration to make a fair comparison; that is planned, not done.
