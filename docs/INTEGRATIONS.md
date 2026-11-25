# Integrations: what exists, and how to connect real test accounts

Nothing in this file is connected yet. AetherProof 0.6.0 has no network client for any payout
provider, bank, wallet or broker. What exists is the decision (`aetherproof.core.gate.decide`),
reconciliation from exported files, and evidence. This page says what each integration needs
and what the founder must provide. No credentials belong in the repository.

## The shape every adapter must have

```
request ──▶ decide(instruction, request, approver_keys, replay, gate_policy) ──▶ allow? ──▶ provider call
                                                                              │
provider webhook / export + bank or chain record ──▶ reconcile ──▶ evidence ◀─┘
```

Rules for any adapter:

1. The provider credential lives only in the adapter's process; application servers never get it.
2. The adapter calls the provider only after `decide(...).allowed` is true, and sets the provider
   reference to the instruction id.
3. Every provider response and webhook is stored as received, for reconciliation.
4. A timeout or unknown status is treated as "may have paid": the approval stays consumed and the
   case goes to reconciliation, never to an automatic retry with a new approval.

## Bank payouts: RazorpayX and Cashfree sandboxes

Founder provides: a sandbox account on each, sandbox API keys, and the sandbox IP or public key
setup the provider requires. Keys go in environment variables on the test machine only.

To build and test (not done):

* an adapter that maps an allowed `PayoutRequest` to the provider's payout create call, with the
  instruction id as the reference, and stores the response;
* a webhook receiver that stores status events and feeds `reconcile_payouts`;
* tests: approved payout succeeds once; changed amount, changed account, replay, expired and
  revoked approvals never reach the provider; a duplicate webhook does not double count.
* Exclusive key custody must be checked on the provider side (keys created only for the adapter,
  dashboard payouts disabled or watched). It cannot be proven from our code alone.

## Crypto: testnet withdrawals

Founder provides: a testnet wallet or a custody sandbox account with testnet funds.

To build and test (not done): destination as `crypto:<network>:<asset>:<address>` (already
supported by the registry), amount and fee in the asset's smallest unit, the chain nonce or the
custodian's idempotency key recorded next to the instruction id, confirmation tracking, and
reconciliation of on-chain transfers against approvals. Comparing with a wallet policy engine is
only meaningful with a real account on that engine.

## Stock orders: broker paper trading

Founder provides: a paper trading account with API access.

To build and test (not done): destination as `stock:<account>:<symbol>:<side>`, quantity and limit
price inside the approval, the broker's own pre-trade limits recorded as the baseline, duplicate
order and cancel handling, and reconciliation of execution reports.

## What can be claimed before these exist

Only what `docs/BENCHMARK.md` and `marketlab/README.md` show: simulated domains, synthetic data,
real AetherProof code on the decision path.
