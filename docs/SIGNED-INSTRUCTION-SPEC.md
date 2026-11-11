[Back to the AetherProof README](../README.md)

# Signed payment instructions - draft v0

Status: draft, open for comment. Reference implementation: `aetherproof/core/instruction.py`,
`aetherproof/core/payouts.py`. Format id: `aetherproof.instruction/v0`.

## Why

A payout API authenticates the **caller** (an API key), not the **instruction**. CERT-In
CIAD-2026-0046 and -0058 (Oct-Nov 2026) describe stolen gateway credentials calling NBFC
disbursal APIs directly, skipping sanction, beneficiary and limit checks. This format lets the
system that approved a payment sign exactly what it approved, and the system that executes it
refuse anything else.

## The instruction

```json
{
  "type": "aetherproof.instruction/v0",
  "instruction_id": "ins_9f2c...",        // <= 40 chars: travels as the provider reference
  "originator": "lender-x",
  "amount_minor": 4850000,                // integer minor units, never a float
  "currency": "INR",
  "beneficiary": {"kind": "token", "value": "fa_123"},
  //   or {"kind": "bank", "salt": "<random hex>", "digest": sha256(salt|IFSC|account)}
  "purpose": "loan_disbursal",
  "reference": "LN-2026-1041",            // business reference (loan account)
  "approval_ref": "SAN-7701",             // where the approval lives
  "approved_by": "credit-ops",
  "policy": "disbursal-v3",
  "not_before_ms": 1793000000000,
  "not_after_ms":  1793000900000,
  "signing_key_id": "3f9a1c0e7b2d4a55",   // sha256(public key PEM)[:16]
  "signature": "<Ed25519 hex>"
}
```

Signature: Ed25519 over the canonical JSON of every field except `signature` (sorted keys,
no whitespace, UTF-8; all values are strings or integers, so this is canonical).

## Executor rules (verify before paying)

Reject unless **all** hold, and consume the instruction only when they do:

1. `type` is supported; `signing_key_id` names a key the executor trusts; the signature verifies.
2. `not_before_ms <= now <= not_after_ms`.
3. Request amount and currency equal the instruction's exactly.
4. Request beneficiary matches (`token` equal, or `bank` digest recomputed from IFSC and account).
5. If the request carries a provider reference, it equals `instruction_id`.
6. `instruction_id` has never been consumed (atomic insert into a replay store; durable).

A rejected attempt does not consume the instruction.

## Outcome verification (after paying)

Match provider records to instructions by reference (`instruction_id`):

| Verdict | When |
|---|---|
| matched | exactly one successful payout, same amount, currency and beneficiary, inside the window (60 s clock tolerance) |
| conflict | different amount/beneficiary, paid more than once, instruction not trusted, or **a payout with no valid instruction** |
| missing | payout failed/reversed/rejected, or none after the window |
| ambiguous | payout still queued/processing, or the window is still open |

## Limits

- A `bank` digest stops precomputed tables, not a targeted brute force of a short account space.
- The gate protects only payouts routed through it; outcome verification catches the rest after the fact.
- Key custody is the originator's: a stolen signing key signs valid instructions. Use an HSM/KMS (roadmap).
- Amount parsing in the CLI assumes 2-decimal currencies.
