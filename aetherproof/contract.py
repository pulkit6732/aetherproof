"""The one contract every layer shares: verdicts, gate decisions, error codes, version.

The API, the CLI, the Rune app and any future Rust core use these names and nothing else.
Changing a meaning here is a contract version bump (see docs/API_CONTRACT.md).
"""

CONTRACT_VERSION = "1"

# Largest amount accepted anywhere, in minor units: 10^15 paise = Rs 10 lakh crore. Far above
# any single payout, and far below 2^63, so every amount fits the app's 64-bit integers
# exactly (QA I10/I11/I35: unbounded amounts were signed, and shown as 0 by the app).
MAX_AMOUNT_MINOR = 10**15

# Outcome verdicts (core/payouts.py, core/reconcile.py)
MATCHED = "matched"      # required evidence agrees with the signed authorisation
CONFLICT = "conflict"    # a defined contradiction or hard policy violation is established
MISSING = "missing"      # an expected outcome is absent after its deadline, or it failed/reversed
AMBIGUOUS = "ambiguous"  # evidence incomplete, delayed or not yet decidable; never treated as fraud
VERDICTS = (MATCHED, CONFLICT, MISSING, AMBIGUOUS)

# Gate decisions (core/instruction.py)
ALLOW = "allow"          # authorised, unchanged, inside its window, first use: consumed
REJECT = "reject"        # a hard check failed; not consumed
REVIEW = "review"        # every hard check passed but the payout cannot be tied back to the
                         # instruction (no provider reference): a person decides; not consumed
DECISIONS = (ALLOW, REJECT, REVIEW)

# Stable API error codes: clients branch on these, never on message text.
ERRORS = {
    "invalid_request": 400,
    "missing_field": 400,
    "invalid_amount": 400,
    "invalid_currency": 400,
    "invalid_beneficiary": 400,
    "invalid_window": 400,
    "unknown_source": 400,
    "unreadable_input": 400,
    "unauthenticated": 401,
    "forbidden": 403,
    "bad_host": 403,
    "not_found": 404,
    "unknown_instruction": 404,
    "unknown_run": 404,
    "too_large": 413,
    "rate_limited": 429,
    "locked_out": 429,
    "internal": 500,
    "gate_policy": 503,
}
