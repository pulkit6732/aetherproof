# Security regression tests

Every test in this folder corresponds to a **real bug found during adversarial
stress testing** of AetherProof. They are the highest-value tests in the suite:
each one re-runs an attack that must stay blocked. If any of these fail, receipts
can be forged or a tamper can go undetected.

## What was found and fixed

| Bug | Severity | What it was | Fix | Test file |
|-----|----------|-------------|-----|-----------|
| **A** | 🔴 Critical | Signing preimage used `"\|".join(fields)`. A `\|` inside any field shifted the boundaries, so two **different** receipts produced the **same** preimage — one signature forged both. | Length-prefix every field as `<len>:<field>` (injective). | `test_preimage_injectivity.py` |
| **B** | 🟡 Medium | `Receipt.from_dict` didn't coerce `timestamp_ms` / `log_sequence`; a JSON string `"1"` stayed a string, diverging from int `1`. Unknown keys also crashed parsing. | Coerce numerics to `int`; ignore unknown keys. | `test_parsing_and_types.py` |
| **C** | 🟡 Latent | `hw_evidence` entered the preimage via `str(list)` (Python repr) — key order / quoting changed it for semantically-equal evidence. | Canonical key-sorted JSON. | `test_preimage_injectivity.py` |
| **D** | 🟠 Med-High | `aetherproof sign` with missing args exited **0**, so `sign && echo ok` falsely passed in CI. | Thread `bool` return → `sys.exit(1)`. | `test_cli_contract.py` |

These were found by treating the receipt as an attacker would: crafting two
distinct receipts that collide under the encoding, feeding string-typed numbers,
reordering nested keys, and checking that every failure path exits non-zero.

## Run

```bash
# the security suite only
python -m pytest tests/security -v

# everything
python -m pytest -q
```

A passing run is the evidence: distinct receipts never share a preimage, a stolen
signature never forges a different receipt, and every failure exits non-zero.
