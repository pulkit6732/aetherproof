# AetherProof

**Proof of authority for payouts and other consequential actions.**

The system that approves a payout signs exactly what it approved. The system that
executes it checks that signature before money moves, and each instruction pays once.
Afterwards, provider records and the bank statement are matched back to the signed
instruction. A stolen API credential can still call a payout API, but it cannot create
a valid instruction.

Status: **0.5.2, evaluation build.** Tested on synthetic data only. No production
deployment, no live provider or bank connector, no independent security audit.

**Join the waitlist:** https://aetherproof.vercel.app/

## What it does

| Layer | What it does | Docs |
|---|---|---|
| Signed instructions | The approver signs amount, currency, beneficiary and validity window (Ed25519) | [SIGNED-INSTRUCTION-SPEC.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/SIGNED-INSTRUCTION-SPEC.md) |
| Payment gate | The executor verifies before paying. A replay store makes each instruction pay once, and the gate fails closed | same |
| Payout verification | Provider records (RazorpayX shaped, generic CSV/JSON) against instructions: matched, conflict, missing, pending. Payouts with no instruction are flagged | [USER_GUIDE.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/USER_GUIDE.md) |
| Settlement evidence | Bank statement against provider status. A "processed" payout the bank never debited is a conflict | same |
| Evidence packages | A run sealed and signed. An auditor checks it offline with your public key | same |
| Checkpoints and time | Hash-chained log, signed checkpoints, RFC 3161 time stamps | [RECONCILIATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/RECONCILIATION.md) |
| Action reconciliation | Automated and agent actions against AWS CloudTrail | same |
| Receipts | Signed, offline verifiable receipts for model output (the original SDK) | [GETTING-STARTED.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/GETTING-STARTED.md) |
| Local API and desktop app | `/api/v1` with roles, lockout, rate limit and a hash-chained audit log | [API_CONTRACT.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/API_CONTRACT.md) |

## Install

```bash
git clone https://github.com/pulkit6732/aetherproof
cd aetherproof
pip install -e ".[timestamp]"
```

`pip install aetherproof` currently installs 0.5.1 from PyPI, which has receipts only.

## Quick start

```bash
# approver: sign what was approved
aetherproof instruction sign --amount 48500.00 --currency INR --beneficiary-token fa_123 \
    --reference LN-1041 --approval-ref SAN-7701 --approved-by credit-ops

# executor: check before paying (exit 0 = allow, 1 = reject)
aetherproof instruction verify ~/.aetherproof/instructions/<id>.json \
    --amount 48500.00 --currency INR --beneficiary-token fa_123

# afterwards: provider export and bank statement against the instructions
aetherproof payouts reconcile payouts.json --instructions ~/.aetherproof/instructions \
    --source razorpayx --statement statement.csv

# auditor: offline tamper check of a signed evidence package
aetherproof evidence verify run.evidence.json --pubkey signing_key.pub

# local API for the desktop app
aetherproof serve
```

The [user guide](https://github.com/pulkit6732/aetherproof/blob/main/docs/USER_GUIDE.md) covers the three minute demo, the daily workflow,
file formats and how an auditor checks evidence.

## Desktop app

`app/` is a desktop client for the local API, built with
[Rune](https://github.com/anomalyco/rune). Screens: Overview, Instructions, Payment gate,
Payouts, Transaction investigation, Evidence, Integrations, Settings and security.

Rune is pre release, so the app builds against a local checkout placed next to this
repository, at `../vendor/rune` from the repository root, pinned to rev `ba5e7c80`.
Then run `aetherproof serve` and `cargo run --release` in `app/`. Every screen also
renders headless: `aetherproof-app --scene payouts --snap payouts.png`.

![Payouts screen](https://raw.githubusercontent.com/pulkit6732/aetherproof/main/app/snaps/payouts.png)

## Receipts

The receipt SDK signs a prompt and output pair so anyone can later check that the
record was not changed.

```python
from aetherproof.auto import sign

sign(prompt=user_prompt, output=out, model_id=resp.model)
```

It never blocks your program. On failure it returns `None`; set `AETHERPROOF_STRICT=1`
to make a missing receipt an error. Decorator and session forms are in
[INTEGRATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/INTEGRATION.md).

Verification needs one dependency (`cryptography`), no network and no account. The
complete offline verifier, tested on every commit, is in
[VERIFICATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/VERIFICATION.md).

## What it proves

| Claim | Mechanism |
|---|---|
| The payout matched what was approved | Signed instruction checked at the gate |
| An instruction paid at most once | Replay store at the gate, fail closed |
| The provider's record agrees with the bank | Statement match in settlement evidence |
| Evidence was not altered after sealing | Signed evidence package, offline verify |
| The local log was not edited, reordered or cut in the middle | Hash chain plus signed checkpoints |

## What it does not prove

Read this before quoting anything above. Full list: [CLAIMS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/CLAIMS.md).

| Not proven | Why |
|---|---|
| Payouts that bypass the gate | The gate only protects payouts routed through it; a direct provider API call skips it |
| Business facts behind an approval | A signature proves who approved, not that the approval was right |
| Authentic bank data | Statements are imported files, not authenticated feeds |
| Safety against a stolen signing key | Whoever holds the key can sign valid instructions |
| Safety against one insider forging both files | Provider export and statement forged together stay consistent |
| That every event was logged | Integrity, not completeness; that needs an independent witness |
| That a named model produced an output | A receipt signs the model and output pair you supply |

## Two implementations

| | Python, `aetherproof/` | Rust, `rust/` |
|---|---|---|
| Signatures | Ed25519 | Ed25519, plus ML-DSA-65 (FIPS 204) in the Rust core |
| Secret wiping, constant time compare | no | yes |
| Distribution | PyPI | source and CI wheels |

The Rust core is optional. The Python package does not import it, which CI enforces.
The 128 byte Rust receipt is a legacy format whose hash fields are 64 bit FNV-1a
checksums, not cryptographic hashes; see [CLAIMS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/CLAIMS.md).

## Tests

Local results on Windows, synthetic data only, not production accuracy:

* Python suite, 18 Nov 2026: 900 passed, 0 skipped (`python -m pytest tests/`)
* Rust core, 18 Nov 2026: 62 passed (`cargo test --release --workspace` in `rust/`)
* Attack lab, 12 Nov 2026, 100k payouts: 0 of 94,400 clean payouts flagged; forged
  "processed" status caught 500 of 500 with the statement (`python bench/attack_lab.py 100000`)
* Unknown attack fuzz, 12 Nov 2026: 0 fail open in 60,000 mutated cases
  (`python bench/unknown_attacks.py 60000`)

Rerun them before quoting.

## Documentation

| | |
|---|---|
| [USER_GUIDE.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/USER_GUIDE.md) | install, demo, workflow, file formats |
| [SIGNED-INSTRUCTION-SPEC.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/SIGNED-INSTRUCTION-SPEC.md) | instruction format, gate, payout checks |
| [API_CONTRACT.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/API_CONTRACT.md) | local API `/api/v1` |
| [RECONCILIATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/RECONCILIATION.md) | CloudTrail, checkpoints, RFC 3161 time |
| [CLAIMS.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/CLAIMS.md) | what this proves and what it does not |
| [VERIFICATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/VERIFICATION.md) | the offline receipt verifier |
| [INTEGRATION.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/INTEGRATION.md) | receipt integration paths |
| [SECURITY.md](https://github.com/pulkit6732/aetherproof/blob/main/SECURITY.md) | reporting a vulnerability, threat model |
| [ROADMAP.md](https://github.com/pulkit6732/aetherproof/blob/main/docs/ROADMAP.md) | what is planned |
| [CONTRIBUTING.md](https://github.com/pulkit6732/aetherproof/blob/main/CONTRIBUTING.md) | how to contribute |

## License

Apache-2.0. Versions up to 0.2.2 were AGPL-3.0-or-later.

Security issues: see [SECURITY.md](https://github.com/pulkit6732/aetherproof/blob/main/SECURITY.md). Please do not open a public issue.
