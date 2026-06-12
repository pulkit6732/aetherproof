# AetherProof — What a Receipt Proves (and What It Does Not)

AetherProof is the **R0 / software-key** tier of the receipt format: an Ed25519
signature, a SHA-256 output binding, and a local hash-chained transparency log.
This document states plainly what that establishes and what it does not, so the
claim can be made in a security review without overstating it. The hardware-rooted
(R1+, TPM / NVIDIA CC), post-quantum, and independently-witnessed-log properties
belong to **Signet** and are explicitly out of scope here.

The honesty rule: a receipt proves things about **signing time** under **one
software key held on the signer's machine**. It does not prove anything about the
inference itself, and it trusts the operator's key custody and clock.

---

## 1. What a receipt PROVES (cryptographically, offline, forever)

| Claim | Mechanism | Where it lives |
|---|---|---|
| This exact output was not modified after signing | `output_hash` (SHA-256 of the output) is inside the signed preimage; `verify --output <file>` recomputes and compares | `core/receipt.py` (`canonical_message`), `verify_output_unmodified`, `cmd_verify --output` |
| The receipt as a whole was not altered after signing | Ed25519 signature over the canonical preimage; any changed field fails verification | `core/verifier.py` (`verify_receipt`) |
| It was signed by the holder of a specific key | Ed25519 verify against that public key; no other input needed | `core/signer.py` (`Verifier.verify`) |
| It can be verified by anyone, offline, with only the receipt + public key | Pure local computation; no network, no vendor SDK, no hardware driver anywhere in the verify path | `verify_receipt`, `verify_receipt_file` |
| A claimed timestamp and log position were fixed at signing | `timestamp_ms`, `log_sequence`, and `log_anchor` are inside the signed preimage | `core/receipt.py` |
| The local transparency log has not been edited, reordered, or had rows deleted | Per-row hash chain over the full receipt body (`prev_hash`/`entry_hash`) plus each receipt's own signed `log_sequence` bound to its slot — detects delete-then-renumber **key-free** (so key rotation never false-flags); signature re-verification with the key is an additional deeper layer | `core/log.py` (`verify_integrity`) |
| A model **identity** was bound to the output | `model_weight_root` (SHA-256 of a model file/dir, or a model name in the wizard) is in the signed preimage | `core/hash.py`, `core/receipt.py` |

---

## 2. What a receipt DOES NOT prove (R0 limits — state these too)

| Not proven | Why | What would close it |
|---|---|---|
| That the named model actually produced this output | There is no inference attestation; AetherProof signs a `(model_id, output)` pair the caller supplies | Hardware/runtime attestation of the inference (Signet R1: TPM / NVIDIA CC) |
| That the model **weights** match (only the model *name* in the wizard) | Easy-mode sets `model_weight_root = SHA-256(model name)`; expert `sign <model_file>` hashes real bytes | Use expert `sign` with the actual model file/dir; measured-load attestation for the strong form |
| That the signing key is held securely | The R0 key is an unencrypted PEM in `~/.aetherproof/` | Hardware-held, non-exportable key (Signet R1: TPM/CC) |
| That the timestamp is truthful | `timestamp_ms` is the signer's own clock, bound but not externally anchored | Anchor ordering to `log_sequence` (done) + an external timestamp authority (RFC 3161) |
| That the log operator is independent | The transparency log is a single local SQLite file run by the signer; tamper-evident but not third-party-witnessed | Independent witness cosigners / published log head (Signet, Sigstore/CT model) |
| That `log_anchor` is a portable inclusion proof | It is the reference string `local://log/<n>`, not yet a Merkle inclusion proof | Merkle tree over the log + signed head (Signet) |
| That the most recent entries were not truncated | The chain detects edits/deletions/reorders *within* the log, but with no published or signed log head, dropping the **tail** (the latest N rows) leaves a shorter self-consistent chain that key-free verification cannot distinguish from "those rows were never written" | A signed/published log head or independent witness (Signet) |
| That rows logged before a chain migration were untouched | The hash chain is computed at migration time; it attests integrity **from migration forward**, not retroactively | A chain built at issuance time from day one (default for any fresh log) |
| That a maximally thorough forger with database write access cannot rewrite the log | Default log verification is key-free and catches deletion, reordering, content edits, and delete-then-renumber; an attacker who also rewrites each receipt's embedded `log_sequence` and recomputes the whole chain is caught **only** by key-bound signature re-verification | Independent witness cosigners / published log head (Signet) removes the single-machine trust assumption entirely |
| That the receipt survives a quantum adversary | Signature is Ed25519 only | Hybrid Ed25519 + ML-DSA-65 (Signet) |

---

## 3. Mapping to the questions a security review asks

| Regulation / control | The question it asks | What AetherProof R0 answers | Residual gap (say it) |
|---|---|---|---|
| SEC 17a-4(f) / FINRA 4511 | Records kept non-rewriteable, non-erasable | Each output has a tamper-evident, hash-chained, signature-bound record; edits/deletions are detectable | Single-operator log; no WORM media or independent retention custody |
| EU AI Act Art. 12 | Automatic, tamper-evident event logs | Append-only hash-chained log with per-entry signatures | No independent witness; operator runs the log |
| FDA PCCP | Deployed model identical to the cleared/validated model | `model_weight_root` binds a model identity hash to every output | Wizard binds a name hash; use a real weight hash; no proof the model *ran* (needs attestation) |
| NYC LL144 / Colorado SB 24-205 | Audited model == model now in production | Continuity via the same `model_weight_root` across receipts | Same weight-hash and inference-attestation gaps |
| FRE 902(14) | Self-authenticating digitally-signed record | Ed25519 signature, verifiable offline by any party | Software key custody (R0); `log_anchor` is local, not yet an inclusion proof |
| HIPAA audit controls | Tamper-evident audit trail of access/decisions | Hash-chained, signature-bound log of each output | Operator-run log; key in software |

---

## 4. The sentence to use in a questionnaire

> "For each AI output, AetherProof produces an Ed25519-signed receipt that binds a
> SHA-256 of the output, a model identity hash, a timestamp, and an append-only
> hash-chained log position. Any modification of the output or the receipt is
> detectable offline by any party using only the receipt and our public key, with
> no dependency on our servers. This is a software-key (R0) implementation; hardware
> key custody, inference attestation, post-quantum signatures, and an
> independently-witnessed log are roadmap items (Signet) and are not claimed here."

Make the claim at the level the code supports. The strongest honest statement is
about **integrity and authentication of the record**, not about the inference.
