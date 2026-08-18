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

## 2a. Integrity vs completeness — the limit that matters most

Every claim in §1 is an **integrity** claim: *what is in the log is authentic,
ordered, and unmodified.* That is a different statement from the one an auditor,
a regulator, or an opposing lawyer actually asks:

> *"Show me the record of this decision."* → **integrity.** AetherProof answers this.
> *"Show me that you logged* ***all*** *the decisions."* → **completeness.** Nothing here answers this.

The gap is not academic, and it is not closed by anything in this repository.

**A deployer who logs 9,000 of 10,000 inferences — omitting the 1,000 that would
embarrass them — passes every check in §1.** The log is perfectly append-only.
Every signature verifies. Every hash chains. The record is cryptographically
sound and evidentially worthless, because the omitted rows were never written and
nothing in a self-operated log can attest to what is absent.

This is why the tail-truncation row in §2 is the most important line in that
table rather than a footnote. It is the same problem in its simplest form: a
shorter self-consistent chain is indistinguishable from a chain that was always
that length.

**Why this cannot be fixed locally.** Detecting an omission requires comparing
the log against something the log's operator does not control. Any purely local
mechanism is computed by the same party who chose what to record, so it inherits
that choice. Closing it requires an independent party — a witness who retains
signed log heads, or an exogenous record (a provider's usage report) to reconcile
against. Both are out of scope here and belong to Signet.

**What to say when asked.** Not *"our logs are complete"* — that is unprovable
with this tool. Say: *"every record we produce is tamper-evident and offline
verifiable by you, without trusting our servers. We do not claim, and no
single-operator log can claim, that no record was withheld; that requires an
independent witness, which is a separate layer."*

Stating this unprompted is stronger than being caught by it. A reviewer who finds
the gap themselves discounts everything else in the document.

---

## 3. Mapping to the questions a security review asks

**Read this table with §2a in mind.** Every row answers an *integrity* question.
No row answers a *completeness* question, and several of these regulations are
ultimately asking a completeness question — so the "residual gap" column is doing
real work and should be quoted alongside the claim, never dropped from it.

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
> no dependency on our servers. This establishes the **integrity** of each record
> we produce; it does not establish that no record was withheld, which no
> single-operator log can establish and which we do not claim. This is a
> software-key (R0) implementation; hardware key custody, inference attestation,
> post-quantum signatures, and an independently-witnessed log are roadmap items
> (Signet) and are not claimed here."

Make the claim at the level the code supports. The strongest honest statement is
about **integrity and authentication of the record** — not about the inference,
and not about the completeness of the set.

---

## 5. Claims to refuse, even when invited

A reviewer or a slide deck will sometimes offer you a stronger sentence than the
code supports. These are the ones to decline:

| Tempting claim | Why it is false | The honest version |
|---|---|---|
| "Cryptographically proves GPT-4o produced this" | No client-side tool can attest a closed cloud model's weights; only the provider could, and none does | "Proves the exact input, the exact output, the model the API *claimed*, and the time — none of it altered" |
| "Post-quantum secure" | Signatures are Ed25519 only. There is no ML-DSA in this codebase | "Ed25519 today; hybrid post-quantum is a Signet roadmap item" |
| "Complete audit trail" | See §2a — completeness is exactly what is not proven | "Tamper-evident record of each output we produce" |
| "Immutable log" | It is a local SQLite file. It is tamper-*evident*, not immutable | "Append-only and tamper-evident; alterations are detectable" |
| "Independently verifiable" *implying a third party vouches* | Anyone can verify the **math** offline, but the log is operator-run | "Verifiable by anyone with the public key; the log itself is not third-party witnessed" |
| "Proves when it happened" | `timestamp_ms` is the signer's own clock | "Binds a claimed time that cannot be changed after signing" |

The pattern in every row: AetherProof proves things about **signing time**, under
**one key**, held by **the signer**. Any claim that reaches past those three
constraints is reaching past the code.
