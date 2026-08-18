<p align="center">
  <img src="docs/signet-logo.png" alt="Signet" width="240">
</p>

# AetherProof

**Cryptographic receipts for AI output.** Prove a model's output has not been
modified — no server, no account, verifiable offline forever.

```bash
pip install aetherproof
```

> **Not a developer?** Start with the [plain-language guide](docs/GETTING-STARTED.md)
> — first receipt in three steps, no code.

---

## The problem

Somebody acts on an AI's output. Weeks later it is questioned:

> *"Did it really say that, or did you change it afterwards?"*

Today that argument is unwinnable in both directions. You cannot prove you did not
edit a text file, and they cannot prove you did. Screenshots prove nothing. Logs you
control prove nothing, because you control them.

**AetherProof turns that into arithmetic that either checks or does not.**

---

## Use it

### Sign one output

```python
from aetherproof.auto import sign

resp = client.chat.completions.create(model="gpt-4o", messages=[...])
out  = resp.choices[0].message.content

sign(prompt=user_prompt, output=out, model_id=resp.model)
```

That is the whole integration. It never prompts, never blocks. On failure it
returns `None` and your program continues — set `AETHERPROOF_STRICT=1` if a missing
receipt should be an error instead.

### Wrap a function you already have

```python
from aetherproof.auto import receipted

@receipted(model_id="gpt-4o")
def ask(prompt: str) -> str:
    return client.chat.completions.create(...).choices[0].message.content
```

No call sites change.

### A whole conversation, one signature

```python
from aetherproof.auto import AutoSession

with AutoSession(model_id="gpt-4o") as chat:      # seals on exit
    for prompt in prompts:
        chat.turn(prompt=prompt, output=ask(prompt))
```

At 1,000 turns that is **one 412-byte seal**. Proving any single turn costs 10
hashes and about 1 KB, and reveals nothing about the other 999.

### From the command line

```bash
aetherproof sign model.onnx output.txt
aetherproof verify receipt.json --output output.txt
aetherproof                                   # interactive menu
```

**More recipes:** [docs/INTEGRATION.md](docs/INTEGRATION.md) — pick a path by one
question, every snippet tested.

---

## Verify it

Verification needs **21 lines and one dependency**. No network, no account, no
special hardware, and it keeps working if this project is abandoned.

```bash
pip install cryptography      # that is the entire requirement
```

**The shape of it**, so you can see there is no trick — this is illustrative, not
complete:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json

r   = json.load(open("receipt.json"))
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["public_key"]))

# every field length-prefixed as "<len>:<field>", concatenated, then signed
preimage = build_preimage(r)                 # see the full version below
pub.verify(bytes.fromhex(r["signature"]), preimage)     # raises if invalid
```

> **Do not ship the snippet above.** It omits `log_sequence`, `hw_evidence`, the
> v1.2 extension commitment, and the v1.3 `receipt_id` and `signing_key_id`, so it
> rejects every receipt the current version produces. The complete verifier — 21
> lines, tested on every commit against real receipts — is in
> **[docs/VERIFICATION.md](docs/VERIFICATION.md)**.

---

## What it proves

| Claim | Mechanism |
|---|---|
| This exact output was not modified after signing | `output_hash` inside the signed preimage |
| The receipt itself was not altered | Ed25519 over a length-prefixed canonical preimage |
| It was signed by the holder of a specific key | Ed25519 verify, no other input |
| A claimed time and log position were fixed at signing | both inside the preimage |
| The local log was not edited, reordered, or truncated in the middle | key-free hash chain |
| A specific turn belongs to a sealed session | Merkle inclusion proof, revealing no other turn |
| Anyone can check all of it offline, forever | receipt + public key, nothing else |

---

## What it does **not** prove

Read this before citing anything above.

**Integrity, not completeness.** *"Show me the record of this decision"* is answered.
*"Show me that you logged them all"* is not. Someone who logs 9,000 of 10,000
outputs passes every check here. That cannot be fixed locally — it needs an
independent witness, which does not exist yet.

| Not proven | Why |
|---|---|
| That the named model produced the output | it signs a `(model, output)` pair you supply |
| That the timestamp is truthful | it is your own clock — bound, not externally anchored |
| That the signing key is held securely | a software key on disk unless you set a passphrase |
| That it survives a quantum adversary | Python is Ed25519 only; ML-DSA-65 is in the Rust core |

**Where it does not fit at all:** detecting deepfakes or unsigned AI content. A
scammer never signs, so there is nothing to verify.

Full list: [docs/CLAIMS.md](docs/CLAIMS.md).

---

## Two implementations

| | Rust — `rust/` | Python — `aetherproof/` |
|---|---|---|
| Receipt | **128 B fixed binary** | 646 B JSON |
| Post-quantum | **ML-DSA-65 (FIPS 204)** | none |
| Secret zeroization, constant-time compare | **yes** | no |
| `unsafe` in production | **zero, compiler-enforced** | n/a |
| Tests | 59 | 642 (93% coverage) |
| Distribution | source + CI wheels | PyPI |

Measured, 50,000 leaves, medians of seven isolated runs: Rust builds a Merkle tree
in **28.16 ms** against Python's 102.71 ms (3.6×) and verifies a proof in
**3.93 µs** against 17.17 µs (4.4×).

The Rust core is optional. `aetherproof` does not import it and behaves identically
without it — enforced in CI. See [docs/ROADMAP.md](docs/ROADMAP.md).

### Secrets that get wiped

A signing key held as a Python `bytes` object cannot be wiped — it is immutable, and
garbage collection does not overwrite the allocation. `SecureSigner` keeps the key
inside Rust and overwrites it on release, including when a block exits by exception.

```python
import _native

with _native.SecureSigner() as signer:        # key wiped on exit
    pub     = signer.public_key()             # nothing returns the secret
    receipt = signer.sign_receipt(pid=1, binary=model_bytes,
                                  memory_hash=0, syscall_count=1)

assert _native.SecureVerifier(pub).verify_receipt(receipt)
```

Setup and post-quantum usage: [docs/INTEGRATION.md](docs/INTEGRATION.md#path-c--secrets-that-get-wiped).

---

## Documentation

| | |
|---|---|
| [INTEGRATION.md](docs/INTEGRATION.md) | **start here** — pick a path by one question |
| [GETTING-STARTED.md](docs/GETTING-STARTED.md) | first receipt, no code |
| [CLAIMS.md](docs/CLAIMS.md) | what this proves and what it does not |
| [VERIFICATION.md](docs/VERIFICATION.md) | the offline verifier, in full |
| [CLOUD-MODELS.md](docs/CLOUD-MODELS.md) | local weights vs an API you do not control |
| [AGENT-CHAIN.md](docs/AGENT-CHAIN.md) | binding agent context (receipt v1.2) |
| [SECURITY.md](SECURITY.md) | reporting a vulnerability, threat model, known issues |
| [ROADMAP.md](docs/ROADMAP.md) | 0.5.0 — Rust core, bindings, post-quantum |
| [ANALYSIS.md](docs/ANALYSIS.md) | measured assessment, including what is unverified |
| [CONTRIBUTING.md](CONTRIBUTING.md) | extension and spec workflow |

---

## License

**Apache-2.0.** Use it, deploy it, fork it, embed it in a commercial product — no
copyleft obligation. The receipt format and the offline verifier are meant to be
copied freely; a proof layer nobody can adopt is not a proof layer.

*Versions up to 0.2.2 were AGPL-3.0-or-later. From 0.3.0 onward: Apache-2.0.*

Security issues: **[SECURITY.md](SECURITY.md)** — please do not open a public issue.
