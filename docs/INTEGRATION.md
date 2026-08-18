[Back to the AetherProof README](../README.md)

# Integration guide

**AetherProof - Pulkit Kr Srivastava | Apache-2.0**How to add AetherProof to something that already exists, in the smallest number of
steps that actually work. Each section is a real situation, not a feature tour.

Every snippet here runs. Where a thing is not built yet, it says so instead of
showing you code that will not import.

---

## Pick your path in one question

**Do you control the code that produces the AI output?**- **Yes**-> [Path A](#path-a--you-call-the-model). Three lines.
- **No, I only have the output afterwards**-> [Path B](#path-b--you-only-have-the-output).
- **Yes, and the key must not sit in Python memory**-> [Path C](#path-c--secrets-that-get-wiped).
- **I only need to check someone else's receipt**-> [Path D](#path-d--verify-only).

---

## Path A - you call the model

The common case. You have a function that calls an API and returns text, and you
want a receipt for every call.

```bash
pip install aetherproof
```

### A1. One call, one receipt

```python
from aetherproof.auto import sign

resp = client.chat.completions.create(model="gpt-4o", messages=[...])
out  = resp.choices[0].message.content

sign(prompt=user_prompt, output=out, model_id=resp.model)
```

That is the whole integration. `sign()` never prompts, never blocks, never reads
stdin. On failure it returns `None` and your program continues - a pipeline losing
a receipt is bad, a pipeline crashing over one is worse.

If a missing receipt *is* a failure for you, invert it:

```bash
export AETHERPROOF_STRICT=1
```

### A2. Wrap a function you already have

```python
from aetherproof.auto import receipted

@receipted(model_id="gpt-4o")
def ask(prompt: str) -> str:
    return client.chat.completions.create(...).choices[0].message.content
```

No call sites change.

### A3. A whole conversation, one signature

Signing 1,000 messages individually means 1,000 signatures, and proving any one of
them means handing over all 1,000. A session seals once and proves any single turn
without revealing the others.

```python
from aetherproof.auto import AutoSession

with AutoSession(model_id="gpt-4o") as chat:      # seals on exit
    for prompt in prompts:
        out = ask(prompt)
        chat.turn(prompt=prompt, output=out)
```

At 1,000 turns: one 412-byte seal, and proving turn 500 costs 10 hashes and
~1 KB. See [A4](#a4-prove-one-turn-later) for the proof.

### A4. Prove one turn later

```python
from aetherproof.core.session import inclusion_proof, verify_inclusion, merkle_root

root  = merkle_root(leaf_hashes)              # from the sealed session
proof = inclusion_proof(leaf_hashes, 500)     # sibling path for turn 500
assert verify_inclusion(leaf_hashes[500], proof, root)
```

The proof reveals nothing about turns 0-499 or 501-999.

---

## Path B - you only have the output

You did not make the call. You have a file, a transcript, or a blob, and you need
it to be tamper-evident from now on.

```bash
aetherproof sign model.onnx output.txt
aetherproof verify receipt.json --output output.txt
```

**Understand what this does and does not give you.** Signing an artifact today
proves it has not changed *since today*. It says nothing about whether it was
altered before you signed it. If that distinction matters - legacy archives,
evidence, anything where the gap between creation and signing is long - signing
now does not close it, and no signature scheme can. That is a property of what a
signature is, not a limitation of this tool.

---

## Path C - secrets that get wiped

A Python `bytes` object holding a signing key is immutable: you cannot wipe it, and
garbage collection does not overwrite the allocation. The key stays readable in the
heap long after its last use, and in a core dump afterwards.

If that matters - a long-lived service, a shared host, anything that produces crash
dumps - use the native extension's `SecureSigner`. The key is generated inside Rust,
never crosses back into Python, and is overwritten on release.

### C1. Build the extension

```bash
cd rust/py
python -m maturin build --release
pip install ../target/wheels/aetherproof_native-*.whl
```

Needs a Rust toolchain ([rustup.rs](https://rustup.rs)). It is **optional**- the
`aetherproof` package does not import it and behaves identically without it.

### C2. Use it

```python
import _native

with _native.SecureSigner() as signer:          # key wiped on block exit
    pub     = signer.public_key()               # 32 bytes, safe to publish
    receipt = signer.sign_receipt(pid=1, binary=model_bytes,
                                  memory_hash=0, syscall_count=1)

verifier = _native.SecureVerifier(pub)
assert verifier.verify_receipt(receipt)
```

The key is wiped even if the block exits by exception. Nothing returns it -
there is no `private_key` accessor, and `repr()` shows only `<SecureSigner live>`
or `<SecureSigner destroyed>`.

After the block, every operation errors rather than misbehaving quietly:

```python
signer.sign(b"x")     # ValueError: Destroyed
```

### C3. Comparing digests safely

`==` on bytes short-circuits, so how long it takes reveals how long a shared prefix
was. Comparing a supplied MAC or digest that way leaks it a byte at a time.

```python
from _native import ct_eq, ct_eq_str

if ct_eq(supplied_mac, expected_mac):    ...
if ct_eq_str(supplied_root, expected_root): ...
```

### C4. Post-quantum signatures

Ed25519 is not broken. ML-DSA is standardised but young. A hybrid receipt carries
both, so a break in either leaves the other intact.

```python
pub_pq, priv_pq = _native.pq_keygen()
hybrid = _native.pq_attach(receipt, priv_pq)     # 128-byte core untouched
assert _native.pq_verify(hybrid, pub_pq)
```

**Know the cost before you turn this on:**| | Ed25519 | ML-DSA-65 | |---|---|---| | Signature | 64 B | **3,309 B**| | Full receipt | 128 B | **3,453 B**| | Public key | 32 B | 1,952 B | | Sign | 18.84 µs | 787.83 µs (**42x**) | | Verify | 22.77 µs | 177.59 µs (7.8x) |

A hybrid receipt is **27x larger**than a plain one. There is no compact
post-quantum option: 3,309 bytes is the FIPS 204 signature size, and no framing
choice shrinks it. Turn this on when you need it, not by default.

The core stays byte-identical, so a verifier that predates the trailer still works:

```python
assert hybrid[:128] == receipt          # true, by test
```

---

## Path D - verify only

You received a receipt and a public key. You do not want to install this project to
check it.

**You do not have to.** Verification needs `cryptography` and 21 lines. No network,
no account, no special hardware, and it keeps working if this project is abandoned.
The full verifier is in the README under *How offline verification actually works*.

```bash
pip install cryptography        # that is the whole dependency list
```

If you *are* installing the package anyway:

```bash
aetherproof verify receipt.json --output output.txt --quiet   # exit 0 or 1
```

---

## Choosing between the two implementations

| Use | When | |---|---| | **Python**(`pip install aetherproof`) | default; no toolchain needed; the whole feature set | | **Rust core**(`rust/`) | 128-byte receipts, kernel wire compatibility, post-quantum, secret wiping, constant-time comparison | | **Both**(extension installed) | Python API unchanged, 2.9-4.3x faster Merkle work |

They are verified to agree: `tests/test_native_equivalence.py` holds them to
identical output across 17 tree sizes, every proof index in 10 tree sizes, 150
randomised trees, and cross-verification in both directions.

---

## Operational notes

**Where things live.**`~/.aetherproof/` holds `signing_key.pem`, `signing_key.pub`,
`log.db`, and `receipts/`. Override with `AETHERPROOF_HOME`.

**Environment variables.**| | | |---|---| | `AETHERPROOF_HOME` | where keys and the log live | | `AETHERPROOF_STRICT=1` | a receipt failure raises instead of returning `None` | | `AETHERPROOF_DISABLE=1` | no-op every call - for test suites | | `AETHERPROOF_KEY_PASSPHRASE` | encrypt the key at rest |

**Back up your private key.** Losing it means you can no longer issue receipts under
that identity. Already-issued receipts keep verifying, because verification needs
only the public key.

**Concurrency.** The log is SQLite in WAL mode with `BEGIN IMMEDIATE`. Verified
intact at 128 threads and 12 processes, and after hard-killing writers mid-write.
Throughput ~1,400 receipts/sec.

**Key rotation.** Receipts carry `signing_key_id`, so a verifier does one lookup
rather than trying every key you hold. Rotating never invalidates old receipts.

---

## Limits worth knowing before you build on this

Full list in `docs/CLAIMS.md`. The three that change design decisions:

1. **Integrity, not completeness.***"Show me the record of this decision"* is
   answered. *"Show me that you logged them all"* is not. Someone who logs 9,000 of
   10,000 outputs passes every check here. This is unsolvable locally - it needs an
   independent witness, which is not built.

2. **The timestamp is the signer's own clock.** Bound at signing, not externally
   anchored. If you need a third party to attest the time, this does not do that.

3. **It does not prove which model ran.** It signs a `(model, output)` pair you
   supply. There is no inference attestation.

**Where it does not fit at all:** detecting deepfakes or unsigned AI content. A
scammer never signs, so there is nothing to verify. That is detection - a different
technology needing serious compute - and this project does not do it.

---

## License

Apache-2.0. Use it, deploy it, fork it, embed it in a commercial product. No
copyleft obligation, no attribution requirement beyond the licence text, no field-
of-use restriction.

The receipt format and the offline verifier are meant to be copied. If you
reimplement the verifier so your users do not have to install anything, that is the
intended outcome, not a workaround.

Security issues: see [SECURITY.md](../SECURITY.md).
