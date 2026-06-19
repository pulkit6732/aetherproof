<p align="center">
  <img src="docs/signet-logo.png" alt="Signet" width="240">
</p>

# AetherProof

**The open-source receipt engine. Prototype of Signet.**

Generate cryptographic receipts that prove an AI output is real and unmodified — no servers, no dependencies, verifiable forever offline.

```
pip install aetherproof
```

Run `aetherproof` with no arguments for the interactive menu:

```
      .+######+.        AETHERPROOF
    ##          ##      v0.2.0
   #      /\      #     Cryptographic receipt engine
  #      /  \      #    Prototype of Signet · R0/L2
  #     / /\ \     #
  #    / /  \ \    #     github.com/pulkit6732/aetherproof
  #   /______\ \   #     Verify(receipt, pk, log) = TRUE
   #  \______/  #
    ##          ##
      '######'
  ────────────────────────────────────────────────
            Sign · Verify · Inspect · Log · Keygen
```

## What it does

Every time an AI model produces output, AetherProof issues a tamper-proof signed receipt:

```
Receipt ID        : receipt_1700000000000
Model Root        : abcdef0123456789... (SHA-256 Merkle of model weights)
Output Hash       : fedcba9876543210... (SHA-256 of the output)
Timestamp         : 2026-06-11T15:30:00Z
Signature         : ✓ Ed25519 VALID
```

**One bit changes → signature fails instantly.**

## Quick start

### Easy mode (for anyone)

```bash
aetherproof
```

Step-by-step wizard:
1. What model did you use?
2. Paste the output
3. Receipt is signed and saved

### Expert mode (for developers)

```bash
# Generate a receipt
aetherproof sign model.onnx output.txt

# Verify it (offline, forever)
aetherproof verify receipt.json

# Inspect all fields
aetherproof inspect receipt.json

# Test tamper detection
aetherproof tamper receipt.json
```

## The invariant (what makes this real)

```
Verify(receipt, public_key, log) = TRUE

using ONLY those three inputs, forever, with zero dependency on
AetherProof servers, any vendor SDK, or any hardware driver.
```

This is not a claim. It's built in. Offline verification uses only:
1. The receipt file
2. The public key (PEM file)
3. (Optional) transparency log entry

No network. No API calls. No special hardware. Works in 2026, 2035, 2050.

## How offline verification actually works

You can prove a receipt is genuine with **no internet and no AetherProof code at
all** — the math is open. Here is the exact process.

### What you need (the three inputs)
1. **The receipt** (`ap_xxxx.json`) — the signed claim.
2. **The public key** (`ap_xxxx.pub`, a PEM file) — shipped beside the receipt.
3. **(Optional) the original output file** — only if you also want to prove the
   output itself wasn't changed.

### The steps
1. **Rebuild the signed message.** The receipt is signed over a canonical,
   length-prefixed preimage of its fields (version, model root, model-root-type,
   input commitment, output hash, timestamp, log sequence, hardware evidence, log
   anchor). The encoding is injective, so no two distinct receipts can share a
   preimage (and thus a signature).
2. **Check the Ed25519 signature** of that preimage against the public key. If it
   verifies, the receipt's contents are exactly what was signed — a single
   changed bit fails this check.
3. **(Optional) Re-hash the output file** with SHA-256 (raw bytes, streamed) and
   compare to the receipt's `output_hash`. If they match, the output is unchanged.

### The one-command way

```bash
# signature only
aetherproof verify ap_xxxx.json

# signature + confirm the output file still matches
aetherproof verify ap_xxxx.json --output original_output.txt

# scripting / CI: machine-readable, exits non-zero on any failure
aetherproof verify ap_xxxx.json --output original_output.txt --quiet
# -> {"valid": true, "signature_valid": true, "output_unmodified": true}
```

Exit code is `0` only when everything checks out, `1` on any tampering — so
`aetherproof verify … && deploy` is safe in a pipeline.

### Verify without AetherProof (any Ed25519 library)

Because the format is open, anyone can verify with a standard crypto library —
no dependency on this tool. In Python with `cryptography`:

```python
import json, hashlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key

r = json.load(open("ap_xxxx.json"))
pub = load_pem_public_key(open("ap_xxxx.pub", "rb").read())

# rebuild the injective preimage: "<len>:<field>" for each field, in order
fields = [
    r["receipt_version"], r["model_weight_root"], r["model_root_type"],
    r["input_commitment"], r["output_hash"], str(r["timestamp_ms"]),
    str(r["log_sequence"]),
    json.dumps(r["hw_evidence"], sort_keys=True, separators=(",", ":")),
    r["log_anchor"],
]
preimage = "".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")

pub.verify(bytes.fromhex(r["signature"]), preimage)  # raises if invalid
print("signature OK")

# optional: prove the output file is unchanged
digest = hashlib.sha256(open("original_output.txt", "rb").read()).hexdigest()
print("output unmodified:", digest == r["output_hash"])
```

That is the whole trust model: **a public key and some SHA-256 + Ed25519 math you
can run anywhere, forever.**

## Architecture (god file)

AetherProof is **Layer 2** of the **Signet** stack. Signet adds hardware roots, compliance packs, and a transparency network on top.

## License

MIT. Use it. Deploy it. Fork it. Verify it.

---

**AetherProof is what you get when you need tamper-proof proof.**

**Signet is what you get when you need hardware roots, compliance packs, and a transparency log.**
