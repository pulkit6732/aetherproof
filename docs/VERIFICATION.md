[Back to the AetherProof README](../README.md)

# Offline verification

**AetherProof - Pulkit Kr Srivastava | Apache-2.0**How a receipt is checked without installing this project, without a network, and
without trusting whoever produced it.

---

## The mechanism

You can prove a receipt is genuine with **no internet and no AetherProof code at
all**- the math is open. Here is the exact process.

### What you need (the three inputs)
1. **The receipt**(`ap_xxxx.json`) - the signed claim.
2. **The public key**(`ap_xxxx.pub`, a PEM file) - shipped beside the receipt.
3. **(Optional) the original output file**- only if you also want to prove the
   output itself wasn't changed.

### The steps
1. **Rebuild the signed message.** The receipt is signed over a canonical,
   length-prefixed preimage of its fields (version, model root, model-root-type,
   input commitment, output hash, timestamp, log sequence, hardware evidence, log
   anchor). The encoding is injective, so no two distinct receipts can share a
   preimage (and thus a signature).
2. **Check the Ed25519 signature**of that preimage against the public key. If it
   verifies, the receipt's contents are exactly what was signed - a single
   changed bit fails this check.
3. **(Optional) Re-hash the output file**with SHA-256 (raw bytes, streamed) and
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

Exit code is `0` only when everything checks out, `1` on any tampering - so
`aetherproof verify ... && deploy` is safe in a pipeline.

### Verify without AetherProof (any Ed25519 library)

Because the format is open, anyone can verify with a standard crypto library -
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

# v1.3 also binds the receipt id and the signing key id. Older receipts
# (<=1.2) do not carry them, so their preimage ends above - which is why
# receipts issued before the upgrade still verify unchanged.
if r["receipt_version"] not in ("1.0", "1.1", "1.2"):
    fields += [r["receipt_id"], r["signing_key_id"]]

# v1.2+ appends a commitment over any signed extensions
if r.get("signed_extensions"):
    def canon(o):
        return json.dumps(o, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    leaves = sorted(
        hashlib.sha256(canon(ns) + canon(body)).hexdigest()
        for ns, body in r["signed_extensions"].items()
    )
    agg = hashlib.sha256("".join(leaves).encode("utf-8")).hexdigest()
    fields.append(f"sha256:{agg}")

preimage = "".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")

pub.verify(bytes.fromhex(r["signature"]), preimage)  # raises if invalid
print("signature OK")

# optional: prove the output file is unchanged
digest = hashlib.sha256(open("original_output.txt", "rb").read()).hexdigest()
print("output unmodified:", digest == r["output_hash"])
```

That is the whole trust model: **a public key and some SHA-256 + Ed25519 math you
can run anywhere, forever.**