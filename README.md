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

## Architecture (god file)

AetherProof is **Layer 2** of the **Signet** stack. Signet adds hardware roots, compliance packs, and a transparency network on top.

## License

MIT. Use it. Deploy it. Fork it. Verify it.

---

**AetherProof is what you get when you need tamper-proof proof.**

**Signet is what you get when you need hardware roots, compliance packs, and a transparency log.**
