[Back to the AetherProof README](../README.md)

# Agent-chain context (receipt v1.2)

**AetherProof - Pulkit Kr Srivastava | Apache-2.0**---

## Binding context to a receipt

A receipt can optionally commit to **namespaced runtime context**- which agent
action, run, or policy decision an output belongs to - *inside* the signature.
This binds a receipt to the exact decision it was issued for, so a valid receipt
can't be replayed in a different context.

```python
from aetherproof.core.receipt import Receipt

r = Receipt(
    model_weight_root="...",
    output_hash="...",
    signed_extensions={
        "org.liminal.agent_chain/v0.1": {
            "purpose": "generate",
            "actor_id": "agent:planner",
            "run_id": "run_42",
            "policy_decision_id": "pol_7",
        }
    },
)
# r.receipt_version is now "1.2"; the SHA-256 commitment over the canonicalized
# extensions is folded into the signing preimage - tampering any field breaks it.
```

- **Empty extensions -> the receipt stays v1.1, byte-identical.**No impact on
  existing receipts or verifiers.
- **Non-empty -> v1.2.**Per-extension SHA-256 commitments (RFC 8785 JCS
  canonicalization) are aggregated and appended to the injective preimage, so a
  namespace can be disclosed or omitted without breaking the others.

This is the AetherProof side of the [agent-chain context spec](https://github.com/pulkit6732/aetherproof/issues/1).
Multi-hop pipeline aggregation (signing each hop, identifying a tampered hop) is
**Signet Layer 3**and builds on this primitive.
