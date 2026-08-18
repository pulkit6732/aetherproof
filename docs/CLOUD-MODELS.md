[Back to the AetherProof README](../README.md)

# Local models and cloud APIs

**AetherProof - Pulkit Kr Srivastava | Apache-2.0**What can be bound for a model you run yourself, what can be bound for a model behind
someone else's API, and why those are different guarantees.

---

## The two cases

This is the most important distinction in AetherProof. **What can be proven
depends on whether you can see the weights.**| | Local / self-hosted (Llama, custom, on-prem) | Cloud API (GPT-4o, Claude, Grok, DeepSeek, Gemini...) | |---|---|---| | Who holds the weights | **You**| The provider | | Can you hash the weights? | **Yes**| **No - ever**| | `model_root_type` | `artifact_hash` | `api_attested` | | Proves the exact model ran? | **Yes**| **No**(only the provider can attest that) | | Proves input + output unaltered? | Yes | **Yes**| | Proves *which model the API claimed* + when? | Yes | **Yes**|

### Why a cloud receipt can't prove the weights - and why that's honest

`model_weight_root` requires reading the weights. With GPT-4o or Grok, **the
weights live on the provider's servers - you never see them, so you cannot hash
them.**No client-side tool can. Anyone claiming to "cryptographically prove the
cloud model ran" is overstating it, and a sharp auditor will reject that.

What a cloud receipt *does* prove is the part **you are liable for**: the exact
input your system sent, the exact output it acted on, the model the API *claimed*,
the time, and that none of it was altered or back-dated. That is your
record-keeping obligation (SEC 17a-4, FRE 902(14)). The provider owns their
infrastructure attestation; AetherProof owns the faithfulness of your record.

### How the model name is captured (you don't type it)

For `api_attested`, the model identity comes **from the API response**, not from a
guess. Every major API returns the resolved id:

```python
# OpenAI / DeepSeek / xAI (Grok) - OpenAI-compatible
resp = client.chat.completions.create(model="gpt-4o", messages=[...])
resp.model              # "gpt-4o-2024-08-06"  <- the RESOLVED id (dated snapshot)
resp.system_fingerprint # "fp_a7d06e42bc"      <- backend config snapshot
resp.id, resp.created   # call id + provider timestamp

# Anthropic (Claude)
resp = client.messages.create(model="claude-opus-4-8", ...)
resp.model              # "claude-opus-4-8"
```

You asked for `"gpt-4o"`; the API answers `"gpt-4o-2024-08-06"` - the exact
snapshot that served you. You bind that returned string + `system_fingerprint`,
so the user can't fake it (it comes back inside the response you're hashing).

### Signing a cloud call

```python
from aetherproof.core.receipt import Receipt
from aetherproof.core.keystore import load_or_create_signer
from aetherproof.core.log import ReceiptLog

resp = client.chat.completions.create(model="gpt-4o", messages=[...])

r = Receipt.for_api_call(
    provider="openai",
    model_id=resp.model,                       # read FROM the response
    prompt=user_prompt,
    output_text=resp.choices[0].message.content,
    response_metadata={
        "system_fingerprint": resp.system_fingerprint,
        "response_id": resp.id,
        "created": resp.created,
    },
)
# r.model_root_type == "api_attested"
signer = load_or_create_signer()
r.signature = signer.sign(r.signing_bytes())
ReceiptLog().append(r)
```

This works for **any**OpenAI-compatible or Anthropic-style provider - OpenAI,
Azure OpenAI, DeepSeek, xAI/Grok, Mistral, Together, Groq, etc. (tested across 17
model families in `tests/security/test_cloud_models_matrix.py`).

### "But what if they have no provider attestation? Won't they get rejected?"

No - the honest answer *passes* the security review. When asked "prove Grok's
weights ran," the answer is:

> "No client-side tool can prove a closed cloud model's weights - only the
> provider can, and they don't expose it. What we prove is the part you're liable
> for: the exact input, the exact output, the model the API claimed, the time,
> and that none of it was altered. That's your record-keeping obligation."

In a real dispute (a wrongful denial, a bad summary), the fight is almost never
"was it GPT-4o or GPT-4-turbo" - it's **"did the AI actually output this, or was
the record edited afterward?"**AetherProof answers that completely, for any cloud
model, with zero provider cooperation. The model-identity gap upgrades to a real
hardware root only when the provider signs their infrastructure (AWS Bedrock +
Nitro, future) - at which point **Signet**imports that signature and the tier
graduates `api_attested -> hardware-rooted`, with no change to the receipt format.
