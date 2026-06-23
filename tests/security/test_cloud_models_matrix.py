"""Cross-provider stress matrix for api_attested cloud receipts.

Every major cloud model family must: produce a valid signed receipt, carry
model_root_type='api_attested', and yield a root distinct from every other
model (no two models share a root). This is the regression that proves the
cloud tier works for "any model out there", not just one provider.
"""

import pytest

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt

# (provider, resolved model id the API returns, system_fingerprint)
MODELS = [
    ("openai", "gpt-4o-2024-08-06", "fp_a7d06e42bc"),
    ("openai", "gpt-4o-mini-2024-07-18", "fp_0ba7d124"),
    ("openai", "o1-2024-12-17", "fp_523ab"),
    ("openai", "gpt-3.5-turbo-0125", "fp_b28b"),
    ("anthropic", "claude-opus-4-8", ""),
    ("anthropic", "claude-sonnet-4-6", ""),
    ("anthropic", "claude-haiku-4-5-20251001", ""),
    ("xai", "grok-2-1212", "fp_grok2"),
    ("xai", "grok-4", "fp_grok4"),
    ("deepseek", "deepseek-chat", "fp_ds3"),
    ("deepseek", "deepseek-reasoner", "fp_dsr1"),
    ("google", "gemini-2.0-flash", ""),
    ("google", "gemini-2.5-pro", ""),
    ("mistral", "mistral-large-2411", ""),
    ("meta", "llama-3.3-70b-instruct", ""),
    ("cohere", "command-r-plus-08-2024", ""),
    ("alibaba", "qwen-max-2025", ""),
]


@pytest.mark.parametrize("provider,model_id,fp", MODELS,
                         ids=[m[1] for m in MODELS])
def test_each_cloud_model_signs_and_verifies(provider, model_id, fp):
    r = Receipt.for_api_call(
        provider=provider, model_id=model_id,
        prompt="audit prompt", output_text=f"audit output for {model_id}",
        response_metadata={"system_fingerprint": fp}, log_sequence=1)
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    assert r.model_root_type == "api_attested"
    assert verify_receipt(r, s.get_public_key()) is True


def test_all_model_roots_are_unique():
    roots = {}
    for provider, model_id, fp in MODELS:
        roots[model_id] = Receipt.api_attested_root(
            model_id, provider, system_fingerprint=fp)
    assert len(set(roots.values())) == len(roots), "two models share a root"
