"""Tests for the api_attested cloud tier (Receipt.for_api_call).

The model identity for a cloud receipt comes from what the API RETURNED
(resp.model + provider metadata), never a hand-typed name. The receipt is honest
that it binds input+output+claimed-model, NOT the weights.
"""

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt
from aetherproof.core.hash import hash_output

META = {"system_fingerprint": "fp_a7d06e42bc", "response_id": "chatcmpl-9x"}


def test_for_api_call_sets_api_attested_type():
    r = Receipt.for_api_call(provider="openai", model_id="gpt-4o-2024-08-06",
                             prompt="p", output_text="o", response_metadata=META)
    assert r.model_root_type == "api_attested"


def test_for_api_call_binds_input_and_output():
    r = Receipt.for_api_call(provider="openai", model_id="gpt-4o", prompt="hello",
                             output_text="world", response_metadata=META)
    assert r.input_commitment == hash_output("hello")
    assert r.output_hash == hash_output("world")


def test_api_root_is_deterministic():
    a = Receipt.api_attested_root("gpt-4o-2024-08-06", "openai", **META)
    b = Receipt.api_attested_root("gpt-4o-2024-08-06", "openai", **META)
    assert a == b


def test_api_root_is_key_order_independent():
    a = Receipt.api_attested_root("m", "openai", x="1", y="2")
    b = Receipt.api_attested_root("m", "openai", y="2", x="1")
    assert a == b


def test_different_model_id_yields_different_root():
    a = Receipt.api_attested_root("gpt-4o-2024-08-06", "openai", **META)
    b = Receipt.api_attested_root("gpt-3.5-turbo", "openai", **META)
    assert a != b


def test_different_fingerprint_yields_different_root():
    a = Receipt.api_attested_root("gpt-4o", "openai", system_fingerprint="fp_1")
    b = Receipt.api_attested_root("gpt-4o", "openai", system_fingerprint="fp_2")
    assert a != b


def test_api_receipt_signs_and_verifies():
    r = Receipt.for_api_call(provider="anthropic", model_id="claude-opus-4-8",
                             prompt="p", output_text="o", response_metadata=META,
                             log_sequence=1, log_anchor="local://log/1")
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    assert verify_receipt(r, s.get_public_key()) is True


def test_tampering_api_output_breaks_signature():
    r = Receipt.for_api_call(provider="openai", model_id="gpt-4o", prompt="p",
                             output_text="real", response_metadata=META,
                             log_sequence=1)
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    pub = s.get_public_key()
    assert verify_receipt(r, pub) is True
    r.output_hash = hash_output("forged")  # rewrite the bound output
    assert verify_receipt(r, pub) is False
