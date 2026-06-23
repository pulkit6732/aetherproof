"""Tests for the v1.2 signed-extensions mechanism (agent-chain context, issue #1).

The extension lets a receipt commit to namespaced runtime context (agent action,
run, policy decision, ...) inside the signature, without breaking v1.1. Security
properties that must hold:
- empty extensions => receipt stays v1.1, byte-identical preimage (compat)
- non-empty => v1.2, commitment appended to the injective preimage
- tampering any extension value breaks the signature
- canonicalization is key-order independent (semantically-equal => same hash)
"""

import pytest

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt

EXT = {"org.liminal.agent_chain/v0.1": {
    "purpose": "generate", "actor_id": "agent:x", "run_id": "r1"}}


def _signed(**kw):
    r = Receipt(**kw)
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    return r, s.get_public_key()


def test_empty_extensions_stays_v11_and_byte_identical():
    a = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1)
    b = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                signed_extensions={})
    assert a.receipt_version == "1.1"
    assert a.canonical_message() == b.canonical_message()


def test_extension_present_bumps_to_v12():
    r = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                log_sequence=1, signed_extensions=EXT)
    assert r.receipt_version == "1.2"
    assert r.signed_extensions_hash() in r.canonical_message()


def test_v12_signs_and_verifies():
    r, pub = _signed(model_weight_root="m", output_hash="o", timestamp_ms=1,
                     log_sequence=1, signed_extensions=dict(EXT))
    assert verify_receipt(r, pub) is True


def test_tampering_extension_breaks_signature():
    ext = {"org.liminal.agent_chain/v0.1": {
        "purpose": "generate", "actor_id": "agent:x", "run_id": "r1"}}
    r, pub = _signed(model_weight_root="m", output_hash="o", timestamp_ms=1,
                     log_sequence=1, signed_extensions=ext)
    r.signed_extensions["org.liminal.agent_chain/v0.1"]["actor_id"] = "agent:EVIL"
    assert verify_receipt(r, pub) is False


def test_extension_canonicalization_is_key_order_independent():
    a = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                signed_extensions={"ns/v1": {"a": "1", "b": "2", "c": "3"}})
    b = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                signed_extensions={"ns/v1": {"c": "3", "b": "2", "a": "1"}})
    assert a.signed_extensions_hash() == b.signed_extensions_hash()
    assert a.canonical_message() == b.canonical_message()


def test_different_extension_values_yield_different_hash():
    a = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                signed_extensions={"ns/v1": {"purpose": "generate"}})
    b = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                signed_extensions={"ns/v1": {"purpose": "classify"}})
    assert a.signed_extensions_hash() != b.signed_extensions_hash()


def test_v12_survives_json_round_trip():
    original = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                       log_sequence=1, signed_extensions=dict(EXT))
    restored = Receipt.from_json(original.to_json())
    assert restored.receipt_version == "1.2"
    assert restored.signed_extensions == original.signed_extensions
    assert restored.canonical_message() == original.canonical_message()
