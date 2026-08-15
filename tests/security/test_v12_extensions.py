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
    """Legacy path: an explicit v1.1 receipt with no extensions stays v1.1.

    New receipts default to v1.3 since the hardening pass, so the v1.1<->v1.2
    relationship is now tested by pinning the version explicitly. That is the
    behaviour that must not drift — receipts already issued under v1.1 keep
    their exact preimage.
    """
    a = Receipt(receipt_version="1.1", model_weight_root="m", output_hash="o",
                timestamp_ms=1, log_sequence=1)
    b = Receipt(receipt_version="1.1", model_weight_root="m", output_hash="o",
                timestamp_ms=1, log_sequence=1, signed_extensions={})
    assert a.receipt_version == "1.1"
    assert a.canonical_message() == b.canonical_message()


def test_extension_present_bumps_to_v12():
    r = Receipt(receipt_version="1.1", model_weight_root="m", output_hash="o",
                timestamp_ms=1, log_sequence=1, signed_extensions=EXT)
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
                receipt_id="ap_fixed01",
                signed_extensions={"ns/v1": {"a": "1", "b": "2", "c": "3"}})
    b = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1, log_sequence=1,
                receipt_id="ap_fixed01",
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
    original = Receipt(receipt_version="1.1", model_weight_root="m", output_hash="o",
                       timestamp_ms=1, log_sequence=1, signed_extensions=dict(EXT))
    restored = Receipt.from_json(original.to_json())
    assert restored.receipt_version == "1.2"
    assert restored.signed_extensions == original.signed_extensions
    assert restored.canonical_message() == original.canonical_message()


# ── issue #1 · normative sort order (safal207, 2026-06-24) ───────────────────
# The aggregate sorts the resulting COMMITMENTS, not the namespace keys. Those
# orders differ, and the implementation previously sorted namespaces while the
# docstring said commitments — so two implementations, each following one
# reading, signed the same receipt differently.

def _leaf(ns, body):
    import hashlib
    from aetherproof.core.receipt import Receipt as R
    return hashlib.sha256(R._canonicalize(ns) + R._canonicalize(body)).hexdigest()


def _divergent_namespaces():
    """Find namespaces whose sort order differs from their commitments' order."""
    for i in range(5000):
        a, b = f"ns.a{i}/v1", f"ns.b{i}/v1"
        ba, bb = {"x": str(i)}, {"y": str(i)}
        if [_leaf(a, ba), _leaf(b, bb)] != sorted([_leaf(a, ba), _leaf(b, bb)]):
            return a, b, ba, bb
    raise AssertionError("no divergent pair found — widen the search")


def test_aggregate_sorts_commitments_not_namespaces():
    import hashlib
    a, b, ba, bb = _divergent_namespaces()
    r = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                log_sequence=1, signed_extensions={a: ba, b: bb})

    by_commitment = sorted([_leaf(a, ba), _leaf(b, bb)])
    expected = "sha256:" + hashlib.sha256("".join(by_commitment).encode()).hexdigest()
    assert r.signed_extensions_hash() == expected

    by_namespace = [_leaf(a, ba), _leaf(b, bb)]          # namespace order
    wrong = "sha256:" + hashlib.sha256("".join(by_namespace).encode()).hexdigest()
    assert r.signed_extensions_hash() != wrong, "regressed to sorting namespaces"


def test_aggregate_is_independent_of_insertion_order():
    a, b, ba, bb = _divergent_namespaces()
    forward = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                      log_sequence=1, signed_extensions={a: ba, b: bb})
    reverse = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                      log_sequence=1, signed_extensions={b: bb, a: ba})
    assert forward.signed_extensions_hash() == reverse.signed_extensions_hash()


def test_single_extension_is_unaffected_by_the_fix():
    """One leaf sorts to itself, so existing single-extension receipts still verify."""
    import hashlib
    ns, body = "org.aetherproof.session/v0.1", {"session_id": "s_1"}
    r = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                log_sequence=1, signed_extensions={ns: body})
    expected = "sha256:" + hashlib.sha256(_leaf(ns, body).encode()).hexdigest()
    assert r.signed_extensions_hash() == expected


def test_three_extensions_agree_with_the_normative_rule():
    import hashlib
    ext = {"c.ns/v1": {"k": "3"}, "a.ns/v1": {"k": "1"}, "b.ns/v1": {"k": "2"}}
    r = Receipt(model_weight_root="m", output_hash="o", timestamp_ms=1,
                log_sequence=1, signed_extensions=ext)
    expected = "sha256:" + hashlib.sha256(
        "".join(sorted(_leaf(ns, body) for ns, body in ext.items())).encode()
    ).hexdigest()
    assert r.signed_extensions_hash() == expected


def test_multi_extension_receipt_still_signs_and_verifies():
    a, b, ba, bb = _divergent_namespaces()
    r, pub = _signed(model_weight_root="m", output_hash="o", timestamp_ms=1,
                     log_sequence=1, signed_extensions={a: ba, b: bb})
    assert verify_receipt(r, pub) is True


def test_tampering_one_of_two_extensions_breaks_the_signature():
    a, b, ba, bb = _divergent_namespaces()
    r, pub = _signed(model_weight_root="m", output_hash="o", timestamp_ms=1,
                     log_sequence=1, signed_extensions={a: dict(ba), b: dict(bb)})
    r.signed_extensions[a]["x"] = "tampered"
    assert verify_receipt(r, pub) is False
