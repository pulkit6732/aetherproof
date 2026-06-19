"""Security regression tests — signing preimage must be INJECTIVE.

Each test here corresponds to a real bug found during adversarial stress testing.
These are the highest-value tests in the suite: they encode forgery attempts that
MUST stay blocked. A failure here means receipts can be forged.

Bug history:
- Bug A (critical): "|".join preimage was non-injective. A "|" inside any field
  shifted boundaries so two different receipts shared one preimage -> one
  signature forged both. Fixed by length-prefixing each field ("<len>:<field>").
- Bug C (latent): hw_evidence was str(list) (Python repr) -> key order / quoting
  changed the preimage for semantically equal evidence. Fixed with canonical,
  key-sorted JSON.
"""

import pytest

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt


def _signed(**kw):
    r = Receipt(**kw)
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    return r, s.get_public_key()


def test_delimiter_in_field_does_not_collide():
    """The exact Bug A exploit: shifting a '|' across adjacent fields must NOT
    produce the same preimage."""
    a = Receipt(model_weight_root="a", model_root_type="b|c",
                output_hash="o", timestamp_ms=1, log_sequence=1)
    b = Receipt(model_weight_root="a|b", model_root_type="c",
                output_hash="o", timestamp_ms=1, log_sequence=1)
    assert a.canonical_message() != b.canonical_message()


def test_stolen_signature_does_not_forge_a_different_receipt():
    """End-to-end: a signature valid for one receipt must not verify a different
    receipt, even one crafted to collide under the old delimiter scheme."""
    legit, pub = _signed(model_weight_root="a", model_root_type="b|c",
                         output_hash="o", timestamp_ms=1, log_sequence=1)
    assert verify_receipt(legit, pub) is True

    forged = Receipt(model_weight_root="a|b", model_root_type="c",
                     output_hash="o", timestamp_ms=1, log_sequence=1)
    forged.signature = legit.signature  # attacker reuses the signature
    assert verify_receipt(forged, pub) is False


@pytest.mark.parametrize("field", [
    "model_weight_root", "model_root_type", "input_commitment",
    "output_hash", "log_anchor",
])
def test_every_string_field_resists_delimiter_injection(field):
    """No string field may let an injected ':' or '|' shift boundaries to collide
    with a neighbour. Fuzz each field with delimiter-laden values."""
    base = dict(model_weight_root="A", model_root_type="B", input_commitment="C",
                output_hash="D", timestamp_ms=1, log_sequence=1, log_anchor="E")
    poison = dict(base); poison[field] = "x|y:z|1:2"
    assert Receipt(**base).canonical_message() != Receipt(**poison).canonical_message()


def test_hw_evidence_key_order_is_canonical():
    """Bug C: semantically-equal evidence with different key order must share one
    preimage (so a re-serialization can't invalidate a valid receipt)."""
    r1 = Receipt(model_weight_root="a", output_hash="o", timestamp_ms=1,
                 log_sequence=1, hw_evidence=[{"t": "x", "v": 1, "kid": "k"}])
    r2 = Receipt(model_weight_root="a", output_hash="o", timestamp_ms=1,
                 log_sequence=1, hw_evidence=[{"kid": "k", "v": 1, "t": "x"}])
    assert r1.canonical_message() == r2.canonical_message()


def test_empty_fields_are_still_distinguished():
    """Length-prefixing must distinguish empty-vs-absent so '' fields can't be
    smeared into a neighbour."""
    a = Receipt(model_weight_root="", model_root_type="ab",
                output_hash="o", timestamp_ms=1, log_sequence=1)
    b = Receipt(model_weight_root="ab", model_root_type="",
                output_hash="o", timestamp_ms=1, log_sequence=1)
    assert a.canonical_message() != b.canonical_message()
