"""Security regression tests — receipt parsing and type handling.

Bug B (medium): Receipt.from_dict did not coerce numeric fields, so a JSON
receipt with timestamp_ms / log_sequence as strings parsed into str fields.
Because the preimage str()-es them, int 1 and str "1" were treated as equal in
one path and unequal in another — a type-confusion footgun. Also, unknown keys
in a (possibly newer / attacker-supplied) receipt should be ignored, not crash.
"""

import json

from aetherproof.core.receipt import Receipt


def test_numeric_fields_coerced_to_int():
    r = Receipt.from_dict({
        "model_weight_root": "a", "output_hash": "o",
        "timestamp_ms": "1700000000000", "log_sequence": "7",
        "signature": "x", "receipt_id": "r",
    })
    assert isinstance(r.timestamp_ms, int) and r.timestamp_ms == 1700000000000
    assert isinstance(r.log_sequence, int) and r.log_sequence == 7


def test_unknown_keys_are_ignored_not_fatal():
    r = Receipt.from_dict({
        "model_weight_root": "a", "output_hash": "o",
        "future_field_from_v9": {"nested": True}, "another": [1, 2, 3],
    })
    assert r.model_weight_root == "a"


def test_json_round_trip_preserves_preimage():
    original = Receipt(model_weight_root="a", model_root_type="artifact_hash",
                       input_commitment="ic", output_hash="o",
                       timestamp_ms=123, log_sequence=4, log_anchor="local://log/4")
    restored = Receipt.from_json(original.to_json())
    assert restored.canonical_message() == original.canonical_message()


def test_string_vs_int_timestamp_yield_same_receipt():
    """After coercion, a receipt loaded with a string timestamp must be identical
    to one built with an int — no preimage divergence."""
    as_int = Receipt(model_weight_root="a", output_hash="o",
                     timestamp_ms=1, log_sequence=1)
    as_str = Receipt.from_dict({"model_weight_root": "a", "output_hash": "o",
                                "timestamp_ms": "1", "log_sequence": "1"})
    assert as_int.canonical_message() == as_str.canonical_message()
