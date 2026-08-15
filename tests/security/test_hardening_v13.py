"""Regression suite for the v1.3 hardening pass.

Each test here corresponds to a defect found by executing the shipped v0.2.2
code, not by reading it. They are written to FAIL against v0.2.2 and pass after
the fix, so the suite is the proof the defect is closed.

Findings covered:
  F1  receipt_id collided ("receipt_0") for every Receipt built without an
      explicit timestamp — i.e. every receipt from Receipt.for_api_call().
  C1  api_attested_root used a non-injective "|".join, the same encoding the
      signing preimage had already abandoned for that exact reason.
  C2  compute_merkle_root duplicated the odd leaf (CVE-2012-2459 pattern), had
      no leaf/internal domain separation, and never bound file paths.
  F4  receipt_id was absent from the signing preimage, so it could be rewritten
      on a standalone receipt file without breaking the signature.

Plus the exhaustive byte-flip tamper probe the shipped tree never had (the old
tamper_detect flipped a single hex digit of a single field).
"""

import json
import hashlib
from pathlib import Path

import pytest

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt
from aetherproof.core.log import ReceiptLog
from aetherproof.core.hash import (
    sha256,
    compute_merkle_root,
    compute_model_weight_root,
    merkle_leaf,
    merkle_node,
)

META = {"system_fingerprint": "fp_a7d06e42bc", "response_id": "chatcmpl-9x"}


# ── F1 · receipt_id uniqueness ────────────────────────────────────────────────

def test_api_receipts_get_distinct_ids():
    """Two cloud receipts must not share an id.

    v0.2.2 produced "receipt_0" for both: __post_init__ derived receipt_id from
    timestamp_ms before timestamp_ms had been defaulted away from 0.
    """
    a = Receipt.for_api_call(provider="openai", model_id="gpt-4o",
                             prompt="p1", output_text="o1", response_metadata=META)
    b = Receipt.for_api_call(provider="openai", model_id="gpt-4o",
                             prompt="p2", output_text="o2", response_metadata=META)
    assert a.receipt_id != b.receipt_id
    assert a.receipt_id != "receipt_0"


def test_receipt_id_is_not_derived_from_a_zero_timestamp():
    r = Receipt(model_weight_root="a" * 64, output_hash="b" * 64)
    assert r.timestamp_ms > 0
    assert r.receipt_id.endswith(str(r.timestamp_ms)) or r.receipt_id.startswith("ap_")
    assert "receipt_0" != r.receipt_id


def test_two_api_receipts_both_append_to_log(tmp_path):
    """The README's own cloud snippet, run twice.

    v0.2.2 raised ValueError on the second append because receipt_id is UNIQUE
    in the log schema and both receipts were "receipt_0".
    """
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    signer = Signer.generate()
    for i in range(2):
        r = Receipt.for_api_call(provider="openai", model_id="gpt-4o",
                                 prompt=f"p{i}", output_text=f"o{i}",
                                 response_metadata=META)
        r.signature = signer.sign(r.signing_bytes())
        log.append(r)
    assert log.count() == 2


# ── C1 · api_attested_root injectivity ────────────────────────────────────────

def test_api_attested_root_resists_model_id_smuggling():
    """A caller must not be able to forge a metadata binding via model_id.

    v0.2.2 joined parts with "|", so a model_id carrying "|system_fingerprint:x"
    produced the same root as an honest call that really had that fingerprint.
    """
    honest = Receipt.api_attested_root("m", "openai", system_fingerprint="fp_2")
    forged = Receipt.api_attested_root("m|system_fingerprint:fp_2", "openai")
    assert honest != forged


def test_api_attested_root_resists_provider_smuggling():
    honest = Receipt.api_attested_root("m", "openai", response_id="r1")
    forged = Receipt.api_attested_root("m", "openai|model:m|response_id:r1")
    assert honest != forged


def test_api_attested_root_still_deterministic_and_order_free():
    a = Receipt.api_attested_root("gpt-4o", "openai", x="1", y="2")
    b = Receipt.api_attested_root("gpt-4o", "openai", y="2", x="1")
    assert a == b


def test_api_attested_root_still_separates_distinct_inputs():
    assert (Receipt.api_attested_root("gpt-4o", "openai", system_fingerprint="fp_1")
            != Receipt.api_attested_root("gpt-4o", "openai", system_fingerprint="fp_2"))
    assert (Receipt.api_attested_root("gpt-4o", "openai")
            != Receipt.api_attested_root("gpt-3.5", "openai"))


# ── C2 · Merkle construction ──────────────────────────────────────────────────

def test_odd_leaf_is_not_duplicated():
    """CVE-2012-2459 class: [A,B,C] must not equal [A,B,C,C]."""
    a, b, c = sha256("a"), sha256("b"), sha256("c")
    assert compute_merkle_root([a, b, c]) != compute_merkle_root([a, b, c, c])


def test_odd_leaf_duplication_at_depth():
    """The same collision, one level deeper: [A,B,C,D,E] vs [A,B,C,D,E,E]."""
    hs = [sha256(x) for x in "abcde"]
    assert compute_merkle_root(hs) != compute_merkle_root(hs + [hs[-1]])


def test_leaf_and_internal_nodes_are_domain_separated():
    """An internal node must not be presentable as a leaf.

    Without a domain tag both are bare 64-hex strings, so a tree over
    [node(A,B)] and a tree over [A, B] were indistinguishable at the root.
    """
    a, b = sha256("a"), sha256("b")
    internal = merkle_node(merkle_leaf(a), merkle_leaf(b))
    assert compute_merkle_root([a, b]) != compute_merkle_root([internal])


def test_single_leaf_is_still_hashed():
    """A one-element tree must not return the raw leaf unchanged."""
    a = sha256("a")
    assert compute_merkle_root([a]) != a


def test_empty_tree_is_empty_string():
    assert compute_merkle_root([]) == ""


def test_model_root_binds_file_names(tmp_path):
    """Renaming a file inside a model directory must change the root.

    v0.2.2 hashed contents only, so two directories holding the same bytes under
    different names produced an identical model_weight_root.
    """
    d1 = tmp_path / "m1"
    d1.mkdir()
    (d1 / "weights.bin").write_bytes(b"AAAA")
    (d1 / "config.json").write_bytes(b"BBBB")

    d2 = tmp_path / "m2"
    d2.mkdir()
    (d2 / "config.json").write_bytes(b"AAAA")   # same bytes, swapped names
    (d2 / "weights.bin").write_bytes(b"BBBB")

    assert compute_model_weight_root(d1) != compute_model_weight_root(d2)


def test_model_root_is_stable_for_identical_dirs(tmp_path):
    for name in ("x", "y"):
        d = tmp_path / name
        d.mkdir()
        (d / "weights.bin").write_bytes(b"AAAA")
        (d / "config.json").write_bytes(b"BBBB")
    assert (compute_model_weight_root(tmp_path / "x")
            == compute_model_weight_root(tmp_path / "y"))


def test_model_root_detects_content_change(tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "weights.bin").write_bytes(b"AAAA")
    before = compute_model_weight_root(d)
    (d / "weights.bin").write_bytes(b"AAAB")
    assert compute_model_weight_root(d) != before


def test_single_file_model_root_is_the_file_digest(tmp_path):
    """A single-file model root stays the plain file SHA-256 (unchanged contract)."""
    f = tmp_path / "model.onnx"
    f.write_bytes(b"weights")
    assert compute_model_weight_root(f) == sha256("weights")


# ── F4 · receipt_id is signed ─────────────────────────────────────────────────

def _signed(**kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="c" * 64,
                timestamp_ms=1_700_000_000_000, log_sequence=1,
                log_anchor="local://log/1", receipt_id="ap_deadbeef")
    base.update(kw)
    r = Receipt(**base)
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    return r, s.get_public_key()


def test_receipt_id_is_inside_the_signing_preimage():
    r, _ = _signed()
    assert r.receipt_id in r.canonical_message()


def test_rewriting_receipt_id_breaks_the_signature():
    r, pub = _signed()
    assert verify_receipt(r, pub) is True
    r.receipt_id = "ap_00000000"
    assert verify_receipt(r, pub) is False


def test_distinct_receipt_ids_give_distinct_preimages():
    a, _ = _signed(receipt_id="ap_aaaaaaaa")
    b, _ = _signed(receipt_id="ap_bbbbbbbb")
    assert a.canonical_message() != b.canonical_message()


# ── v1.3 versioning + backward compatibility ──────────────────────────────────

def test_new_receipts_default_to_v13():
    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64)
    assert r.receipt_version == "1.3"


def test_v13_with_extensions_stays_v13():
    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64,
                signed_extensions={"org.liminal.agent_chain/v0.1": {"run_id": "r1"}})
    assert r.receipt_version == "1.3"
    assert r.signed_extensions_hash() in r.canonical_message()


@pytest.mark.parametrize("version", ["1.1", "1.2"])
def test_legacy_receipts_still_verify(version):
    """A receipt signed under the old preimage must still verify after the bump.

    This is the whole point of keeping the legacy builders: receipts already in
    an auditor's hands cannot be invalidated by our fix.
    """
    ext = {"ns/v1": {"a": "b"}} if version == "1.2" else {}
    r = Receipt(receipt_version=version, model_weight_root="a" * 64,
                model_root_type="artifact_hash", input_commitment="b" * 64,
                output_hash="c" * 64, timestamp_ms=1_700_000_000_000,
                log_sequence=1, log_anchor="local://log/1",
                receipt_id="ap_legacy01", signed_extensions=ext)
    assert r.receipt_version == version
    s = Signer.generate()
    r.signature = s.sign(r.signing_bytes())
    assert verify_receipt(r, s.get_public_key()) is True


def test_legacy_preimage_excludes_receipt_id():
    """v1.1/v1.2 preimages must be byte-identical to what v0.2.2 produced."""
    r = Receipt(receipt_version="1.1", model_weight_root="a" * 64,
                model_root_type="artifact_hash", input_commitment="b" * 64,
                output_hash="c" * 64, timestamp_ms=1_700_000_000_000,
                log_sequence=1, log_anchor="local://log/1",
                receipt_id="ap_deadbeef")
    expected = "".join(
        f"{len(f)}:{f}" for f in
        ["1.1", "a" * 64, "artifact_hash", "b" * 64, "c" * 64,
         "1700000000000", "1", "[]", "local://log/1"]
    )
    assert r.canonical_message() == expected
    assert "ap_deadbeef" not in r.canonical_message()


def test_v13_and_legacy_preimages_differ():
    common = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                  input_commitment="b" * 64, output_hash="c" * 64,
                  timestamp_ms=1_700_000_000_000, log_sequence=1,
                  log_anchor="local://log/1", receipt_id="ap_deadbeef")
    old = Receipt(receipt_version="1.1", **common)
    new = Receipt(receipt_version="1.3", **common)
    assert old.canonical_message() != new.canonical_message()


# ── exhaustive byte-flip tamper probe ─────────────────────────────────────────

def test_every_byte_of_the_preimage_is_load_bearing():
    """Flip every bit position of every byte of the signed preimage.

    The shipped tamper_detect flipped one hex digit of one field. This asserts
    the real property: no single-bit change anywhere in the preimage can survive
    verification. This is the evidence behind a "byte-level tamper testing"
    claim.
    """
    r, pub = _signed()
    msg = bytearray(r.signing_bytes())
    sig = r.signature
    checked = 0
    for i in range(len(msg)):
        original = msg[i]
        for bit in range(8):
            msg[i] = original ^ (1 << bit)
            assert pub.verify(bytes(msg), sig) is False, f"byte {i} bit {bit} survived"
            checked += 1
        msg[i] = original
    assert pub.verify(bytes(msg), sig) is True  # restored
    assert checked == len(msg) * 8


def test_every_byte_of_the_signature_is_load_bearing():
    r, pub = _signed()
    msg = r.signing_bytes()
    raw = bytearray(bytes.fromhex(r.signature))
    for i in range(len(raw)):
        original = raw[i]
        raw[i] = original ^ 0x01
        assert pub.verify(msg, raw.hex()) is False, f"sig byte {i} survived"
        raw[i] = original
    assert pub.verify(msg, raw.hex()) is True


def test_tampering_any_receipt_field_breaks_verification():
    mutations = {
        "model_weight_root": "f" * 64,
        "model_root_type": "name_only",
        "input_commitment": "e" * 64,
        "output_hash": "d" * 64,
        "timestamp_ms": 1_700_000_000_001,
        "log_sequence": 2,
        "log_anchor": "local://log/2",
        "receipt_id": "ap_ffffffff",
    }
    for field_name, bad in mutations.items():
        r, pub = _signed()
        assert verify_receipt(r, pub) is True
        setattr(r, field_name, bad)
        assert verify_receipt(r, pub) is False, f"{field_name} was not bound"
